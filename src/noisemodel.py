"""Zaj-tanacsado: egy apro, gyors szoveg-osztalyozo (multinomialis Naive Bayes, csak a standard konyvtar), amely a novelty-leleteket
"valoszinuleg zaj" jelzessel latja el es sorrendbe allitja. KIZAROLAG TANACSADO: soha nem szur, nem torol, nem hoz letre szabalyt.
A vedelmeket (must_keep kapu, ismert ugyek, hibaszintu sorok) nem kerüli meg, hanem tiszteletben tartja:

- tanitas: a tarolt novelty-mintak (nov_patterns); zaj = a jelenlegi zajszabalyok valamelyike illeszkedik, fontos = nincs zajszabaly es a szint
  hiba-vagy-rosszabb. A tobbi (warning/info, szabaly nelkul) cimkezetlen, nem tanitjuk, csak pontozzuk.
- kuszob (tau): csoportos 5-szoros keresztvalidacio (egesz zajszabaly-csaladok / egesz azonositok ismeretlenek a tanitasnal); tau = a
  visszatartott FONTOS sorok es a must_keep mintasorok legnagyobb pontszama. Csak az eleri a "valoszinuleg zaj" jelzest, ami tau FOLOTT van.
- tovabbi tiltas: hiba-szintu sor, must_keep mintasorral azonos sor, vagy ismert ugyre illeszkedo sor soha nem kap jelzest.
Merese (valos adaton, 50 kezi cimke): lasd docs/aiops-merokeret.md."""
import hashlib
import math
import re
import threading
import time

IMPORTANT = {"emerg", "alert", "crit", "critical", "err", "error"}   # a naplo-szintek es az ingest-szintek (critical) is
TOK = re.compile(r"[a-z][a-z0-9_\-]{1,}")
MIN_NOISE, MIN_IMPORTANT = 200, 50     # ennel kevesebb tanitopeldanal nincs modell (a kuszob nem lenne megbizhato)
MAX_TRAIN = 40000                      # tanitopeldak felso hatara (a szal ne foglalja sokaig a processzort)
RETRAIN_S = 6 * 3600
MIN_RETRAIN_S = 300                    # konfig-valtozas utan is legfeljebb ilyen gyakran
FOLDS = 5


def feats(ident, level, tmpl):
    w = TOK.findall((str(ident) + " " + str(tmpl)).lower())
    f = set(w) | {a + "_" + b for a, b in zip(w, w[1:])}
    f.add("LVL_" + str(level))
    f.add("ID_" + str(ident).lower())
    return f


class NB:
    """Binaris Naive Bayes; y=1: zaj. score() = a zaj naplo-esely-hanyadosa (log-odds)."""

    def fit(self, X, y):
        self.c = {}
        self.n = [0, 0]
        for f, t in zip(X, y):
            self.n[t] += 1
            for k in f:
                v = self.c.get(k)
                if v is None:
                    v = self.c[k] = [0, 0]
                v[t] += 1
        self.prior = math.log((self.n[1] + 1) / (self.n[0] + 1))
        self.d0, self.d1 = self.n[0] + 1, self.n[1] + 1
        return self

    def score(self, f):
        s = self.prior
        for k in f:
            v = self.c.get(k)
            if v is not None:
                s += math.log((v[1] + 0.5) / self.d1) - math.log((v[0] + 0.5) / self.d0)
        return s


def _fold(key):
    return int(hashlib.sha1(key.encode("utf-8", "replace")).hexdigest(), 16) % FOLDS


def _text(r):
    return f"{r['host']} | {r['ident']} | {r['tmpl']}"


def _norm_line(s):
    return re.sub(r"\d+", "<N>", str(s)).strip()


def label(rows, known):
    """-> [(csoport, y, jellemzok, sor)]; y=1 zaj, y=0 fontos; a tobbi sor kimarad."""
    out = []
    for r in rows:
        kind, what = known.classify_idx(_text(r))
        if kind == "noise":
            out.append(("r:%d" % what, 1, feats(r["ident"], r["level"], r["tmpl"]), r))
        elif kind == "keep" and str(r["level"]).lower() in IMPORTANT:
            out.append(("i:" + str(r["ident"]), 0, feats(r["ident"], r["level"], r["tmpl"]), r))
    return out


def train(rows, known, must_keep=(), min_noise=MIN_NOISE, min_important=MIN_IMPORTANT):
    """-> Model-dict vagy None (kevés tanitopelda). A kuszob a csoportos keresztvalidacio visszatartott, FONTOS soraibol szarmazik."""
    data = label(rows, known)
    nn = sum(1 for d in data if d[1] == 1)
    ni = len(data) - nn
    if nn < min_noise or ni < min_important:
        return {"ready": False, "reason": f"not enough labelled patterns (noise {nn}/{min_noise}, important {ni}/{min_important})",
                "n_noise": nn, "n_important": ni, "trained_at": time.time()}
    t0 = time.perf_counter()
    mk = []
    for line in must_keep:
        p = str(line).split(" | ", 2)
        if len(p) == 3:
            mk.append((p[1], feats(p[1], "err", p[2])))
    held_imp, held_noise, mk_scores = [], [], []
    for k in range(FOLDS):
        tr = [d for d in data if _fold(d[0]) != k]
        te = [d for d in data if _fold(d[0]) == k]
        if not tr or not te:
            continue
        m = NB().fit([d[2] for d in tr], [d[1] for d in tr])
        for d in te:
            (held_noise if d[1] == 1 else held_imp).append(m.score(d[2]))
        for ident, f in mk:
            if _fold("i:" + ident) == k:
                mk_scores.append(m.score(f))
    risky = held_imp + mk_scores
    tau = max(risky) if risky else 0.0
    model = NB().fit([d[2] for d in data], [d[1] for d in data])
    cut = sum(1 for s in held_noise if s > tau) / max(len(held_noise), 1)
    return {"ready": True, "model": model, "tau": tau, "n_noise": nn, "n_important": ni, "must_keep": len(mk),
            "cv_noise_cut": round(cut, 3), "cv_secs": round(time.perf_counter() - t0, 1), "trained_at": time.time(),
            "must_keep_norm": {_norm_line(x) for x in must_keep}}


class Advisor:
    """Hatterszalon tanul (a hivo nem var ra); ha nincs kesz modell, nincs pontszam (a lelet marad ugyanugy)."""

    def __init__(self):
        self.store = None
        self.m = None
        self.error = ""
        self._rev = None
        self._lock = threading.Lock()
        self._training = False
        self._last_try = 0.0

    def attach(self, store):
        self.store = store

    @staticmethod
    def enabled():
        import aiops
        return aiops.CFG.get("NOISE_ADVISOR", "on") == "on"

    def _doc(self):
        cur = self.store.current("known") if self.store else None
        return (cur or {"content": {}})["content"]

    def ensure(self):
        """Szukseg eseten (nincs modell / 6 oras / a known valtozott) elinditja az ujratanitast a hatterben. Nem blokkol."""
        if not self.store or not self.enabled():
            return
        now = time.monotonic()
        rev = self.store.revision_id("known")
        stale = self.m is None or (self.m.get("trained_at") and time.time() - self.m["trained_at"] > RETRAIN_S) or rev != self._rev
        with self._lock:
            if self._training or not stale or now - self._last_try < MIN_RETRAIN_S:
                return
            self._training, self._last_try = True, now
        threading.Thread(target=self._train, args=(rev,), daemon=True, name="noise-advisor").start()

    def _train(self, rev):
        try:
            import aiops
            doc = self._doc()
            known = aiops.Known(data=doc)
            rows = self.store.nov_training_rows(MAX_TRAIN)
            m = train(rows, known, doc.get("must_keep", []))
            self.m, self._rev, self.error = m, rev, ""
            aiops.log("zaj-tanacsado: " + (f"kesz (zaj {m['n_noise']}, fontos {m['n_important']}, tau {m['tau']:.1f}, {m['cv_secs']} mp)" if m.get("ready") else m["reason"]))
        except Exception as e:  # noqa: BLE001 - a tanacsado hibaja nem allithatja meg a szolgaltatast
            self.error = f"{type(e).__name__}: {e}"[:200]
        finally:
            self._training = False

    def score(self, f, known=None):
        """f: novelty-lelet (host, ident, level, tmpl). -> (pontszam, valoszinuleg_zaj) vagy None, ha nincs kesz modell."""
        m = self.m
        if not m or not m.get("ready"):
            return None
        s = m["model"].score(feats(f["ident"], f["level"], f["tmpl"]))
        likely = s > m["tau"]
        if likely and str(f["level"]).lower() in IMPORTANT:
            likely = False
        if likely and _norm_line(_text(f)) in m["must_keep_norm"]:
            likely = False
        if likely and known is not None and known.classify_idx(_text(f))[0] not in ("keep", "noise"):
            likely = False
        return round(s, 1), likely

    def info(self):
        m = self.m
        base = {"enabled": self.enabled(), "state": "off" if not self.enabled() else "learning", "error": self.error}
        if m is not None:
            if m.get("ready"):
                base.update({"state": "ready", "n_noise": m["n_noise"], "n_important": m["n_important"], "tau": round(m["tau"], 1),
                             "must_keep": m["must_keep"], "cv_noise_cut": m["cv_noise_cut"],
                             "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(m["trained_at"]))})
            else:
                base.update({"state": "insufficient", "reason": m["reason"]})
        if self._training and base["state"] not in ("ready", "off"):
            base["state"] = "training"
        if not self.enabled():
            base["state"] = "off"
        return base


ADVISOR = Advisor()
