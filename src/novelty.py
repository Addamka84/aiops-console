"""Ujdonsag- es gyakorisag-ugras eszleles a naplokon (kod, nem modell).

Minden naplosor sablonna alakul (a szamok <N>-re vonva, mint a modell bemenetenel), es a tar (store.py, nov_* tablak)
megjegyzi, melyik sablont mikor latta eloszor/utoljara es mennyiszer. Ket leletet ad:
  * "new":   olyan sablon, amit eddig sosem latott (a zajlista / snooze / ismert ugyek erre is hatnak);
  * "spike": a sablon gyakorisaga a sajat atlaganak sokszorosa (NOVELTY_SPIKE_FACTOR, es legalabb NOVELTY_SPIKE_MIN sor/ablak).
Jelentes modban fut: a leletek a Status oldalon es a napi osszefoglalo bemenetenek egy szakaszaban jelennek meg, ertesites nincs.

Menet: az elso inditaskor az alapvonalat a tarolt naplokbol toltjuk fel (NOVELTY_BACKFILL_DAYS, 12 oras darabokban, hogy az elso
napon ne legyen hamis "uj"); ha ez nem megy, NOVELTY_LEARN_HOURS ideig tanul lelet nelkul. Utana minden NOVELTY_INTERVAL_MIN
percben egy osszefuggo, atfedes nelkuli ablakot dolgoz fel (a darabok vegei egymasba illenek, igy a szamlalas pontos).
"""
import datetime as dt
import hashlib
import re
import time

import aiops

# (forras, szuro, hoszt-mezo, azonosito-mezo, szint-mezo)  - a collect() forrasaival egyezo szurok (az OPNsense zajos)
SOURCES = (
    ("syslog", "pipeline:syslog -host:OPNsense*", "host", "appname", "severity"),
    ("journald", "_HOSTNAME:*", "_HOSTNAME", "SYSLOG_IDENTIFIER", "PRIORITY"),
    ("docker", "pipeline:docker", "host", "appname", None),
)
LEVEL_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
LIVE_LIMIT = 3000        # sablon / forras / ablak
BACKFILL_LIMIT = 20000   # sablon / forras / 12 oras darab
BACKFILL_CHUNK_H = 12
MAX_WINDOW_H = 6         # leallas utani felzarkozas: egy kor legfeljebb ennyi oranyi naplot dolgoz fel
MAX_NEW_PER_SCAN = 25
SPIKE_COOLDOWN_H = 6
MIN_TRACK_MIN = 360      # ennyi ideje kovetett minta utan szamit a "sajat atlag"
VL_OFFSET_S = 60         # a VictoriaLogs a legutobbi ~30 mp-et meg nem mutatja
RETAIN_PATTERNS_DAYS = 60
RETAIN_FINDINGS_DAYS = 30
MAX_BACKFILL_FAILS = 5

NORM_VERSION = 3         # a sablonkepzes verzioja: valtozasakor a tarolt mintak egyszer ujrakulcsolodnak (_migrate)
MAX_PATTERNS = 250000

# A VictoriaLogs collapse_nums csak a szamokat vonja ossze; a hexa azonositok (konteneres veth-nevek, rovid hash-ek) es a "56AM"
# tipusu idok szetszorodnanak, es minden ujrainditas "uj" mintakat szulne.
_VETH_RX = re.compile(r"\bveth[0-9a-f]{6,}")
_ID_RX = re.compile(r"(?<![\w<])(?:[0-9a-f]|<N>){7,}(?![\w>])")
_AMPM_RX = re.compile(r"\b\d+(AM|PM)\b")
_ANSI_RX = re.compile(r"\x1b?\[(?:<N>|\d+)(?:;(?:<N>|\d+))*m")           # szinkodok (a szamok mar <N>-re vonva lehetnek; az ESC lehet lathatatlan)
_BAR_RX = re.compile(r"\[[=>\- ]{5,}\]")                                  # elorehaladas-jelzo: [=====>    ]
_DECIMAL_RX = re.compile(r"(?<=<N>)\.\d+")                               # a collapse_nums utan maradt tizedes: <N>.67kB
_NODE_RX = re.compile(r"(@<N>:)[0-9a-f]{1,3}(?=•)")                     # Matter csomopont/vegpont-azonosito: @<N>:1a•


def normalize(tmpl):
    """A VictoriaLogs-sablon tovabbi egyszerusitese: szinkodok, elorehaladas-jelzok es tizedesek eltavolitasa/osszevonasa,
    veth<ID>, hexa azonositok -> <ID>, <szam>AM/PM -> <N>AM/PM."""
    t = tmpl.lstrip("﻿")
    t = _ANSI_RX.sub("", t)
    t = _BAR_RX.sub("[<BAR>]", t)
    t = _DECIMAL_RX.sub("", t)
    t = _NODE_RX.sub(r"\1<ID>", t)
    t = _VETH_RX.sub("veth<ID>", t)
    # azonosito csak akkor, ha szamjegyet (vagy <N>-t) tartalmaz: igy az "added", "decade" tipusu szavak nem esnek ide
    t = _ID_RX.sub(lambda m: "<ID>" if re.search(r"\d|<N>", m.group(0)) else m.group(0), t)
    return _AMPM_RX.sub(r"<N>\1", t)


STATE = {"mode": "off", "last_scan": None, "next_from": None, "backfill": "", "error": "", "truncated": [],
         "learning_until": "", "last_new": 0, "last_spikes": 0}


def _utc(s):
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def level_rank(level):
    return LEVEL_NAMES.index(level) if level in LEVEL_NAMES else (4 if level == "error" else 6)


def _level(src, raw, tmpl):
    if src == "docker":
        return "error" if re.search(aiops.DOCKER_ERR_RX, tmpl) else "info"
    if src == "journald":
        try:
            return LEVEL_NAMES[int(raw)]
        except (TypeError, ValueError, IndexError):
            return "info"
    return (raw or "info").lower()


def _fetch(src, t_from, t_to, limit, with_times, timeout):
    name, flt, hf, idf, lf = src
    by = ", ".join([hf, idf] + ([lf] if lf else []) + ["_msg"])
    agg = "count() as hits" + (", min(_time) as first, max(_time) as last" if with_times else "")
    q = (f"_time:[{aiops.iso(t_from)}, {aiops.iso(t_to)}) {flt} | collapse_nums | stats by ({by}) {agg} "
         f"| sort by (hits desc) | limit {limit}")
    rows = aiops.vl_query(q, timeout=timeout)
    out = []
    for r in rows:
        try:
            hits = int(r.get("hits", 0) or 0)
        except ValueError:
            continue
        tmpl = normalize(aiops.cut(str(r.get("_msg", "")), 400))
        if hits <= 0 or not tmpl.strip():
            continue
        out.append({"source": name, "host": str(r.get(hf, "")), "ident": str(r.get(idf, "")),
                    "level": _level(name, r.get(lf) if lf else "", tmpl), "tmpl": tmpl, "hits": hits,
                    "first": str(r.get("first", ""))[:19] + "Z" if r.get("first") else "",
                    "last": str(r.get("last", ""))[:19] + "Z" if r.get("last") else ""})
    return out, len(rows) >= limit


def _key(r):
    return hashlib.sha1(f"{r['source']}|{r['ident']}|{r['tmpl']}".encode("utf-8", "replace")).hexdigest()[:20]


def _merge(rows):
    """Azonos kulcs (ugyanaz a sablon tobb hoszton) osszevonasa."""
    out = {}
    for r in rows:
        k = _key(r)
        if k in out:
            out[k]["hits"] += r["hits"]
            out[k]["first"] = min(x for x in (out[k]["first"], r["first"]) if x) if (out[k]["first"] or r["first"]) else ""
            out[k]["last"] = max(out[k]["last"], r["last"])
        else:
            out[k] = dict(r)
    return out


def _is_reportable(known, r, now):
    kind, _ = known.classify_idx(f"{r['host']} | {r['ident']} | {r['tmpl']}")  # a snooze-lejaratot maga szamolja
    return kind == "keep"


def _migrate(store):
    """Ha a sablonkepzes valtozott (NORM_VERSION), a tarolt mintak sablonjat ugyanugy egyszerusiti es ujrakulcsolja, hogy a valtozas
    ne dobjon fel ujra minden erintett mintat 'ujkent'. Egyszeri; hiba eseten a kovetkezo kor ujraprobalja."""
    if str(store.nov_meta("norm", "1")) == str(NORM_VERSION):
        return
    before, after = store.nov_rekey(lambda r: (_key(dict(r, tmpl=normalize(r["tmpl"]))), normalize(r["tmpl"])))
    store.nov_set_meta("norm", NORM_VERSION)
    aiops.log(f"ujdonsag-eszleles: sablonkepzes v{NORM_VERSION}, {before} minta -> {after}")


# ---------------------------------------------------------------- alapvonal feltoltese (elozmenybol)

def _backfill_chunk(store, now):
    start = _utc(store.nov_meta("bf_start"))
    nxt = _utc(store.nov_meta("bf_next"))
    end = _utc(store.nov_meta("bf_end"))
    stop = min(nxt + dt.timedelta(hours=BACKFILL_CHUNK_H), end)
    rows, trunc = [], []
    for src in SOURCES:
        got, t = _fetch(src, nxt, stop, BACKFILL_LIMIT, True, 180)
        rows.extend(got)
        if t:
            trunc.append(src[0])
    ups = []
    for k, r in _merge(rows).items():
        ups.append({"key": k, "source": r["source"], "host": r["host"], "ident": r["ident"], "level": r["level"], "tmpl": r["tmpl"],
                    "first_seen": r["first"] or aiops.iso(nxt), "last_seen": r["last"] or aiops.iso(stop), "total": r["hits"],
                    "since": aiops.iso(start), "last_spike": ""})
    if ups:
        store.nov_upsert(ups)
    if trunc:
        STATE["truncated"] = sorted(set(STATE["truncated"]) | set(trunc))
    store.nov_set_meta("bf_fails", 0)
    if stop >= end:
        store.nov_set_meta("backfill", "done")
        STATE["backfill"] = "done"
        aiops.log(f"ujdonsag-eszleles: alapvonal kesz ({store.nov_counts()['patterns']} minta)")
    else:
        store.nov_set_meta("bf_next", aiops.iso(stop))


def _backfill_failed(store, now):
    fails = int(store.nov_meta("bf_fails", "0") or 0) + 1
    store.nov_set_meta("bf_fails", fails)
    if fails >= MAX_BACKFILL_FAILS:
        until = now + dt.timedelta(hours=aiops.CFG["NOVELTY_LEARN_HOURS"])
        store.nov_set_meta("backfill", "failed")
        store.nov_set_meta("learn_until", aiops.iso(until))
        STATE["backfill"] = "failed"
        aiops.log("ujdonsag-eszleles: az elozmeny-feltoltes nem sikerult, tanulasi idoszak indul")


# ---------------------------------------------------------------- elo feldolgozas

def _process(store, known, rows, t_from, t_to, now, learning):
    keyed = _merge(rows)
    existing = store.nov_patterns(keyed.keys())
    win_min = max(1.0, (t_to - t_from).total_seconds() / 60)
    ups, new_c, spikes = [], [], []
    for k, r in keyed.items():
        ex = existing.get(k)
        row = {"key": k, "source": r["source"], "host": r["host"], "ident": r["ident"], "level": r["level"], "tmpl": r["tmpl"],
               "first_seen": aiops.iso(t_from), "last_seen": aiops.iso(t_to), "total": r["hits"], "since": aiops.iso(t_from),
               "last_spike": ""}
        if ex is None:
            if not learning and _is_reportable(known, r, now):
                new_c.append(r | {"key": k})
        else:
            mins = (t_from - _utc(ex["since"])).total_seconds() / 60
            if mins >= MIN_TRACK_MIN and r["hits"] >= aiops.CFG["NOVELTY_SPIKE_MIN"]:
                mean = ex["total"] / mins  # sor / perc, az aktualis ablak elott
                if (r["hits"] / win_min >= aiops.CFG["NOVELTY_SPIKE_FACTOR"] * max(mean, 0.005)
                        and (not ex["last_spike"] or _utc(ex["last_spike"]) + dt.timedelta(hours=SPIKE_COOLDOWN_H) <= now)
                        and _is_reportable(known, r, now)):
                    spikes.append(r | {"key": k, "baseline": round(mean * win_min, 1)})
                    row["last_spike"] = aiops.iso(now)
        ups.append(row)
    if ups:
        store.nov_upsert(ups)
    ts = aiops.iso(now)
    items = []
    new_c.sort(key=lambda r: (level_rank(r["level"]), -r["hits"]))
    for r in new_c[:MAX_NEW_PER_SCAN]:
        items.append({"ts": ts, "kind": "new", "key": r["key"], "source": r["source"], "host": r["host"], "ident": r["ident"],
                      "level": r["level"], "tmpl": r["tmpl"], "hits": r["hits"], "baseline": 0})
    if len(new_c) > MAX_NEW_PER_SCAN:
        more = len(new_c) - MAX_NEW_PER_SCAN
        items.append({"ts": ts, "kind": "new", "key": "many", "source": "-", "host": "-", "ident": "(many)", "level": "info",
                      "tmpl": f"{more} more new patterns in this scan window (cap {MAX_NEW_PER_SCAN}; many different messages at once)",
                      "hits": more, "baseline": 0})
    for r in sorted(spikes, key=lambda r: -r["hits"])[:MAX_NEW_PER_SCAN]:
        items.append({"ts": ts, "kind": "spike", "key": r["key"], "source": r["source"], "host": r["host"], "ident": r["ident"],
                      "level": r["level"], "tmpl": r["tmpl"], "hits": r["hits"], "baseline": r["baseline"]})
    if items:
        store.nov_add_findings(items)
    STATE["last_new"], STATE["last_spikes"] = len(new_c), len(spikes)


def _scan(store, known, now):
    nf = _utc(store.nov_meta("next_from"))
    due = (now - dt.timedelta(seconds=VL_OFFSET_S)).replace(microsecond=0)
    if (due - nf).total_seconds() < aiops.CFG["NOVELTY_INTERVAL_MIN"] * 60:
        return
    to = min(due, nf + dt.timedelta(hours=MAX_WINDOW_H))
    rows, trunc = [], []
    for src in SOURCES:
        got, t = _fetch(src, nf, to, LIVE_LIMIT, False, 90)
        rows.extend(got)
        if t:
            trunc.append(src[0])
    lu = store.nov_meta("learn_until")
    learning = bool(lu) and now < _utc(lu)
    _process(store, known, rows, nf, to, now, learning)
    store.nov_set_meta("next_from", aiops.iso(to))
    STATE["truncated"] = trunc
    STATE["last_scan"] = aiops.iso(now)
    store.nov_prune(aiops.iso(now - dt.timedelta(days=RETAIN_PATTERNS_DAYS)), MAX_PATTERNS,
                    aiops.iso(now - dt.timedelta(days=RETAIN_FINDINGS_DAYS)))


def step(store, known, now=None):
    """A hatterszal minden korben hivja; maga donti el, kell-e dolgoznia. SOHA nem dob kivetelt."""
    now = now or aiops.utcnow()
    mode = aiops.CFG["NOVELTY_MODE"]
    STATE["mode"] = mode
    if mode != "report" or store is None:
        return
    try:
        if not store.nov_meta("next_from"):
            store.nov_set_meta("norm", NORM_VERSION)  # uj telepites: a minta mar az uj sablonkepzessel kerul be
            live_from = (now - dt.timedelta(seconds=VL_OFFSET_S + 30)).replace(microsecond=0)
            store.nov_set_meta("next_from", aiops.iso(live_from))
            days = aiops.CFG["NOVELTY_BACKFILL_DAYS"]
            if days > 0:
                start = live_from - dt.timedelta(days=days)
                for k, v in (("bf_start", aiops.iso(start)), ("bf_next", aiops.iso(start)), ("bf_end", aiops.iso(live_from)),
                             ("backfill", "running")):
                    store.nov_set_meta(k, v)
            else:
                store.nov_set_meta("learn_until", aiops.iso(now + dt.timedelta(hours=aiops.CFG["NOVELTY_LEARN_HOURS"])))
        _migrate(store)
        STATE["next_from"] = store.nov_meta("next_from")
        STATE["backfill"] = store.nov_meta("backfill", "")
        STATE["learning_until"] = store.nov_meta("learn_until", "")
        if STATE["backfill"] == "running":
            try:
                _backfill_chunk(store, now)
            except (OSError, ValueError) as e:
                _backfill_failed(store, now)
                raise
            return
        _scan(store, known, now)
        STATE["error"] = ""
    except (OSError, ValueError) as e:
        STATE["error"] = f"{type(e).__name__}: {e}"[:200]
        aiops.log(f"ujdonsag-eszleles: lekerdezes sikertelen: {e}", key="novelty")
    except Exception as e:  # noqa: BLE001 - a hatterszal ne haljon meg
        STATE["error"] = f"{type(e).__name__}: {e}"[:200]
        aiops.log(f"ujdonsag-eszleles: varatlan hiba: {type(e).__name__}: {e}", key="novelty")


def run_loop(store, get_known, period_s=20):
    """A sajat szal ciklusa (a service_loop inditja). A step() sajat hibait elnyeli."""
    while True:
        try:
            step(store, get_known())
        except Exception as e:  # noqa: BLE001
            aiops.log(f"ujdonsag-ciklus hiba: {type(e).__name__}: {e}", key="novelty_loop")
        time.sleep(period_s)


def status(store):
    c = store.nov_counts() if store is not None else {"patterns": 0, "open_findings": 0}
    return dict(STATE) | c | {"interval_min": aiops.CFG["NOVELTY_INTERVAL_MIN"], "spike_factor": aiops.CFG["NOVELTY_SPIKE_FACTOR"],
                              "spike_min": aiops.CFG["NOVELTY_SPIKE_MIN"]}


def digest_lines(store, t_from, t_to, limit=10):
    """A napi osszefoglalo bemenetenek szakasza: az ablakban talalt, meg nem elintezett leletek (sulyossag, majd gyakorisag szerint)."""
    if store is None or aiops.CFG["NOVELTY_MODE"] != "report":
        return []
    lo, hi = aiops.iso(t_from), aiops.iso(t_to)
    items = [i for i in store.nov_findings("open", since=lo, limit=300) if i["ts"] <= hi]
    if not items:
        return []
    items.sort(key=lambda i: (level_rank(i["level"]), -i["hits"]))
    out = ["== New log patterns / rate spikes found by a detector (never seen before, or far above their normal rate). "
           "They are NOT necessarily problems: report one only if the text itself shows a real fault; otherwise ignore it."]
    for i in items[:limit]:
        what = "NEW" if i["kind"] == "new" else f"SPIKE (usual ~{i['baseline']:g} per window)"
        out.append(f"{i['host']} | {i['ident']} | {i['level']} | {what} {i['hits']}x | {aiops.cut(i['tmpl'], 160)}")
    if len(items) > limit:
        out.append(f"(+{len(items) - limit} more not shown)")
    return out
