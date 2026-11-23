"""Futasideju osszekotes: a konfig-tar, a hatterszal (aiops) es a konzol kozott.

- bootstrap(): az elso inditaskor a known-dokumentum betoltese (KNOWN_FILE vagy a beepitett alap)
- get_known(): a hatterszal hivja minden kor elejen; a konfig valtozasat (verzio-azonosito) azonnal felveszi
- validate_doc()/apply_known_patch(): a javaslatok es a PUT-ok kozos ellenorzese
"""
import copy
import json
import os
import threading
import time
import uuid

import aiops
import detectors
import ingest
import rules
import rulesync
import settings
import topology

DEFAULTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "defaults", "known.default.json")
KEYS = ("known", "settings", "topology", "detectors", "ingest", "rules")


class DocError(Exception):
    def __init__(self, errors):
        super().__init__("; ".join(errors))
        self.errors = errors


def validate_doc(key, content):
    """-> tisztitott dokumentum; DocError ha ervenytelen."""
    if key == "known":
        errs = aiops.validate_known(content)
        if errs:
            raise DocError(errs)
        return content
    if key == "settings":
        clean, errs = settings.validate(content)
        if errs:
            raise DocError(errs)
        return clean
    if key == "topology":
        errs = topology.validate(content)
        if errs:
            raise DocError(errs)
        return content
    if key == "detectors":
        errs = detectors.validate(content)
        if errs:
            raise DocError(errs)
        return content
    if key == "ingest":
        errs = ingest.validate(content)
        if errs:
            raise DocError(errs)
        return content
    if key == "rules":
        errs = rules.validate(content)
        if errs:
            raise DocError(errs)
        return content
    raise DocError([f"unknown config key {key!r} (expected one of {', '.join(KEYS)})"])


PATCH_KEYS = ("add_noise", "remove_noise", "add_known_issues", "remove_known_issue_ids", "set_context",
              "add_snoozes", "remove_snooze_ids", "prune_expired_snoozes")


def _new_snooze(s, now, errs):
    """Egy add_snoozes elem -> a dokumentumba kerulo snooze (vagy None + hiba). 'hours' VAGY 'until' kell."""
    if not isinstance(s, dict):
        errs.append("add_snoozes: each item must be an object")
        return None
    extra = [k for k in s if k not in ("id", "regex", "hours", "until", "note")]
    if extra:
        errs.append(f"add_snoozes: unknown field(s) {', '.join(extra)}")
        return None
    if (s.get("hours") is None) == (s.get("until") is None):
        errs.append("add_snoozes: give exactly one of 'hours' or 'until'")
        return None
    if s.get("hours") is not None:
        h = s["hours"]
        if isinstance(h, bool) or not isinstance(h, (int, float)) or not 0 < h <= aiops.SNOOZE_MAX_HOURS:
            errs.append(f"add_snoozes: 'hours' must be a number between 0 and {aiops.SNOOZE_MAX_HOURS} (90 days)")
            return None
        until = now + aiops.dt.timedelta(hours=h)
    else:
        until = aiops.parse_until(s["until"])
        if until is None:
            errs.append("add_snoozes: 'until' must be a UTC time like 2026-01-31T12:00:00Z")
            return None
        if until <= now:
            errs.append("add_snoozes: 'until' is in the past")
            return None
        if until > now + aiops.dt.timedelta(hours=aiops.SNOOZE_MAX_HOURS):
            errs.append("add_snoozes: a snooze is limited to 90 days; use a noise rule for permanent muting")
            return None
    out = {"id": s.get("id") or "sn-" + uuid.uuid4().hex[:8], "regex": s.get("regex"),
           "until": aiops.iso(until.replace(microsecond=0))}
    if s.get("note"):
        out["note"] = str(s["note"])[:300]
    return out


def apply_known_patch(doc, patch):
    """Kis, kovetheto modositas a known-dokumentumon (a javaslatok diffje kicsi marad). -> uj dokumentum"""
    if not isinstance(patch, dict):
        raise DocError(["patch must be an object"])
    errs = [f"{k}: unknown patch key (expected {', '.join(PATCH_KEYS)})" for k in patch if k not in PATCH_KEYS]
    if errs:
        raise DocError(errs)
    d = copy.deepcopy(doc)
    d.setdefault("noise", [])
    d.setdefault("known_issues", [])
    for rx in patch.get("remove_noise", []):
        if rx not in d["noise"]:
            errs.append(f"remove_noise: no such noise regex: {rx!r}")
        else:
            d["noise"].remove(rx)
    for rx in patch.get("add_noise", []):
        if rx in d["noise"]:
            errs.append(f"add_noise: already present: {rx!r}")
        else:
            d["noise"].append(rx)
    ids = [k.get("id") for k in d["known_issues"] if isinstance(k, dict)]
    for kid in patch.get("remove_known_issue_ids", []):
        if kid not in ids:
            errs.append(f"remove_known_issue_ids: no such id: {kid!r}")
        else:
            d["known_issues"] = [k for k in d["known_issues"] if k.get("id") != kid]
    for k in patch.get("add_known_issues", []):
        d["known_issues"].append(k)
    if "set_context" in patch:
        d["context"] = patch["set_context"]
    if any(k in patch for k in ("add_snoozes", "remove_snooze_ids", "prune_expired_snoozes")):
        now = aiops.utcnow().replace(tzinfo=None)
        sn = d.setdefault("snoozes", [])
        sids = [s.get("id") for s in sn if isinstance(s, dict)]
        for sid in patch.get("remove_snooze_ids", []):
            if sid not in sids:
                errs.append(f"remove_snooze_ids: no such id: {sid!r}")
            else:
                sn[:] = [s for s in sn if s.get("id") != sid]
        if patch.get("prune_expired_snoozes"):
            sn[:] = [s for s in sn if (aiops.parse_until(s.get("until")) or now) > now]
        for s in patch.get("add_snoozes", []):
            new = _new_snooze(s, now, errs)
            if new is None:
                continue
            if any(x.get("id") == new["id"] for x in sn):
                errs.append(f"add_snoozes: id already present: {new['id']!r}")
            else:
                sn.append(new)
        if not sn:
            d.pop("snoozes", None)
    if errs:
        raise DocError(errs)
    return d


class Runtime:
    def __init__(self, store):
        self.store = store
        self._lock = threading.Lock()
        self._known = None
        self._known_rev = -1
        self._settings_rev = -1
        self._topo_rev = -1
        self._det_rev = -1
        self._ing_rev = -1
        self._rules_rev = -1
        self._raw = {}  # hours -> (monotonic, raw)  (a regex-teszt gyorsitotara)

    # ---- inditas
    def bootstrap(self):
        if self.store.revision_id("known") == 0:
            doc, author = None, "seed:default"
            path = aiops.CFG.get("KNOWN_FILE")
            if path and os.path.exists(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        cand = json.load(f)
                    if not aiops.validate_known(cand):
                        doc, author = cand, "seed:file"
                    else:
                        aiops.log(f"a KNOWN_FILE ({path}) ervenytelen, a beepitett alap kerul be")
                except (OSError, ValueError) as e:
                    aiops.log(f"a KNOWN_FILE nem olvashato: {e}")
            if doc is None:
                with open(DEFAULTS_FILE, encoding="utf-8") as f:
                    doc = json.load(f)
            self.store.put("known", doc, author, "initial configuration")
            aiops.log(f"known-konfig betoltve ({author})")
        self.sync()

    # ---- a konfig valtozasanak felvetele
    def sync(self):
        """Idempotens: csak akkor dolgozik, ha a verzio valtozott."""
        with self._lock:
            sid = self.store.revision_id("settings")
            settings_changed = sid != self._settings_rev
            if settings_changed:
                cur = self.store.current("settings")
                settings.apply(cur["content"] if cur else {})
                self._settings_rev = sid
            tid = self.store.revision_id("topology")
            if tid != self._topo_rev:
                cur = self.store.current("topology")
                aiops.TOPOLOGY = topology.Topology(cur["content"] if cur else {})
                self._topo_rev = tid
            did = self.store.revision_id("detectors")
            if did != self._det_rev:
                cur = self.store.current("detectors")
                aiops.DETECTORS = [detectors.full(x) for x in (cur["content"].get("detectors", []) if cur else [])]
                self._det_rev = did
            rid = self.store.revision_id("rules")
            if rid != self._rules_rev or settings_changed:
                self._rules_rev = rid
                rulesync.kick(self.store)      # kikapcsolt kiadasnal csak az allapotot frissiti ('off'); hatterszalban fut
            iid = self.store.revision_id("ingest")
            if iid != self._ing_rev:
                cur = self.store.current("ingest")
                ingest.set_active(cur["content"] if cur else {})
                self._ing_rev = iid
            kid = self.store.revision_id("known")
            if kid != self._known_rev:
                cur = self.store.current("known")
                self._known = aiops.Known(data=cur["content"])
                self._known_rev = kid
                self._cover_findings()

    def _cover_findings(self):
        """Zajszabaly-valtozas utan a mar nyitott novelty-leletek kozul azokat, amelyekre MOST zajszabaly illeszkedik, lezarja
        (a detektor az uj leleteket mar szuri; a regi nyitottak kulonben a listan maradnanak). Csak a 'noise' talalat szamit
        (a snooze ideiglenes, az ismert ugy nem zaj). Hiba nem allithatja meg a szinkront."""
        try:
            rows = self.store.nov_findings("open", limit=500)
            ids = [r["id"] for r in rows if self._known.classify_idx(f"{r['host']} | {r['ident']} | {r['tmpl']}")[0] == "noise"]
            if ids:
                n = self.store.nov_dismiss_ids(ids, "system", f"{len(ids)} open finding(s) now covered by a noise rule")
                aiops.log(f"novelty: {n} nyitott lelet lezarva (a zajszabalyok mar lefedik)")
        except Exception as e:  # noqa: BLE001
            aiops.log(f"novelty: automatikus lezaras sikertelen: {type(e).__name__}: {e}")

    def get_known(self):
        self.sync()
        return self._known

    def changed(self):
        """Konfig-iras utan: azonnali felvetel + a hatterszal felebresztese."""
        self.sync()
        aiops.WAKE.set()

    # ---- regex-teszt: a nyers sorok gyorsitotarazva (a VictoriaLogs-lekerdezes lassabb, mint a regexek)
    def raw_rows(self, hours):
        hit = self._raw.get(hours)
        if hit and time.monotonic() - hit[0] < 120:
            return hit[1]
        now = aiops.utcnow()
        raw = aiops.collect(now - aiops.dt.timedelta(hours=hours), now)
        self._raw[hours] = (time.monotonic(), raw)
        return raw
