"""Eseménybemeneti réteg: súlyosság-normalizálás + mezőleképezés (adapter) a monitoring-eszközök eltérő rekordjaihoz.

A konzol egyetlen közös skálán dolgozik: debug | info | warning | error | critical. Az eszközök saját skálát használnak (pl. Dynatrace AVAILABILITY,
SolarWinds Serious, vROps Immediate, LogicMonitor 4), ezeket a 'ingest' konfig-dokumentum képezi le. Szerkezete:

  {"sources": {"<eszkoz-kod>": {
        "severity": {"<nyers ertek>": "<szint>", ...},     # kis/nagybetu nem szamit; szam is lehet ("4")
        "default":  "error",                               # nem leképezett érték: alapértelmezés (a 'warning' alatti szint nem ajánlott)
        "fields":   {"host": "entity.name", "msg": "title", "ts": "startTime", "level": "severity", "ident": "problemId"}}}}

A beépített alapok (DEFAULT_SOURCES) a négy eszköz TIPIKUS skáláit tükrözik, NEM hivatalos gyártói specifikációk: az éles értékekkel egyeztetni kell,
és a konfig felülírhatja őket. Elv: a nem leképezett súlyosság SOHA nem lesz észrevétlenül 'info' (alapértelmezés 'error'), és az importer megszámolja őket.
A modul csak a standard könyvtárat használja, és nem importálja az aiops-ot.
"""
import datetime as dt
import re

LEVELS = ("debug", "info", "warning", "error", "critical")
SOURCE_RX = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,39}$")
MAX_SOURCES, MAX_MAP = 50, 100
FIELD_KEYS = ("ts", "host", "ident", "level", "msg")
FIELD_DEFAULTS = {"ts": "ts", "host": "host", "ident": "ident", "level": "level", "msg": "msg"}
FALLBACK_LEVEL = "error"

# általános nevek (syslog / gyakori szövegek): minden forrásra érvényesek, a forrás saját leképezése előbb számít
GENERIC = {"emerg": "critical", "emergency": "critical", "alert": "critical", "crit": "critical", "critical": "critical", "fatal": "critical",
           "err": "error", "error": "error", "warn": "warning", "warning": "warning", "notice": "info", "info": "info", "information": "info",
           "informational": "info", "debug": "debug", "trace": "debug"}

DEFAULT_SOURCES = {
    "dynatrace": {"severity": {"AVAILABILITY": "critical", "ERROR": "error", "PERFORMANCE": "warning", "RESOURCE_CONTENTION": "warning", "CUSTOM_ALERT": "warning", "INFO": "info"}},
    "logicmonitor": {"severity": {"4": "critical", "3": "error", "2": "warning", "1": "info", "0": "info"}},
    "solarwinds": {"severity": {"0": "info", "1": "warning", "2": "critical", "3": "error", "4": "info", "serious": "error", "notice": "info"}},
    "vrops": {"severity": {"immediate": "error", "critical": "critical", "warning": "warning", "info": "info"}},
}


def _key(v):
    return str(v).strip().lower()


def validate(doc):
    """-> hibák listája (üres = rendben). A '_' kezdetű kulcsok megjegyzések."""
    if not isinstance(doc, dict):
        return ["the document must be a JSON object"]
    errs = [f"{k}: unknown top-level key" for k in doc if k != "sources" and not str(k).startswith("_")]
    src = doc.get("sources", {})
    if not isinstance(src, dict):
        return errs + ["sources: must be an object"]
    if len(src) > MAX_SOURCES:
        errs.append(f"sources: at most {MAX_SOURCES}")
    for name, s in src.items():
        w = f"sources.{name}"
        if not SOURCE_RX.match(str(name)):
            errs.append(f"{w}: the source code must match {SOURCE_RX.pattern} (lower case)")
        if not isinstance(s, dict):
            errs.append(f"{w}: must be an object")
            continue
        errs += [f"{w}.{k}: unknown key" for k in s if k not in ("severity", "default", "fields") and not str(k).startswith("_")]
        sev = s.get("severity", {})
        if not isinstance(sev, dict) or len(sev) > MAX_MAP:
            errs.append(f"{w}.severity: must be an object with at most {MAX_MAP} entries")
        else:
            for raw, lvl in sev.items():
                if not str(raw).strip() or len(str(raw)) > 60:
                    errs.append(f"{w}.severity: empty or too long raw value")
                if lvl not in LEVELS:
                    errs.append(f"{w}.severity[{raw!r}]: level must be one of {', '.join(LEVELS)}")
            if len({_key(k) for k in sev}) != len(sev):
                errs.append(f"{w}.severity: raw values differ only in case")
        if "default" in s and s["default"] not in LEVELS:
            errs.append(f"{w}.default: level must be one of {', '.join(LEVELS)}")
        fl = s.get("fields", {})
        if not isinstance(fl, dict):
            errs.append(f"{w}.fields: must be an object")
        else:
            for k, p in fl.items():
                if k not in FIELD_KEYS:
                    errs.append(f"{w}.fields.{k}: unknown (expected {', '.join(FIELD_KEYS)})")
                elif not isinstance(p, str) or not re.match(r"^[A-Za-z0-9_.@:-]{1,120}$", p):
                    errs.append(f"{w}.fields.{k}: must be a dotted field path")
    return errs


class Config:
    """Az érvényes konfig + a beépített alapok összefésülve (a konfig felülír). Üres / None dokumentum = csak az alapok."""

    def __init__(self, doc=None):
        self.sources = {}
        for name, s in DEFAULT_SOURCES.items():
            self.sources[name] = {"severity": {_key(k): v for k, v in s["severity"].items()}, "default": s.get("default", FALLBACK_LEVEL), "fields": {}}
        for name, s in ((doc or {}).get("sources") or {}).items():
            cur = self.sources.setdefault(name, {"severity": {}, "default": FALLBACK_LEVEL, "fields": {}})
            cur["severity"].update({_key(k): v for k, v in (s.get("severity") or {}).items()})
            if "default" in s:
                cur["default"] = s["default"]
            cur["fields"].update(s.get("fields") or {})

    def level(self, source, raw):
        """-> (szint, leképezett-e). Üres / hiányzó nyers érték: nincs adat, ezért a forrás alapértelmezése ('mapped' = False)."""
        s = self.sources.get(_key(source or ""), None)
        k = _key(raw) if raw is not None else ""
        if k and s and k in s["severity"]:
            return s["severity"][k], True
        if k in GENERIC:
            return GENERIC[k], True
        return (s["default"] if s else FALLBACK_LEVEL), False


def effective(doc=None):
    """A hatályos leképezés (beépített alap + konfig) a kezelőfelületnek: {forrás: {severity, default, fields, builtin}}."""
    return {n: {"severity": dict(s["severity"]), "default": s["default"], "fields": dict(s["fields"]), "builtin": n in DEFAULT_SOURCES}
            for n, s in sorted(Config(doc).sources.items())}


ACTIVE = Config()   # a konzol runtime-ja cseréli a konfig változásakor (mint az aiops.TOPOLOGY)


def set_active(doc):
    global ACTIVE
    ACTIVE = Config(doc)


def level_of(source, raw):
    """A normalizált szint az aktív konfiggal (a súlyosság-ellenőrzések ezt használják, nem a nyers szöveget)."""
    return ACTIVE.level(source, raw)[0]


def _path(rec, path):
    cur = rec
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def parse_ts(v):
    """Epoch (mp / ms / µs) vagy ISO-8601 -> unix idő (float); ValueError, ha nem értelmezhető. A zóna nélküli idő UTC."""
    if isinstance(v, bool) or v is None:
        raise ValueError("no timestamp")
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d+(\.\d+)?", v.strip())):
        x = float(v)
        return x / 1e6 if x > 1e14 else x / 1e3 if x > 1e11 else x
    t = dt.datetime.fromisoformat(str(v).strip().replace("Z", "+00:00"))
    return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).timestamp()


def to_event(rec, source, cfg=None):
    """Egy eszköz-rekord (dict) -> (esemény a közös sémában, nem leképezett nyers súlyosság vagy None). ValueError, ha a rekord nem alakítható át
    (nincs host / üzenet / időpont). A host és az üzenet szóközei levágva; a hossz korlátozott (a naplók adatok, nem utasítások)."""
    cfg = cfg or ACTIVE
    s = cfg.sources.get(_key(source), {"fields": {}})
    fm = dict(FIELD_DEFAULTS, **s["fields"])
    host, msg = _path(rec, fm["host"]), _path(rec, fm["msg"])
    if host is None or not str(host).strip():
        raise ValueError(f"no host ({fm['host']})")
    if msg is None or not str(msg).strip():
        raise ValueError(f"no message ({fm['msg']})")
    ts = parse_ts(_path(rec, fm["ts"]))
    raw = _path(rec, fm["level"])
    level, mapped = cfg.level(source, raw)
    ident = _path(rec, fm["ident"])
    ev = {"ts": round(ts, 3), "source": _key(source), "host": str(host).strip()[:120], "ident": str(ident).strip()[:80] if ident not in (None, "") else _key(source),
          "level": level, "msg": str(msg).strip()[:1000]}
    return ev, (None if mapped else ("(missing)" if raw is None else str(raw)))
