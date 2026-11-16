"""Detektorok: a UI-rol szerkesztheto, naplo-alapu szabalyok, amelyeket az aiops maga ertekel ki (nem a vmalert).

Egy verziozott konfig-dokumentum ('detectors', mint a 'known'): {"detectors": [...]}. Egy detektor:
  id, name, enabled (alap: igaz), query (LogsQL SZURO, csovek nelkul), group_by [mezok] (csak mode=count),
  mode: count (>= threshold talalat az ablakban) | absent (az ablakban egyetlen talalat sincs: elhallgatas),
  threshold, window_min, cooldown_min (ugyanarra a csoportra ennyi ideig nem tuzel ujra),
  action: triage (incidens-elemzes a modellel, zaj/snooze/topologia, ertesites a szokasos szabaly szerint)
        | direct (kozvetlen HA-ertesites, modell nelkul) | none (csak az esemeny a tarban / a Status oldalon),
  severity (direct / none eseten a kuldott / rogzitett sulyossag), note.
Kiertekeles: DETECTOR_INTERVAL_S-enkent sajat szalon; a talalatok egy sorba kerulnek, a fo ciklus donti el a szuneteltetest (cooldown) es az
akciot. Visszateszt: ugyanaz a szuro a mult napjaira (nem atfedo ablakok), a hatas mentes elott latszik.
"""
import datetime as dt
import re
import time

import aiops

MODES = ("count", "absent")
ACTIONS = ("triage", "direct", "none")
MAX_DETECTORS = 50
_ID_RX = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,48}$")
_FIELD_RX = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,39}$")
_FIELDS = {"id", "name", "enabled", "query", "group_by", "mode", "threshold", "window_min", "cooldown_min", "action", "severity", "note"}
DEFAULTS = {"enabled": True, "group_by": [], "mode": "count", "threshold": 1, "window_min": 15, "cooldown_min": 60,
            "action": "triage", "severity": "medium", "note": ""}


def check_query(q):
    """A szuro ellenorzese (NEM fut le): csak szuro, csovek nelkul. -> hibauzenet vagy None."""
    if not isinstance(q, str) or not q.strip():
        return "query must be a non-empty LogsQL filter"
    if len(q) > 300:
        return "query is at most 300 characters"
    if "|" in q:
        return "query must be a filter only (no pipes: the grouping and counting are added by the detector)"
    if "\n" in q or "\r" in q or ";" in q:
        return "query must be a single line without ';'"
    if re.search(r"(^|[\s(])_time\s*:", q):
        return "do not use _time in the query: the window setting does that"
    if q.count('"') % 2:
        return "unbalanced quotes in the query"
    if q.count("(") != q.count(")"):
        return "unbalanced parentheses in the query"
    return None


def validate(doc):
    """-> hibak listaja (ures = ervenyes)."""
    if not isinstance(doc, dict):
        return ["the detectors document must be a JSON object"]
    errs = [f"unknown top-level key {k!r}" for k in doc if k != "detectors"]
    items = doc.get("detectors", [])
    if not isinstance(items, list):
        return errs + ["detectors must be a list"]
    if len(items) > MAX_DETECTORS:
        errs.append(f"at most {MAX_DETECTORS} detectors")
    seen = set()
    for i, d in enumerate(items):
        where = f"detectors[{i}]"
        if not isinstance(d, dict):
            errs.append(f"{where}: must be an object")
            continue
        did = d.get("id")
        if isinstance(did, str):
            where = f"detector {did!r}"
        extra = sorted(set(d) - _FIELDS)
        if extra:
            errs.append(f"{where}: unknown field(s) {', '.join(extra)}")
        if not isinstance(did, str) or not _ID_RX.match(did):
            errs.append(f"{where}: id must be lowercase letters, digits, '_', '.', '-' (max 49 chars)")
            continue
        if did in seen:
            errs.append(f"{where}: duplicate id")
        seen.add(did)
        name = d.get("name", did)
        if not isinstance(name, str) or not 1 <= len(name) <= 80:
            errs.append(f"{where}: name must be 1-80 characters")
        q = check_query(d.get("query"))
        if q:
            errs.append(f"{where}: {q}")
        mode = d.get("mode", "count")
        if mode not in MODES:
            errs.append(f"{where}: mode must be one of {', '.join(MODES)}")
        if d.get("action", "triage") not in ACTIONS:
            errs.append(f"{where}: action must be one of {', '.join(ACTIONS)}")
        if d.get("severity", "medium") not in aiops.SEVERITIES:
            errs.append(f"{where}: severity must be one of {', '.join(aiops.SEVERITIES)}")
        if not isinstance(d.get("enabled", True), bool):
            errs.append(f"{where}: enabled must be true or false")
        for f, lo, hi in (("threshold", 1, 1000000), ("window_min", 5, 1440), ("cooldown_min", 5, 10080)):
            v = d.get(f, DEFAULTS[f])
            if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
                errs.append(f"{where}: {f} must be an integer between {lo} and {hi}")
        gb = d.get("group_by", [])
        if not isinstance(gb, list) or len(gb) > 3 or any(not isinstance(x, str) or not _FIELD_RX.match(x) for x in gb):
            errs.append(f"{where}: group_by must be a list of at most 3 field names")
        elif gb and mode == "absent":
            errs.append(f"{where}: group_by is not available for mode 'absent' (use one detector per source)")
        if not isinstance(d.get("note", ""), str) or len(d.get("note", "")) > 300:
            errs.append(f"{where}: note must be at most 300 characters")
    return errs


def full(d):
    """Hianyzo mezok alapertekkel."""
    out = dict(DEFAULTS)
    out.update(d)
    out.setdefault("name", out["id"])
    return out


def _esc(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def group_filter(group):
    """{"host": "a", "appname": "b"} -> host:"a" appname:"b" (a lekerdezesbe szurt ertekek escape-elve)."""
    return " ".join(f'{k}:"{_esc(v)}"' for k, v in (group or {}).items() if _FIELD_RX.match(k))


def _stats_query(d, window_filter):
    gb = d["group_by"]
    by = f"by ({', '.join(gb)}) " if gb else ""
    return f"{window_filter} ({d['query']}) | stats {by}count() as hits".strip()


def evaluate(d, now=None):
    """Elo kiertekeles: -> [{"group": {...}, "hits": n}] a tuzelo csoportokra (absent: egy elem, group {}, hits 0).
    VictoriaLogs-hiba (OSError / ValueError) kivetelkent jon: a hivo kezeli."""
    d = full(d)
    q = _stats_query(d, f"_time:{d['window_min']}m")
    rows = aiops.vl_query(q, timeout=60)
    if d["mode"] == "absent":
        total = sum(int(r.get("hits", 0) or 0) for r in rows)
        return [{"group": {}, "hits": 0}] if total == 0 else []
    out = []
    for r in rows:
        try:
            n = int(r.get("hits", 0) or 0)
        except ValueError:
            continue
        if n >= d["threshold"]:
            out.append({"group": {k: str(r.get(k, "")) for k in d["group_by"]}, "hits": n})
    out.sort(key=lambda x: -x["hits"])
    return out[:20]


def evidence_rows(d, group, t_from, t_to, limit=8):
    """A tuzeles mogotti sorok (a csoportra szukitve): [{host, ident, msg, hits}]. Az 'absent' detektorra nincs (ures lista)."""
    d = full(d)
    if d["mode"] == "absent":
        return []
    gf = group_filter(group)
    q = (f"_time:[{aiops.iso(t_from)}, {aiops.iso(t_to)}] ({d['query']}) {gf} | collapse_nums | "
         f"stats by (host, appname, _HOSTNAME, SYSLOG_IDENTIFIER, _msg) count() as hits | sort by (hits desc) | limit {int(limit)}")
    out = []
    for r in aiops.vl_query(q, timeout=60):
        try:
            n = int(r.get("hits", 0) or 0)
        except ValueError:
            n = 0
        out.append({"host": r.get("host") or r.get("_HOSTNAME") or "", "ident": r.get("appname") or r.get("SYSLOG_IDENTIFIER") or "",
                    "msg": str(r.get("_msg", "")), "hits": n})
    return out


def run_once(now=None):
    """Az osszes engedelyezett detektor kiertekelese; a talalatok a fo ciklus soraba (aiops.DETECTOR_HITS) kerulnek.
    Egy detektor hibaja (pl. ervenytelen szuro) csak az o allapotaban latszik, a tobbit nem erinti."""
    now = now or aiops.utcnow()
    for d in list(aiops.DETECTORS):
        if not d.get("enabled", True):
            continue
        st = aiops.DETECTOR_STATUS.setdefault(d["id"], {})
        try:
            hits = evaluate(d, now)
            st.update(last_eval=aiops.iso(now), last_hits=len(hits), error="")
            for h in hits:
                try:
                    aiops.DETECTOR_HITS.put_nowait({"detector": d, "group": h["group"], "hits": h["hits"]})
                except Exception:  # noqa: BLE001 - tele a sor: a talalat a kovetkezo korben ujra jon
                    break
        except (OSError, ValueError) as e:
            st.update(last_eval=aiops.iso(now), error=f"{type(e).__name__}: {e}"[:200])
            aiops.log(f"detektor {d['id']}: kiertekeles sikertelen: {e}", key=f"det_{d['id']}")


def run_loop():
    """A sajat szal ciklusa (a service_loop inditja)."""
    while True:
        try:
            if aiops.CFG["DETECTOR_MODE"] == "on":
                run_once()
        except Exception as e:  # noqa: BLE001
            aiops.log(f"detektor-ciklus hiba: {type(e).__name__}: {e}", key="det_loop")
        time.sleep(max(30, aiops.CFG["DETECTOR_INTERVAL_S"]))


def describe(d, group, hits):
    """A riasztas szovege (az incidens / ertesites bemenete)."""
    d = full(d)
    g = ", ".join(f"{k}={v}" for k, v in (group or {}).items())
    if d["mode"] == "absent":
        return f"[DETECTOR] {d['name']}: no matching log lines at all in the last {d['window_min']} min (silence)"
    return f"[DETECTOR] {d['name']}: {hits} matching lines in the last {d['window_min']} min (threshold {d['threshold']})" + (f" for {g}" if g else "")


def backtest(d, hours, now=None):
    """A detektor hatasa a mult `hours` orajara (nem atfedo `window_min` perces vedrek; az elo kiertekeles csuszo ablak, ez kozelito).
    -> {"hours", "window_min", "events": [{time, group, hits, fires}], "firings": n, "total": n, "samples": [{msg, hits}], "buckets"}"""
    d = full(d)
    err = check_query(d["query"])
    if err:
        raise ValueError(err)
    now = now or aiops.utcnow()
    t_to = now
    t_from = now - dt.timedelta(hours=hours)
    step = f"{d['window_min']}m"
    step_s = d["window_min"] * 60
    res = aiops.vl_stats_range(_stats_query(d, ""), t_from, t_to, step, timeout=90)
    # (csoport-kulcs) -> {bucket_ts: hits}
    series = {}
    for s in res:
        key = tuple(str(s["metric"].get(k, "")) for k in d["group_by"])
        for ts, v in s["values"]:
            series.setdefault(key, {})[int(ts)] = series.get(key, {}).get(int(ts), 0) + int(float(v))
    first_ts = int(t_from.timestamp()) // step_s * step_s
    last_ts = int(t_to.timestamp()) // step_s * step_s
    all_buckets = list(range(first_ts, last_ts, step_s))  # a folyamatban levo (utolso) vedrot kihagyjuk
    cool = d["cooldown_min"] * 60
    events, total = [], 0
    if d["mode"] == "absent":
        have = {ts for s in series.values() for ts in s}
        total = sum(s_v for s in series.values() for s_v in s.values())
        last_fire = None
        first_data = min(have) if have else None   # az elso adatot megelozo vedrek nem 'elhallgatas' (akkor meg nem volt mit figyelni)
        for ts in all_buckets:
            if ts in have or first_data is None or ts < first_data:
                continue
            fires = last_fire is None or ts - last_fire >= cool
            if fires:
                last_fire = ts
            events.append({"time": aiops.iso(dt.datetime.fromtimestamp(ts, dt.timezone.utc)), "group": {}, "hits": 0, "fires": fires})
        if total == 0 and not have:
            events = []  # ha az egesz idoszakban semmi sem egyezik, az nem 'elhallgatas', hanem rossz szuro: az osszefoglalo jelzi
    else:
        last_fire = {}
        for key, pts in series.items():
            total += sum(pts.values())
            group = dict(zip(d["group_by"], key))
            for ts in sorted(pts):
                if ts >= last_ts or pts[ts] < d["threshold"]:
                    continue
                fires = key not in last_fire or ts - last_fire[key] >= cool
                if fires:
                    last_fire[key] = ts
                events.append({"time": aiops.iso(dt.datetime.fromtimestamp(ts, dt.timezone.utc)), "group": group, "hits": pts[ts], "fires": fires})
        events.sort(key=lambda e: e["time"])
    samples = []
    try:
        for r in aiops.vl_query(f"_time:{int(hours)}h ({d['query']}) | collapse_nums | stats by (_msg) count() as hits | sort by (hits desc) | limit 5", timeout=60):
            samples.append({"msg": aiops.cut(str(r.get("_msg", "")), 240), "hits": int(r.get("hits", 0) or 0)})
    except (OSError, ValueError):
        pass
    return {"hours": hours, "window_min": d["window_min"], "mode": d["mode"], "buckets": len(all_buckets), "total": total,
            "firings": sum(1 for e in events if e["fires"]), "events": events[-60:], "events_total": len(events), "samples": samples,
            "no_match": (d["mode"] == "count" and total == 0) or (d["mode"] == "absent" and not any(series.values()))}
