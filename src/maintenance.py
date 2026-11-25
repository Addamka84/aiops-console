"""Karbantartasi ablakok (verziozott 'maintenance' konfigkulcs): egy tervezett beavatkozas alatt (gepcsere, stack-ujratelepites,
frissites) a celpontokra - es kerésre a topologiaban toluk fuggo eszkozokre - erkezo riasztas es detektor-talalat csak naplozodik:
nem nyit incidenst, es a korrelacioba sem kerul be (2026-11-25: a logstack ujratelepitese hamis incidenseket szult).

Dokumentum: {"windows": [{"id", "targets": [eszkoz-id / nev], "start": "...Z", "end": "...Z", "include_dependents": bool, "note"}]}
Csak olvas a tobbi modulbol; az aktiv dokumentumot a runtime allitja (set_active)."""
import datetime as dt
import re
import threading

MAX_WINDOWS = 50
MAX_HOURS = 7 * 24
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
_ID_RX = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_LOCK = threading.Lock()
_ACTIVE = {"windows": []}


def parse_ts(v):
    if not isinstance(v, str):
        return None
    try:
        return dt.datetime.strptime(v, TS_FMT)
    except ValueError:
        return None


def fmt_ts(t):
    return t.strftime(TS_FMT)


def resolve_target(topo, t):
    """Egy celpont (id, nev vagy alias) -> topologiai eszkoz-id vagy None."""
    if not topo:
        return None
    s = str(t).strip()
    if s in topo.assets:
        return s
    low = s.lower()
    for aid, a in topo.assets.items():
        names = [aid, a.get("name") or ""] + list(a.get("aliases") or [])
        if any(str(n).lower() == low for n in names if n):
            return aid
    return None


def validate(doc, topo=None, now=None):
    """-> hibak listaja. A celpontoknak a topologiaban kell lenniuk, ha van topologia (kulonben a szoveges egyezes szamit)."""
    if not isinstance(doc, dict):
        return ["the document must be a JSON object"]
    errs = [f"{k}: unknown top-level key" for k in doc if k != "windows" and not str(k).startswith("_")]
    ws = doc.get("windows", [])
    if not isinstance(ws, list):
        return errs + ["windows: must be a list"]
    if len(ws) > MAX_WINDOWS:
        errs.append(f"windows: at most {MAX_WINDOWS} (remove finished ones)")
    seen = set()
    for i, w in enumerate(ws):
        p = f"windows[{i}]"
        if not isinstance(w, dict):
            errs.append(f"{p}: must be an object")
            continue
        for k in w:
            if k not in ("id", "targets", "start", "end", "include_dependents", "note"):
                errs.append(f"{p}.{k}: unknown key")
        wid = w.get("id")
        if not isinstance(wid, str) or not _ID_RX.match(wid):
            errs.append(f"{p}.id: lowercase letters, digits, '_', '.', '-' (max 64)")
        elif wid in seen:
            errs.append(f"{p}.id: duplicate {wid!r}")
        else:
            seen.add(wid)
        tg = w.get("targets")
        if not isinstance(tg, list) or not tg or not all(isinstance(x, str) and x.strip() for x in tg) or len(tg) > 20:
            errs.append(f"{p}.targets: 1-20 device ids or names")
        elif topo:
            bad = [x for x in tg if resolve_target(topo, x) is None]
            if bad:
                errs.append(f"{p}.targets: not in the topology: {', '.join(bad[:5])}")
        s, e = parse_ts(w.get("start")), parse_ts(w.get("end"))
        if s is None or e is None:
            errs.append(f"{p}: 'start' and 'end' must be UTC times like 2026-11-25T18:00:00Z")
        elif e <= s:
            errs.append(f"{p}: 'end' must be after 'start'")
        elif e - s > dt.timedelta(hours=MAX_HOURS):
            errs.append(f"{p}: a window is limited to {MAX_HOURS // 24} days")
        if "include_dependents" in w and not isinstance(w["include_dependents"], bool):
            errs.append(f"{p}.include_dependents: must be true or false")
        if "note" in w and (not isinstance(w["note"], str) or len(w["note"]) > 300):
            errs.append(f"{p}.note: a string of at most 300 characters")
    return errs


def set_active(doc):
    with _LOCK:
        _ACTIVE["windows"] = list((doc or {}).get("windows", []))


def expanded(topo, w):
    """Egy ablak celpontjai topologiai id-kent (+ a fuggok, ha include_dependents) es a fel nem oldott szoveges celpontok."""
    import correlation
    ids, texts = set(), set()
    for t in w.get("targets", []):
        aid = resolve_target(topo, t)
        if aid is None:
            texts.add(str(t).strip().lower())
            continue
        ids.add(aid)
        if w.get("include_dependents") and topo:
            ids.update(correlation.topo_down(topo, aid))
    return ids, texts


def active(now=None):
    now = now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    with _LOCK:
        ws = list(_ACTIVE["windows"])
    out = []
    for w in ws:
        s, e = parse_ts(w.get("start")), parse_ts(w.get("end"))
        if s and e and s <= now < e:
            out.append(w)
    return out


def match(topo, text, label_values=(), cis=None, now=None):
    """Egy riasztas / detektor-talalat eszkozei egy aktiv ablakba esnek-e? -> az ablak (dict) vagy None.
    cis: a mar feloldott topologiai eszkozok (ha nincs megadva, a szovegbol es a cimke-ertekekbol oldjuk fel)."""
    ws = active(now)
    if not ws:
        return None
    import correlation
    if cis is None:
        cis = correlation.resolve_cis(topo, [text] + [str(v) for v in label_values]) if topo else []
    blob = " ".join([str(text or "")] + [str(v) for v in label_values]).lower()
    for w in ws:
        ids, texts = expanded(topo, w)
        if ids & set(cis):
            return w
        if any(re.search(r"(?<![\w.-])" + re.escape(t) + r"(?![\w-])", blob) for t in texts):
            return w
    return None


def views(topo, doc, now=None):
    """A UI-nak: ablakonkent allapot (active / upcoming / ended) es a tenyleges lefedett eszkozok."""
    now = now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    out = []
    for w in (doc or {}).get("windows", []):
        s, e = parse_ts(w.get("start")), parse_ts(w.get("end"))
        state = "active" if s and e and s <= now < e else "upcoming" if s and s > now else "ended"
        ids, texts = expanded(topo, w)
        out.append(dict(w, state=state, covers=sorted(ids) + sorted(texts),
                        remaining_s=int((e - now).total_seconds()) if state == "active" else 0))
    return out
