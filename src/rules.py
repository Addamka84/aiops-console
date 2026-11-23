"""Riasztasi szabalyok (vmalert): a 'rules' konfig-dokumentum, ellenorzese es a vmalert szabaly-fajlja.

Az eszleles a vmalert + Alertmanager dolga; az aiops-console a szabalyokat kezeli (javaslat -> jovahagyas -> revizio -> naplo) es
kirendereli a vmalert szabaly-fajlt. Ez a modul CSAK ellenoriz es renderel: nem ir fajlt, nem hivja a vmalertet (az a kovetkezo lepes).
A 'detectors' konfig (sajat motor) ettol fuggetlen, az atallas lepesenkent tortenik.

Dokumentum: {"rules": [ {...}, ... ]}. Egy szabaly:
  id (az alertname, pl. ContainerLogFlood), enabled (alap: igaz), kind, interval_min (a csoport kiertekelesi gyakorisaga), for_min,
  keep_firing_min, severity (info|low|medium|high|critical), notify (triage = az aiops elemzi | direct = kozvetlen HA-ertesites | none = csak naplo),
  summary (a riasztas szovege; csak {{ $value }} es {{ $labels.<mezo> }} sablon), note.
  kind=count   : query (LogsQL SZURO, csovek nelkul), group_by, threshold (>= talalat), window_min
  kind=silence : query, group_by (kotelezo), window_min (ennyi ideje nem jott sor), history_h (ennyi orara visszanezve latott forrasok), min_total
  kind=absent  : query, window_min (az ablakban egyetlen talalat sincs)
  kind=raw     : expr (teljes LogsQL, 'stats' csovel), evidence (opcionalis szuro a triazs bizonyitekahoz)
A renderelt fajl determinisztikus (ugyanabbol a dokumentumbol ugyanaz a szoveg); minden szoveg JSON-idezettel kerul a YAML-ba (nincs injekcio).
"""
import json
import re

import aiops
import detectors

KINDS = ("count", "silence", "absent", "raw")
NOTIFY = ("triage", "direct", "none")
MAX_RULES = 100
FILE_NAME = "aiops-console.yml"
_ID_RX = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")
_LABEL_RX = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,39}$")
_TPL_RX = re.compile(r"\{\{(.*?)\}\}")
_TPL_OK = re.compile(r"^\s*(\$value|\$labels\.[A-Za-z_][A-Za-z0-9_]*)\s*$")
COMMON = {"id", "enabled", "kind", "interval_min", "for_min", "keep_firing_min", "severity", "notify", "summary", "note"}
KIND_FIELDS = {"count": {"query", "group_by", "threshold", "window_min"},
               "silence": {"query", "group_by", "window_min", "history_h", "min_total"},
               "absent": {"query", "window_min"},
               "raw": {"expr", "evidence"}}
DEFAULTS = {"enabled": True, "interval_min": 1, "for_min": 0, "keep_firing_min": 0, "severity": "medium", "notify": "triage", "summary": "",
            "note": "", "group_by": [], "threshold": 1, "window_min": 5, "history_h": 24, "min_total": 20, "evidence": ""}
INT_RANGES = {"interval_min": (1, 60), "for_min": (0, 1440), "keep_firing_min": (0, 10080), "threshold": (1, 1000000),
              "window_min": (1, 1440), "history_h": (1, 168), "min_total": (0, 1000000)}


def _bare(s):
    """A "..." szovegek kivagva (a szerkezetet a maradekon nezzuk)."""
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', s)


def check_summary(s):
    """-> hibauzenet vagy None. Csak {{ $value }} es {{ $labels.<mezo> }}: a vmalert sablon mas fuggvenyei (pl. query) tiltottak."""
    if not isinstance(s, str) or len(s) > 300 or "\n" in s or "\r" in s:
        return "summary must be a single line of at most 300 characters"
    for inner in _TPL_RX.findall(s):
        if not _TPL_OK.match(inner):
            return "summary may only use {{ $value }} and {{ $labels.<field> }}"
    rest = _TPL_RX.sub("", s)
    if "{{" in rest or "}}" in rest:
        return "unbalanced {{ }} in the summary"
    return None


def check_expr(e):
    """Nyers LogsQL kifejezes: egy sor, kiegyensulyozott idezojel/zarojel, tartalmaz 'stats' csovet. NEM fut le. -> hibauzenet vagy None."""
    if not isinstance(e, str) or not e.strip():
        return "expr must be a non-empty LogsQL expression"
    if len(e) > 1000:
        return "expr is at most 1000 characters"
    if "\n" in e or "\r" in e:
        return "expr must be a single line"
    bare = _bare(e)
    if '"' in bare.replace('""', ""):
        return "unbalanced quotes in expr"
    if "'" in bare or "`" in bare:
        return "single quotes and backticks are not allowed outside double-quoted text"
    if ";" in bare:
        return "expr must not contain ';' outside quotes"
    if bare.count("(") != bare.count(")"):
        return "unbalanced parentheses in expr"
    if not re.search(r"\|\s*stats\b", bare):
        return "expr needs a stats pipe (vmalert fires for every result row)"
    return None


def validate(doc):
    """-> hibak listaja (ures = ervenyes)."""
    if not isinstance(doc, dict):
        return ["the rules document must be a JSON object"]
    errs = [f"unknown top-level key {k!r}" for k in doc if k != "rules" and not str(k).startswith("_")]
    items = doc.get("rules", [])
    if not isinstance(items, list):
        return errs + ["rules must be a list"]
    if len(items) > MAX_RULES:
        errs.append(f"at most {MAX_RULES} rules")
    seen = set()
    for i, r in enumerate(items):
        where = f"rules[{i}]"
        if not isinstance(r, dict):
            errs.append(f"{where}: must be an object")
            continue
        rid = r.get("id")
        if isinstance(rid, str):
            where = f"rule {rid!r}"
        if not isinstance(rid, str) or not _ID_RX.match(rid):
            errs.append(f"{where}: id must be letters and digits, starting with a letter (max 64 chars; it is the alertname)")
            continue
        if rid.lower() in seen:
            errs.append(f"{where}: duplicate id")
        seen.add(rid.lower())
        kind = r.get("kind")
        if kind not in KINDS:
            errs.append(f"{where}: kind must be one of {', '.join(KINDS)}")
            continue
        extra = sorted(set(r) - COMMON - KIND_FIELDS[kind])
        if extra:
            errs.append(f"{where}: field(s) not valid for kind {kind}: {', '.join(extra)}")
        if r.get("severity", "medium") not in aiops.SEVERITIES:
            errs.append(f"{where}: severity must be one of {', '.join(aiops.SEVERITIES)}")
        if r.get("notify", "triage") not in NOTIFY:
            errs.append(f"{where}: notify must be one of {', '.join(NOTIFY)}")
        if not isinstance(r.get("enabled", True), bool):
            errs.append(f"{where}: enabled must be true or false")
        bad_int = set()
        for f, (lo, hi) in INT_RANGES.items():
            if f in r:
                v = r[f]
                if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
                    errs.append(f"{where}: {f} must be an integer between {lo} and {hi}")
                    bad_int.add(f)
        if "summary" in r:
            m = check_summary(r["summary"])
            if m:
                errs.append(f"{where}: {m}")
        if not isinstance(r.get("note", ""), str) or len(r.get("note", "")) > 300:
            errs.append(f"{where}: note must be at most 300 characters")
        if kind == "raw":
            m = check_expr(r.get("expr"))
            if m:
                errs.append(f"{where}: {m}")
            if r.get("evidence"):
                m = detectors.check_query(r["evidence"])
                if m:
                    errs.append(f"{where}: evidence: {m}")
            continue
        m = detectors.check_query(r.get("query"))
        if m:
            errs.append(f"{where}: {m}")
        gb = r.get("group_by", [])
        if "group_by" in KIND_FIELDS[kind]:
            if not isinstance(gb, list) or len(gb) > 3 or any(not isinstance(x, str) or not _LABEL_RX.match(x) for x in gb):
                errs.append(f"{where}: group_by must be a list of at most 3 field names (letters, digits, '_')")
            elif kind == "silence" and not gb:
                errs.append(f"{where}: kind silence needs at least one group_by field (the sources it watches)")
        w, iv, hh = (r.get(k, DEFAULTS[k]) for k in ("window_min", "interval_min", "history_h"))
        if not bad_int & {"window_min", "interval_min"} and w < iv:
            errs.append(f"{where}: window_min must not be shorter than interval_min (the windows would leave gaps)")
        if kind == "silence" and not bad_int & {"window_min", "history_h"} and hh * 60 <= w:
            errs.append(f"{where}: history_h must be longer than window_min")
    return errs


def full(r):
    out = dict(DEFAULTS)
    out.update(r)
    return out


def expr(r):
    """A vmalert-kifejezes (LogsQL) egy szabalyra."""
    r = full(r)
    if r["kind"] == "raw":
        return r["expr"]
    q, gb = r["query"], ", ".join(r["group_by"])
    by = f"by ({gb}) " if gb else ""
    if r["kind"] == "count":
        return f"_time:{r['window_min']}m ({q}) | stats {by}count() as hits | filter hits:>={r['threshold']}"
    if r["kind"] == "silence":
        return (f"_time:{r['history_h']}h ({q}) | stats {by}count() as total, count() if (_time:{r['window_min']}m) as recent"
                f" | filter recent:0 total:>{r['min_total']}")
    return f"_time:{r['window_min']}m ({q}) | stats count() as n | filter n:0"


def default_summary(r):
    r = full(r)
    parts = "".join(f" {g}={{{{ $labels.{g} }}}}" for g in r["group_by"] if r["kind"] != "raw")
    if r["kind"] == "count":
        return f"{r['id']}:{parts} {{{{ $value }}}} matching line(s) in {r['window_min']} min"
    if r["kind"] == "silence":
        return f"{r['id']}:{parts} no matching lines for {r['window_min']}+ min"
    if r["kind"] == "absent":
        return f"{r['id']}: no matching lines in the last {r['window_min']} min"
    return r["id"]


def _q(s):
    """YAML dupla idezojeles szoveg: a JSON-szoveg ervenyes YAML (a sablonok es a kifejezesek biztonsagosan kerulnek bele)."""
    return json.dumps(s, ensure_ascii=False)


def render(doc, rev=None):
    """-> {"files": {FILE_NAME: szoveg}, "rules": engedelyezett szabalyok szama, "disabled": letiltottak szama}. ValueError, ha a dokumentum ervenytelen."""
    errs = validate(doc)
    if errs:
        raise ValueError("; ".join(errs))
    rules = [full(r) for r in doc.get("rules", [])]
    live = [r for r in rules if r["enabled"]]
    lines = [f"# Generated by aiops-console from the 'rules' configuration{f' (revision {rev})' if rev is not None else ''}.",
             "# Manual edits are overwritten on the next approval.", "groups:"]
    if not live:
        lines = lines[:-1] + ["groups: []"]
    for iv in sorted({r["interval_min"] for r in live}):
        lines += [f"  - name: {_q(f'aiops-console-{iv}m')}", "    type: vlogs", f"    interval: {iv}m", "    rules:"]
        for r in (x for x in live if x["interval_min"] == iv):
            lines += [f"      - alert: {r['id']}", f"        expr: {_q(expr(r))}"]
            if r["for_min"]:
                lines.append(f"        for: {r['for_min']}m")
            if r["keep_firing_min"]:
                lines.append(f"        keep_firing_for: {r['keep_firing_min']}m")
            lines += ["        labels:", f"          severity: {_q(r['severity'])}"]
            if r["notify"] != "triage":
                lines.append(f"          notify: {_q(r['notify'])}")
            lines += ["        annotations:", f"          summary: {_q(r['summary'] or default_summary(r))}"]
            if r["note"]:
                lines.append(f"          description: {_q(r['note'])}")
    return {"files": {FILE_NAME: "\n".join(lines) + "\n"}, "rules": len(live), "disabled": len(rules) - len(live)}


def preview(doc, rev=None):
    """Az API-nak: hibak VAGY a renderelt fajl (sosem dob)."""
    errs = validate(doc)
    if errs:
        return {"errors": errs}
    return dict(render(doc, rev), errors=[])
