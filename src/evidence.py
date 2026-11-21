"""Bizonyitek a zajszabaly-javaslatok melle (determinisztikus, nem modell): mit csendesitene el a szabaly, es mikor kell kulonosen figyelni.

- hatas: a tarolt minta-alapvonalon (7 napos naplo sablonjai) es a nyitott novelty-leleteken lefuttatva: hany sablon / talalat / host,
  szintek, a lefedett nyitott leletek, nehany (kiszurt) peldasor, es a mar meglevo szabalyok, amelyek ugyanazt is lefedik.
- figyelem-jelzes: biztonsagi / rendelkezesre allasi kulcsszavak (belepes, tiltas, OOM, SMART, parositas, halozat le-fel...) a szabaly
  szovegeben vagy a lefedett sorokban. Ez NEM dont: csak azt jelzi, hogy a javaslatot emberi szemmel erdemes atnezni.
A modell (Supervisor) szoveges indoklasa nem szerepel benne: az a biztonsagi tartalmat tevesen "rutinnak" nevezheti."""
import re

ATTENTION_RX = [re.compile(x, re.I) for x in (
    r"preauth", r"authenticat\w*", r"auth(?:entication)? fail\w*", r"denied", r"refused", r"failed password", r"invalid user",
    r"permit[ _-]?join", r"pairing", r"allowing new devices", r"network (?:closed|opened)", r"stack status", r"out of memory",
    r"\boom\b", r"\bkilled\b", r"panic", r"segfault|segmentation", r"\bsmart\b", r"i/o error", r"corrupt\w*", r"degraded",
    r"unreachable", r"\bexpired\b", r"certificate", r"unauthori[sz]ed|forbidden", r"brute", r"call trace", r"read-only file system",
    r"no space left")]
MAX_EXAMPLES = 5
IMPORTANT = {"emerg", "alert", "crit", "critical", "err", "error"}


def attention(texts, limit=6):
    """-> a talalt kulcsszavak (egyedi, sorrendben). texts: a szabaly regexe(i) es/vagy lefedett sorok."""
    out = []
    for t in texts:
        for rx in ATTENTION_RX:
            m = rx.search(str(t))
            if m:
                w = m.group(0).lower()[:30]
                if w not in out:
                    out.append(w)
                    if len(out) >= limit:
                        return out
    return out


def _text(r):
    return f"{r['host']} | {r['ident']} | {r['tmpl']}"


def noise_evidence(new_rules, patterns, findings, existing_rules=(), redact=lambda s: s):
    """new_rules: az uj zaj-regexek; patterns: a minta-alapvonal sorai; findings: nyitott leletek (id, host, ident, level, tmpl);
    existing_rules: a meglevo zaj-regexek. -> [szabalyonkent egy dict]"""
    existing = []
    for x in existing_rules:
        try:
            existing.append((x, re.compile(x)))
        except re.error:
            continue
    out = []
    for rule in new_rules:
        try:
            rx = re.compile(rule)
        except re.error as e:
            out.append({"rule": rule, "error": f"invalid regex: {e}"})
            continue
        pats = [r for r in patterns if rx.search(_text(r))]
        covered = [f for f in findings if rx.search(_text(f))]
        hosts = {}
        levels = {}
        hits = 0
        for r in pats:
            hosts[r["host"]] = hosts.get(r["host"], 0) + int(r.get("total", 0) or 0)
            levels[r["level"]] = levels.get(r["level"], 0) + 1
            hits += int(r.get("total", 0) or 0)
        sample = [_text(r) for r in (pats[:60] + covered[:20])]
        similar = []
        for x, erx in existing:
            if any(erx.search(s) for s in sample):
                similar.append(x[:140])
                if len(similar) >= 3:
                    break
        out.append({
            "rule": rule,
            "templates": len(pats), "hits": hits, "hosts": len(hosts),
            "top_hosts": [{"host": h, "hits": n} for h, n in sorted(hosts.items(), key=lambda kv: -kv[1])[:3]],
            "levels": levels,
            "important_templates": sum(n for lv, n in levels.items() if lv in IMPORTANT),
            "covered_open": len(covered), "covered_ids": [f["id"] for f in covered][:200],
            "examples": [{"host": f["host"], "ident": f["ident"], "level": f["level"], "text": redact(str(f["tmpl"]))[:160]}
                         for f in (covered[:MAX_EXAMPLES] if covered else pats[:MAX_EXAMPLES])],
            "attention": attention([rule] + sample),
            "similar_rules": similar,
        })
    return out
