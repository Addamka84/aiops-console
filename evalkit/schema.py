"""Esemeny-sema es JSONL I/O.

Egy esemeny (egy sor a JSONL-ben):
  ts        unix ido (masodperc, float)
  source    a monitoring eszkoz kodja (pl. dynatrace, logicmonitor, solarwinds, vrops)
  host      az erintett entitas neve (a topologia eszkoz-azonositoja vagy aliasa)
  ident     a riasztas osztalya / azonositoja (a zajlista "host | ident | uzenet" szovegenek a kozepso resze)
  level     debug | info | warning | error | critical
  msg       az esemeny szovege
  label     (opcionalis, ismert igazsag) noise = veszteseg nelkul elnyelheto | neutral | must_keep = SOHA nem nyelheto el
  incident  (opcionalis, ismert igazsag) az incidens azonositoja, amelyhez az esemeny tartozik
Az ismert igazsag nelkuli adat (valos export) is betoltheto: ilyenkor csak a label/incidens-fuggetlen mutatok szamolhatok.
"""
import json

LABELS = (None, "noise", "neutral", "must_keep")
LEVELS = ("debug", "info", "warning", "error", "critical")
REQUIRED = ("ts", "source", "host", "ident", "level", "msg")


def text(e):
    """A zajlista / ismert-ugy szabalyok altal latott szoveg (ugyanaz, mint az eles osztalyozasnal)."""
    return f"{e['host']} | {e['ident']} | {e['msg']}"


def problems(e):
    errs = [f"missing field {k!r}" for k in REQUIRED if k not in e]
    if "level" in e and e["level"] not in LEVELS:
        errs.append(f"bad level {e['level']!r}")
    if "label" in e and e["label"] not in LABELS:
        errs.append(f"bad label {e['label']!r}")
    if "ts" in e and not isinstance(e["ts"], (int, float)):
        errs.append("ts must be a number")
    return errs


def dump(events, path):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n")


def load(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            e = json.loads(line)
            errs = problems(e)
            if errs:
                raise ValueError(f"{path}:{n}: {'; '.join(errs)}")
            e.setdefault("label", None)
            e.setdefault("incident", None)
            out.append(e)
    return out
