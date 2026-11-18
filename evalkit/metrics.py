"""KPI-k: zajszures (biztonsaggal), sablon-tomorites, korrelacio (az ismert igazsaggal szemben), teljesitmeny, regresszios kapu.

A legfontosabb mutato a BIZTONSAG: hany `must_keep` esemenyt nyelt volna el a szabalyrendszer (cel: 0), konfidencia-felso korlattal.
A zajcsokkenes %-a onmagaban semmit nem bizonyit, ha kritikus esemenyek is elvesznek.
"""
import math
import re
import time
from collections import Counter, defaultdict

from . import _env  # noqa: F401
import aiops  # noqa: E402
import correlation  # noqa: E402
from . import schema  # noqa: E402
from .schema import text  # noqa: E402

SUPPRESSED = ("noise", "snooze", "known")
_NUM = re.compile(r"\d+")


def wilson_upper(k, n, z=1.96):
    """A k/n arany 95%-os Wilson-felso hatara (0 talalatnal is ertelmes: 0/100 -> ~3.7%). n=0 -> None."""
    if n <= 0:
        return None
    p = k / n
    return (p + z * z / (2 * n) + z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / (1 + z * z / n)


def load_known(path_or_doc):
    import json
    doc = path_or_doc if isinstance(path_or_doc, dict) else json.load(open(path_or_doc, encoding="utf-8-sig"))
    return aiops.Known(data=doc)


def rule_name(known, kind, what):
    if kind == "noise":
        return "noise: " + known.noise[what].pattern
    if kind == "snooze":
        return "snooze: " + str(what.get("id"))
    return "known: " + str(what.get("id")) if what else kind


def classify(events, known):
    """-> [(kind, rule_name|None)] eventenkent (az eles Known.classify_idx-szel, ugyanazon a szovegen)."""
    out = []
    for e in events:
        kind, what = known.classify_idx(text(e))
        out.append((kind, rule_name(known, kind, what) if kind != "keep" else None))
    return out


def templates(events):
    """Sablonok szama (a szamjegyek <N>-re vonva): hany kulonbozo uzenet-forma van."""
    c = Counter(e["ident"] + "|" + _NUM.sub("<N>", e["msg"]) for e in events)
    top = c.most_common()
    acc, cover80 = 0, 0
    for i, (_, n) in enumerate(top, 1):
        acc += n
        if acc >= 0.8 * len(events):
            cover80 = i
            break
    return {"templates": len(c), "events_per_template": round(len(events) / max(1, len(c)), 1), "templates_covering_80pct": cover80}


def suppression_report(events, known, cls=None):
    cls = cls or classify(events, known)
    n = len(events)
    kinds = Counter(k for k, _ in cls)
    suppressed = sum(kinds[k] for k in SUPPRESSED)
    rules = Counter(r for _, r in cls if r)
    must = [i for i, e in enumerate(events) if e["label"] == "must_keep"]
    noise = [i for i, e in enumerate(events) if e["label"] == "noise"]
    missed = [i for i in must if cls[i][0] in SUPPRESSED]
    caught = [i for i in noise if cls[i][0] in SUPPRESSED]
    wrong = sum(1 for i, e in enumerate(events) if cls[i][0] in SUPPRESSED and e["label"] == "must_keep")
    labeled_suppressed = sum(1 for i, e in enumerate(events) if cls[i][0] in SUPPRESSED and e["label"] in ("noise", "must_keep", "neutral"))
    offenders = Counter(cls[i][1] for i in missed)
    return {
        "events": n, "by_disposition": dict(kinds), "suppressed": suppressed, "suppressed_pct": round(100 * suppressed / n, 2) if n else 0.0,
        "kept": n - suppressed,
        "must_keep": len(must), "must_keep_missed": len(missed),
        "must_keep_missed_rate_upper95": wilson_upper(len(missed), len(must)),
        "noise_labeled": len(noise), "noise_caught": len(caught), "noise_recall_pct": round(100 * len(caught) / len(noise), 2) if noise else None,
        "suppression_precision_pct": round(100 * (labeled_suppressed - wrong) / labeled_suppressed, 2) if labeled_suppressed else None,
        "top_rules": rules.most_common(8), "offending_rules": offenders.most_common(),
        "missed_samples": [text(events[i])[:140] for i in missed[:5]],
        "gate_pass": len(missed) == 0,
    }


def _pairs(c):
    return sum(v * (v - 1) // 2 for v in c.values())


def dedup(events, kept_idx, topo, cooldown_s=1800):
    """Az elo folyamat ismetles-szurese: ugyanaz a (host, ident, sablon) kulcs cooldown_s-en belul nem lesz ujra elem (a termelesi 30 perces szuneteltetes
    kozelitese). Csak a topologiabol azonosithato eszkozu esemeny lesz elem. -> (elemek ts szerint, eldobott ismetlesek, topologiahoz nem rendelheto)."""
    items, last, dropped, unresolved = [], {}, [], 0
    for i in kept_idx:
        e = events[i]
        key = (e["host"], e["ident"], _NUM.sub("<N>", e["msg"]))
        if e["ts"] - last.get(key, -1e18) < cooldown_s:
            dropped.append(i)          # egy azonos kulcsu, korabbi elem mar megjelent: ez ismetlesnek szamit
            continue
        last[key] = e["ts"]
        cis = correlation.resolve_cis(topo, [e["host"], e["msg"]])
        if not cis:
            unresolved += 1
            continue
        items.append({"idx": i, "ts": e["ts"], "cis": cis})
    return items, dropped, unresolved


def stream(items, topo, settle=90, window_s=600, max_pending=1500):
    """A termelesi 'leulepedes' logikaja (alert-replay.py-val azonos): az elemek varakozo halmazban gyulnek, es egy csoport akkor zarul incidensse, ha
    a legujabb eleme settle masodperce nem frissult (vagy a legregebbi 4*settle ideje var). A korrelator csak a varakozo halmazon fut.
    max_pending folott az uj elemek sajat incidensbe kerulnek (a korrelator paronkenti, O(n^2)): ennek szama maga is eredmeny. -> (incidensek, max_pending_seen, overflow)"""
    pending, done, biggest, overflow = [], [], 0, 0

    def flush(now, force=False):
        nonlocal pending
        if not pending or (not force and now - min(it["ts"] for it in pending) < settle):
            return
        keep, gone = [], set()
        for g in correlation.cluster(topo, pending, window_s=window_s):
            newest, oldest = max(pending[i]["ts"] for i in g), min(pending[i]["ts"] for i in g)
            if force or now - newest >= settle or now - oldest >= 4 * settle:
                done.append([pending[i] for i in g])
                gone.update(g)
        pending = [it for i, it in enumerate(pending) if i not in gone]

    for it in items:
        flush(it["ts"])
        if len(pending) >= max_pending:
            overflow += 1
            done.append([it])
            continue
        pending.append(it)
        biggest = max(biggest, len(pending))
    flush(1e18, force=True)
    return done, biggest, overflow


def correlation_report(events, topo, kept_idx=None, window_s=600, settle=90, cooldown_s=1800, max_pending=1500, min_level="debug"):
    """A megtartott esemenyek teljes termelesi-szeru feldolgozasa (ismetles-szures -> leulepedes -> korrelacio) az ISMERT IGAZSAGGAL szemben.
    Biztonsag incidens-szinten: minden valos incidensnek maradnia kell legalabb egy elemenek (incident_coverage).
    min_level: csak ennel sulyosabb (vagy egyenlo) esemenyek lesznek elemek (a tobbi 'attekintesre' marad, nem riaszt)."""
    kept_idx = list(range(len(events))) if kept_idx is None else kept_idx
    rank = schema.LEVELS.index(min_level)
    kept_idx = [i for i in kept_idx if schema.LEVELS.index(events[i]["level"]) >= rank]
    items, dropped, unresolved = dedup(events, kept_idx, topo, cooldown_s)
    t0 = time.perf_counter()
    clusters, biggest, overflow = stream(items, topo, settle, window_s, max_pending)
    secs = time.perf_counter() - t0
    pred = {it["idx"]: n for n, g in enumerate(clusters) for it in g}
    truth = {i: events[i]["incident"] for i in pred if events[i]["incident"]}
    all_truth = {e["incident"] for e in events if e["incident"]}
    # lefedettseg INFORMACIOS szinten: az incidens riasztasa megjelent (sajat elemkent, vagy egy azonos kulcsu korabbi elem mellett az ismetles-szuro mogott).
    # A 'repeat_only' azokat az incidenseket szamolja, amelyeknek NINCS sajat eleme, csak egy korabbi azonos riasztas takarja: ez a cooldown valodi kockazata
    # (egy uj, onallo incidens 30 percen belul ugyanazzal a szoveggel ugyanazon az eszkozon az elozohoz vonodik).
    own = {events[i]["incident"] for i in pred if events[i]["incident"]}
    repeated = {events[i]["incident"] for i in dropped if events[i]["incident"]}
    covered = own | repeated
    cell = Counter((pred[i], t) for i, t in truth.items())
    pc, tc = Counter(pred[i] for i in truth), Counter(truth.values())
    tp = _pairs(cell)
    prec = tp / _pairs(pc) if _pairs(pc) else None
    rec = tp / _pairs(tc) if _pairs(tc) else None
    n_total = len(events)
    return {"kept_events": len(kept_idx), "cooldown_dropped": len(dropped), "items": len(items), "unresolved_events": unresolved, "clusters": len(clusters),
            "max_pending": biggest, "overflow_items": overflow,
            "compression": round(len(items) / max(1, len(clusters)), 2), "end_to_end_reduction": round(n_total / max(1, len(clusters)), 1),
            "truth_incidents": len(all_truth), "incidents_covered": len(covered), "incident_coverage_gate": covered == all_truth,
            "incidents_repeat_only": len(repeated - own),
            "pair_precision": None if prec is None else round(prec, 4), "pair_recall": None if rec is None else round(rec, 4),
            "fragmentation": round(sum(len({pred[i] for i, t in truth.items() if t == inc}) for inc in tc) / len(tc), 2) if tc else None,
            "secs": round(secs, 3), "_clusters": clusters, "_pred": pred}


def root_accuracy(events, topo, corr, truth_meta):
    """Incidensenkent: a legnagyobb reszet tartalmazo jelolt-klaszter gyoker-javaslata megegyezik-e a valos gyokerrel (csak viharokra, ahol van gyoker)."""
    ok = total = 0
    by_inc = defaultdict(list)
    for i, c in corr["_pred"].items():
        if events[i]["incident"]:
            by_inc[events[i]["incident"]].append(c)
    for inc, meta in truth_meta.items():
        if not meta["kind"].startswith("storm") or inc not in by_inc:
            continue
        best = Counter(by_inc[inc]).most_common(1)[0][0]
        info = correlation.analyze(topo, corr["_clusters"][best])
        total += 1
        ok += info["root"] == meta["root"]
    return {"storms": total, "root_correct": ok, "root_accuracy_pct": round(100 * ok / total, 1) if total else None}


def throughput(events, known, repeat=1):
    t0 = time.perf_counter()
    for _ in range(repeat):
        classify(events, known)
    secs = time.perf_counter() - t0
    n = len(events) * repeat
    return {"events": n, "secs": round(secs, 3), "events_per_sec": int(n / secs) if secs else None}


def correlator_scaling(topo, sizes=(100, 200, 400), seed=7, reference_max=1600, cis_per_item=1):
    """A korrelator ideje egyetlen ablakban osszegyult N esemenyre (eseményvihar): ez mutatja, hol torik meg a skalazas. A regi, paronkenti referenciat
    (cluster_pairwise) reference_max eseményig is megmeri (afelett negyzetes ideje miatt kihagyja), es ellenorzi, hogy az eredmeny azonos."""
    import random
    rng = random.Random(seed)
    ids = sorted(topo.assets)
    out = []
    for n in sizes:
        # cis_per_item > 1: a legrosszabb eset (minden elem szinte egyedi eszkozhalmaz: a halmazok szama ~ az elemek szama)
        items = [{"ts": 1000 + rng.random() * 100, "cis": [rng.choice(ids) for _ in range(cis_per_item)]} for _ in range(n)]
        t0 = time.perf_counter()
        fast = correlation.cluster(topo, items, window_s=600)
        row = {"events_in_window": n, "secs": round(time.perf_counter() - t0, 3), "reference_secs": None, "same_result": None}
        if n <= reference_max:
            t0 = time.perf_counter()
            ref = correlation.cluster_pairwise(topo, items, window_s=600)
            row["reference_secs"] = round(time.perf_counter() - t0, 3)
            row["same_result"] = ref == fast
        out.append(row)
    return out


def compare(events, base_known, cand_known):
    """Regresszios kapu egy valtoztatasra (pl. egy uj zaj-regex): mit nyel el az uj szabalyrendszer, amit a regi nem; elnyel-e `must_keep` esemenyt."""
    a, b = classify(events, base_known), classify(events, cand_known)
    new = [i for i in range(len(events)) if a[i][0] == "keep" and b[i][0] in SUPPRESSED]
    freed = [i for i in range(len(events)) if a[i][0] in SUPPRESSED and b[i][0] == "keep"]
    new_must = [i for i in new if events[i]["label"] == "must_keep"]
    return {"newly_suppressed": len(new), "newly_kept": len(freed), "newly_suppressed_must_keep": len(new_must),
            "newly_suppressed_by_label": dict(Counter(events[i]["label"] for i in new)),
            "offending_rules": Counter(b[i][1] for i in new_must).most_common(),
            "samples": [text(events[i])[:140] for i in new_must[:5]], "gate_pass": not new_must,
            "base": suppression_report(events, base_known, a)["suppressed_pct"], "candidate": suppression_report(events, cand_known, b)["suppressed_pct"]}
