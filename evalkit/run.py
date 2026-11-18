"""evalkit CLI.  Hasznalat (a stacks/aiops-console mappabol):
  python -m evalkit synth   --out DIR [--days 1] [--events-per-day 20000] [--storms-per-day 5] [--seed 1]
  python -m evalkit report  --data DIR --known known.json [--window 600] [--settle 90] [--cooldown 1800] [--json out.json]
  python -m evalkit compare --data DIR --base known.json --candidate known2.json
  python -m evalkit bench   --data DIR --known known.json [--sizes 100,200,400]
A kimenet angol (munkahelyi bemutatasra is szant); a kod es a megjegyzesek magyarok. Kilepesi kod: 0 = a kapu atment, 2 = a biztonsagi kapu elbukott.
"""
import argparse
import json
import os
import sys

from . import _env  # noqa: F401
import topology  # noqa: E402
from . import metrics, schema, synth  # noqa: E402


def _load(data):
    ev = schema.load(os.path.join(data, "events.jsonl"))
    topo_doc = json.load(open(os.path.join(data, "topology.json"), encoding="utf-8"))
    truth_p = os.path.join(data, "truth.json")
    truth = json.load(open(truth_p, encoding="utf-8")) if os.path.exists(truth_p) else {}
    return ev, topology.Topology(topo_doc), truth


def cmd_synth(a):
    os.makedirs(a.out, exist_ok=True)
    ev, doc, truth = synth.generate(a.seed, a.days, a.events_per_day, a.storms_per_day, a.singles_per_day)
    schema.dump(ev, os.path.join(a.out, "events.jsonl"))
    json.dump(doc, open(os.path.join(a.out, "topology.json"), "w", encoding="utf-8"), indent=1)
    json.dump(truth, open(os.path.join(a.out, "truth.json"), "w", encoding="utf-8"), indent=1)
    labels = {}
    for e in ev:
        labels[e["label"]] = labels.get(e["label"], 0) + 1
    print(f"wrote {len(ev)} synthetic events ({labels}), {len(doc['assets'])} assets, {len(truth)} ground-truth incidents -> {a.out}")
    return 0


def pct(x):
    return "n/a" if x is None else f"{100 * x:.2f}%"


def cmd_report(a):
    ev, topo, truth = _load(a.data)
    known = metrics.load_known(a.known)
    cls = metrics.classify(ev, known)
    sup = metrics.suppression_report(ev, known, cls)
    kept = [i for i, (k, _) in enumerate(cls) if k not in metrics.SUPPRESSED]
    tpl = metrics.templates(ev)
    cor = metrics.correlation_report(ev, topo, kept, a.window, a.settle, a.cooldown)
    root = metrics.root_accuracy(ev, topo, cor, truth) if truth else {}
    tp = metrics.throughput(ev, known)
    print(f"== Events: {sup['events']:,}  |  distinct templates: {tpl['templates']} ({tpl['events_per_template']} events/template; {tpl['templates_covering_80pct']} templates cover 80%)")
    print(f"== Noise handling: suppressed {sup['suppressed']:,} ({sup['suppressed_pct']}%), kept {sup['kept']:,}   dispositions: {sup['by_disposition']}")
    print(f"   noise recall {sup['noise_recall_pct']}% | suppression precision {sup['suppression_precision_pct']}% (labeled events)")
    print(f"== SAFETY: must_keep events {sup['must_keep']:,}, suppressed by mistake: {sup['must_keep_missed']}  "
          f"(95% upper bound of the miss rate: {pct(sup['must_keep_missed_rate_upper95'])})  ->  GATE {'PASS' if sup['gate_pass'] else 'FAIL'}")
    for r, n in sup["offending_rules"]:
        print(f"   offending rule x{n}: {r}")
    for s in sup["missed_samples"]:
        print(f"   missed: {s}")
    print(f"== Pipeline (cooldown {a.cooldown}s, settle {a.settle}s, window {a.window}s): {cor['kept_events']:,} kept events -> {cor['items']:,} after repeat filter "
          f"(-{cor['cooldown_dropped']:,}, {cor['unresolved_events']:,} not mapped to an asset) -> {cor['clusters']:,} incidents (compression {cor['compression']}x)")
    print(f"   END TO END: {sup['events']:,} raw events -> {cor['clusters']:,} incidents = {cor['end_to_end_reduction']}x reduction | largest pending set {cor['max_pending']} | overflow {cor['overflow_items']} | {cor['secs']} s")
    print(f"   SAFETY (incident level): {cor['incidents_covered']}/{cor['truth_incidents']} real incidents were surfaced  ->  GATE {'PASS' if cor['incident_coverage_gate'] else 'FAIL'}"
          f"   (of which {cor['incidents_repeat_only']} only as a repeat of an earlier identical alert: the cooldown merged them)")
    print(f"   grouping vs ground truth: pair precision {cor['pair_precision']} | pair recall {cor['pair_recall']} | fragmentation {cor['fragmentation']} clusters/incident")
    if root:
        print(f"   root cause: {root['root_correct']}/{root['storms']} storms correct ({root['root_accuracy_pct']}%)")
    # ugyanaz csak a hiba-szintu (error+) esemenyekkel: a kisebb sulyossagu, megtartott esemenyek a korrelaciot (a gyokerok-elemzest) rontjak-e
    gated = metrics.correlation_report(ev, topo, kept, a.window, a.settle, a.cooldown, min_level="error")
    groot = metrics.root_accuracy(ev, topo, gated, truth) if truth else {}
    print(f"== Severity-gated (error+ only; the rest goes to a digest): {gated['items']:,} items -> {gated['clusters']:,} incidents, end to end {gated['end_to_end_reduction']}x | "
          f"incidents surfaced {gated['incidents_covered']}/{gated['truth_incidents']} | pair precision {gated['pair_precision']} | recall {gated['pair_recall']}"
          + (f" | root cause {groot['root_correct']}/{groot['storms']} ({groot['root_accuracy_pct']}%)" if groot else ""))
    print(f"== Throughput: {tp['events_per_sec']:,} events/s for classification ({tp['events']:,} events in {tp['secs']} s)")
    if a.json:
        for c in (cor, gated):
            c.pop("_clusters")
            c.pop("_pred")
        json.dump({"templates": tpl, "suppression": sup, "correlation": cor, "root": root, "correlation_error_plus": gated, "root_error_plus": groot, "throughput": tp},
                  open(a.json, "w", encoding="utf-8"), indent=1, default=str)
    return 0 if sup["gate_pass"] and cor["incident_coverage_gate"] and gated["incident_coverage_gate"] else 2


def cmd_compare(a):
    ev, _, _ = _load(a.data)
    r = metrics.compare(ev, metrics.load_known(a.base), metrics.load_known(a.candidate))
    print(f"== Change gate: suppressed {r['base']}% -> {r['candidate']}%  |  newly suppressed events: {r['newly_suppressed']:,} {r['newly_suppressed_by_label']}  |  newly kept: {r['newly_kept']:,}")
    print(f"   newly suppressed MUST_KEEP events: {r['newly_suppressed_must_keep']}  ->  GATE {'PASS' if r['gate_pass'] else 'FAIL'}")
    for rule, n in r["offending_rules"]:
        print(f"   offending rule x{n}: {rule}")
    for s in r["samples"]:
        print(f"   would be lost: {s}")
    return 0 if r["gate_pass"] else 2


def cmd_bench(a):
    ev, topo, _ = _load(a.data)
    known = metrics.load_known(a.known)
    tp = metrics.throughput(ev, known, repeat=a.repeat)
    print(f"== Classification: {tp['events_per_sec']:,} events/s ({tp['events']:,} events in {tp['secs']} s); a month of 5M events would take ~{5_000_000 / max(1, tp['events_per_sec']):.0f} s")
    print("== Correlator vs events in a single window (reference = the old pairwise algorithm):")
    for r in metrics.correlator_scaling(topo, [int(x) for x in a.sizes.split(",")], cis_per_item=a.cis_per_item):
        ref = "" if r["reference_secs"] is None else f"   reference {r['reference_secs']} s ({'same result' if r['same_result'] else 'DIFFERENT RESULT'})"
        print(f"   {r['events_in_window']:>6} events -> {r['secs']} s{ref}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="evalkit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("synth")
    s.add_argument("--out", required=True)
    s.add_argument("--days", type=float, default=1)
    s.add_argument("--events-per-day", type=int, default=20000)
    s.add_argument("--storms-per-day", type=int, default=5)
    s.add_argument("--singles-per-day", type=int, default=40)
    s.add_argument("--seed", type=int, default=1)
    r = sub.add_parser("report")
    r.add_argument("--data", required=True)
    r.add_argument("--known", required=True)
    r.add_argument("--window", type=int, default=600)
    r.add_argument("--settle", type=int, default=90)
    r.add_argument("--cooldown", type=int, default=1800)
    r.add_argument("--json")
    c = sub.add_parser("compare")
    c.add_argument("--data", required=True)
    c.add_argument("--base", required=True)
    c.add_argument("--candidate", required=True)
    b = sub.add_parser("bench")
    b.add_argument("--data", required=True)
    b.add_argument("--known", required=True)
    b.add_argument("--sizes", default="100,400,1600,6400,25000")
    b.add_argument("--cis-per-item", type=int, default=1, help="assets named per event; 3 = worst case (almost every event has a unique asset set)")
    b.add_argument("--repeat", type=int, default=1)
    a = ap.parse_args(argv)
    return {"synth": cmd_synth, "report": cmd_report, "compare": cmd_compare, "bench": cmd_bench}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
