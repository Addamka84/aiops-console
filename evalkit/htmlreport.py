"""Egyoldalas, onallo HTML-jelentes a `report` eredmenyebol (bemutatora: nincs kulso eroforras, nincs JavaScript, vilagos/sotet tema).
A szoveg angol (munkahelyi bemutatasra szant); a kod es a megjegyzesek magyarok."""
import html
import math
from collections import Counter

from . import _env  # noqa: F401
import correlation  # noqa: E402

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b2430;--mute:#5d6b7c;--line:#dde2e8;--ok:#1a7f4b;--okbg:#e3f4ea;--bad:#b3261e;--badbg:#fbe7e5;--acc:#2456c4;--accbg:#e6edfb;--warn:#8a5a00;--warnbg:#fff3d6}
@media (prefers-color-scheme:dark){:root{--bg:#10151c;--card:#182029;--ink:#e6ebf1;--mute:#93a1b2;--line:#2a3541;--ok:#53c98b;--okbg:#14301f;--bad:#ff8a80;--badbg:#3a1b19;--acc:#7da4ff;--accbg:#1a2640;--warn:#f2c35a;--warnbg:#332a12}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 10px}
.sub{color:var(--mute);margin:0 0 16px}
.banner{background:var(--warnbg);color:var(--warn);border:1px solid var(--warn);border-radius:8px;padding:10px 14px;margin:12px 0 20px;font-size:14px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile .v{font-size:28px;font-weight:700;line-height:1.1}.tile .l{color:var(--mute);font-size:13px;margin-top:4px}
.tile.ok{border-color:var(--ok)}.tile.ok .v{color:var(--ok)}.tile.bad{border-color:var(--bad)}.tile.bad .v{color:var(--bad)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.funnel .row{display:grid;grid-template-columns:200px 1fr 110px;gap:10px;align-items:center;margin:6px 0}
.funnel .bar{height:20px;border-radius:4px;background:var(--acc);min-width:3px}
.funnel .n{text-align:right;font-variant-numeric:tabular-nums}
.badge{display:inline-block;border-radius:999px;padding:2px 10px;font-size:13px;font-weight:600}
.badge.ok{background:var(--okbg);color:var(--ok)}.badge.bad{background:var(--badbg);color:var(--bad)}
table{border-collapse:collapse;width:100%;font-size:13px}
td,th{padding:5px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--mute);font-weight:600}
code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
.root{background:var(--okbg)}
ul{margin:6px 0 0 18px;padding:0}li{margin:3px 0}
.foot{color:var(--mute);font-size:13px;margin-top:28px}
@media (max-width:600px){.funnel .row{grid-template-columns:1fr}.funnel .n{text-align:left}}
"""


def _e(s):
    return html.escape(str(s))


def _num(n):
    return f"{n:,}"


def _pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


def _tile(value, label, cls=""):
    return f'<div class="tile {cls}"><div class="v">{_e(value)}</div><div class="l">{_e(label)}</div></div>'


def storm_example(ev, topo, truth, gated, max_rows=10):
    """A legnagyobb vihar: a nyers riasztasok es amit a rendszer belole csinalt (a gyoker-javaslat a valos gyokerrel szemben)."""
    storms = [(meta["events"], inc) for inc, meta in truth.items() if meta["kind"].startswith("storm")]
    if not storms:
        return None
    _, inc = max(storms)
    idx = [i for i, e in enumerate(ev) if e["incident"] == inc]
    pred = gated["_pred"]
    ours = [i for i in idx if i in pred]
    if not ours:
        return None
    best = Counter(pred[i] for i in ours).most_common(1)[0][0]
    group = gated["_clusters"][best]
    info = correlation.analyze(topo, group)
    t0 = min(ev[i]["ts"] for i in idx)
    rows = [(round(ev[i]["ts"] - t0, 1), ev[i]["host"], ev[i]["source"], ev[i]["level"], ev[i]["msg"]) for i in sorted(idx, key=lambda k: ev[k]["ts"])]
    return {"id": inc, "meta": truth[inc], "raw": len(idx), "rows": rows[:max_rows], "more": max(0, len(rows) - max_rows),
            "in_incident": len(group), "from_storm": sum(1 for it in group if ev[it["idx"]]["incident"] == inc), "found_root": info["root"], "confidence": info["confidence"], "impacted": info["impacted"],
            "correct": info["root"] == truth[inc]["root"]}


def _funnel(sup, cor, gated):
    steps = [("Raw events", sup["events"]), ("After noise suppression", sup["kept"]), ("After repeat filter", cor["items"]),
             ("Incidents (all severities)", cor["clusters"]), ("Incidents (error and above)", gated["clusters"])]
    top = math.log10(max(2, steps[0][1]))
    out = []
    for name, n in steps:
        w = max(1.0, 100 * math.log10(max(2, n)) / top) if n else 1.0
        out.append(f'<div class="row"><div>{_e(name)}</div><div><div class="bar" style="width:{w:.1f}%"></div></div><div class="n"><b>{_num(n)}</b></div></div>')
    return "".join(out)


def render(res):
    """res: {sup, tpl, cor, gated, root, groot, tp, storm, change (opcionalis compare-eredmeny + cimkek), title, meta}"""
    sup, cor, gated, tpl, tp = res["sup"], res["cor"], res["gated"], res["tpl"], res["tp"]
    groot, storm, change = res.get("groot") or {}, res.get("storm"), res.get("change")
    gate_ok = sup["gate_pass"] and cor["incident_coverage_gate"]
    tiles = [
        _tile(_num(sup["events"]), "raw events in the data set"),
        _tile(f"{cor['end_to_end_reduction']}x", f"fewer items to look at ({_num(sup['events'])} events -> {_num(cor['clusters'])} incidents, nothing filtered by severity)"),
        _tile(f"{sup['must_keep_missed']} / {_num(sup['must_keep'])}", f"critical events lost to noise rules (95% upper bound {_pct(sup['must_keep_missed_rate_upper95'])})",
              "ok" if sup["gate_pass"] else "bad"),
        _tile(f"{cor['incidents_covered']} / {cor['truth_incidents']}", "real incidents that surfaced as at least one alert", "ok" if cor["incident_coverage_gate"] else "bad"),
    ]
    if groot:
        tiles.append(_tile(f"{groot['root_correct']} / {groot['storms']}", "event storms where the root cause was identified (error and above)", "ok" if groot["root_correct"] == groot["storms"] else ""))
    tiles.append(_tile(f"{tp['events_per_sec']:,}/s", f"classification speed (a month of 5 M events = ~{5_000_000 / max(1, tp['events_per_sec']):.0f} s)"))
    h = [f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
         f"<title>{_e(res.get('title', 'AIOps evaluation report'))}</title><style>{CSS}</style></head><body><main>",
         f"<h1>{_e(res.get('title', 'AIOps evaluation report'))}</h1>",
         f"<p class=\"sub\">{_e(res.get('meta', ''))}</p>",
         '<div class="banner"><b>Synthetic data.</b> The numbers show that the mechanics work (safety gate, correlation, speed), '
         'not what the reduction would be on real production alerts. That requires an anonymised export loaded into the same schema.</div>',
         f'<p>Safety gate: <span class="badge {"ok" if gate_ok else "bad"}">{"PASS" if gate_ok else "FAIL"}</span> &nbsp; '
         "<span class=\"sub\">no critical event may be suppressed, and every real incident must surface.</span></p>",
         f'<div class="tiles">{"".join(tiles)}</div>',
         "<h2>From raw events to incidents</h2>",
         f'<div class="card funnel">{_funnel(sup, cor, gated)}'
         f'<p class="sub" style="margin:10px 0 0">Bar length is logarithmic. The data set has {tpl["templates"]} distinct message shapes '
         f'({tpl["events_per_template"]} events per shape); {tpl["templates_covering_80pct"]} of them cover 80% of all events. '
         f'The repeat filter dropped {_num(cor["cooldown_dropped"])} identical repeats.</p></div>']
    if storm:
        rows = "".join(f'<tr{" class=root" if r[1] == storm["meta"]["root"] else ""}><td class="mono">+{r[0]} s</td><td class="mono">{_e(r[1])}</td><td>{_e(r[2])}</td><td>{_e(r[3])}</td><td class="mono">{_e(r[4])}</td></tr>'
                       for r in storm["rows"])
        more = f"<tr><td colspan=5 class=\"sub\">... and {storm['more']} more alerts</td></tr>" if storm["more"] else ""
        verdict = ('<span class="badge ok">root cause correct</span>' if storm["correct"] else '<span class="badge bad">root cause missed</span>')
        h += ["<h2>One event storm, end to end</h2>", '<div class="card">',
              f'<p><b>{storm["raw"]} alerts</b> from several tools arrived within about two minutes after one device failed '
              f'(<code>{_e(storm["meta"]["root"])}</code>, ground truth). The system turned them into <b>one incident</b> '
              f'covering {storm["in_incident"]} alerts ({storm["from_storm"]} from this storm) and {storm["impacted"]} impacted assets. It named '
              f'<code>{_e(storm["found_root"])}</code> as the likely root cause (confidence {storm["confidence"]}) {verdict}</p>',
              f'<table><tr><th>When</th><th>Asset</th><th>Tool</th><th>Level</th><th>Alert text</th></tr>{rows}{more}</table>',
              '<p class="sub" style="margin:8px 0 0">The highlighted row is the real root. The alerts come from the dependency model (CMDB): a switch or hypervisor failure explains '
              'the "unreachable" alerts of everything that depends on it.</p></div>']
    if change:
        r = change["result"]
        offend = "".join(f"<li><code>{_e(rule)}</code>: {n} critical event(s)</li>" for rule, n in r["offending_rules"])
        samples = "".join(f"<li class=\"mono\">{_e(s)}</li>" for s in r["samples"])
        h += ["<h2>Change gate: a bad noise rule is stopped before it ships</h2>", '<div class="card">',
              f'<p>Candidate rule set <code>{_e(change["candidate"])}</code> against the current one <code>{_e(change["base"])}</code>: suppression would go from {r["base"]}% to {r["candidate"]}%, '
              f'and it would newly suppress {_num(r["newly_suppressed"])} events, of which <b>{r["newly_suppressed_must_keep"]} are critical</b> '
              f'<span class="badge {"ok" if r["gate_pass"] else "bad"}">{"PASS" if r["gate_pass"] else "BLOCKED"}</span></p>']
        if offend:
            h.append(f"<p>Offending rule(s):</p><ul>{offend}</ul>")
        if samples:
            h.append(f"<p>Examples of what would be lost:</p><ul>{samples}</ul>")
        h.append("</div>")
    h += ["<h2>Limits (read before quoting any number)</h2>", '<div class="card"><ul>',
          "<li>Synthetic data, generated with known ground truth. Message shapes resemble four common monitoring tools but are not vendor formats.</li>",
          "<li>The event reduction depends strongly on the data. A small asset model makes storms collapse more than a real CMDB would.</li>",
          "<li>Labels (noise / critical) are defined by the generator. On real data labelling is human work and the most sensitive part of the measurement.</li>",
          "<li>The repeat filter can merge a new, separate incident into an earlier identical alert. The kit counts these cases; they are not silent losses, but they distort incident counts.</li>",
          "<li>The error-and-above view relies on normalised severities; the built-in tool mappings are typical scales, not vendor specifications, and must be checked against the real values (<code>evalkit import</code> lists unmapped ones).</li></ul></div>",
          '<p class="foot">Generated by evalkit (aiops-console). Same inputs and seed give the same report.</p>', "</main></body></html>"]
    return "".join(h)
