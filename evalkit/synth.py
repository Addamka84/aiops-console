"""Szintetikus vallalati esemenyfolyam ISMERT IGAZSAGGAL (label, incidens, gyokerok) - valos munkahelyi adat nelkul is merhetove teszi a rendszert.

FIGYELEM: a szoveg-alakok negy tipikus monitoring eszkoz (Dynatrace, LogicMonitor, SolarWinds, vRealize Operations) riasztasaihoz HASONLITANAK, de nem
gyartoi formatumok (nem pontos masolatok). Ezzel a mechanika (zajszures biztonsaga, korrelacio, teljesitmeny) merheto, a VALOS eloszlas nem: a
tenyleges ertek bizonyitasahoz valos (anonimizalt) exportot kell ugyanebbe a semaba tolteni (lasd schema.py).

Determinisztikus: ugyanaz a (seed, parameterek) ugyanazt az adatot adja.
"""
import random

from . import _env  # noqa: F401
import correlation  # noqa: E402
import topology  # noqa: E402

TOOLS = ("dynatrace", "logicmonitor", "solarwinds", "vrops")
START = 1_760_000_000     # rogzitett kezdoido (reprodukalhatosag)


def build_topology(n_esx=8, n_web=4, n_app=6, n_db=2):
    """Kis, vallalati jellegu CMDB: core + access switchek, hypervisorok, VM-ek, szolgaltatasok."""
    assets = []

    def add(aid, kind, deps=(), runs_on=None, crit="normal"):
        a = {"id": aid, "name": aid, "kind": kind, "criticality": crit}
        if deps:
            a["depends_on"] = [{"id": d, "type": t} for d, t in deps]
        if runs_on:
            a["runs_on"] = runs_on
        assets.append(a)

    add("sw-core-1", "network", crit="high")
    add("sw-core-2", "network", crit="high")
    for k in range(1, 5):
        add(f"sw-acc-{k:02d}", "network", deps=[("sw-core-1" if k <= 2 else "sw-core-2", "network")])
    for k in range(1, n_esx + 1):
        add(f"esx-{k:02d}", "host", deps=[(f"sw-acc-{(k - 1) % 4 + 1:02d}", "network")], crit="high")
    for k in range(1, n_db + 1):
        add(f"vm-db-{k:02d}", "host", runs_on=f"esx-{(k - 1) % n_esx + 1:02d}", crit="high")
    for k in range(1, n_app + 1):
        add(f"vm-app-{k:02d}", "host", runs_on=f"esx-{(k + 1) % n_esx + 1:02d}", deps=[(f"vm-db-{(k - 1) % n_db + 1:02d}", "data")])
    for k in range(1, n_web + 1):
        add(f"vm-web-{k:02d}", "host", runs_on=f"esx-{(k + 3) % n_esx + 1:02d}")
    add("svc-portal", "service", deps=[("vm-web-01", "other"), ("vm-app-01", "other")], crit="high")
    add("svc-erp", "service", deps=[("vm-app-02", "other"), ("vm-db-01", "data")], crit="high")
    doc = {"assets": assets}
    errs = topology.validate(doc)
    assert not errs, errs
    return doc


# ---- szoveg-sablonok (tool, szint, uzenet-sablon; {h}=entitas, {v}=szam, {n}=azonosito)
NOISE = [   # veszteseg nelkul elnyelheto: heartbeat, atmeneti kuszob-tullepes, karbantartas
    ("logicmonitor", "info", "Agent heartbeat received ({v} ms)"),
    ("dynatrace", "info", "OneAgent heartbeat OK, version {v}"),
    ("logicmonitor", "warning", "WARN - CPU utilization {v}% (threshold 85%), auto-clears"),
    ("solarwinds", "warning", "Node response time {v} ms (warning)"),
    ("vrops", "warning", "Symptom: VM CPU ready {v}% above threshold (transient)"),
    ("dynatrace", "info", "Maintenance window active, alerting paused for {h}"),
]
NEUTRAL = [   # kapacitas / tajekoztato: nem zaj, nem kritikus
    ("logicmonitor", "warning", "WARN - Disk usage {v}% on /data"),
    ("vrops", "info", "Symptom: patch pending on {h}"),
    ("solarwinds", "info", "Interface utilization {v}% on uplink"),
]
CRITICAL = [   # SOHA nem nyelheto el
    ("logicmonitor", "critical", "CRIT - SMART status FAILING on disk {v}"),
    ("solarwinds", "critical", "RAID array degraded, {v} disk(s) failed"),
    ("dynatrace", "critical", "Problem P-{n}: Service not responding on {h}"),
    ("vrops", "critical", "Symptom: memory exhausted, available {v} MB on {h}"),
    ("logicmonitor", "critical", "CRIT - Database replication broken, lag {v} s"),
    ("dynatrace", "error", "Problem P-{n}: Certificate expires in {v} days on {h}"),
    ("solarwinds", "error", "Backup job failed on {h} (exit {v})"),
]
STORM = {   # gyoker-tipus: (suly, host-elotag, ["unreachable"-jellegu uzenetek])
    "esx": ("esx-", [("solarwinds", "critical", "Node {h} is down"), ("dynatrace", "critical", "Problem P-{n}: Host unavailable {h}"),
                     ("vrops", "critical", "Symptom: host not responding {h}")]),
    "acc": ("sw-acc-", [("solarwinds", "critical", "Node {h} is down"), ("logicmonitor", "critical", "CRIT - {h} ping loss 100%")]),
    "core": ("sw-core-", [("solarwinds", "critical", "Node {h} is down"), ("logicmonitor", "critical", "CRIT - {h} ping loss 100%")]),
}
DEPENDENT = [("dynatrace", "critical", "Problem P-{n}: Unavailable {h}"), ("logicmonitor", "critical", "CRIT - {h} not reachable"),
             ("vrops", "critical", "Symptom: agent heartbeat lost on {h}")]


def _event(ts, tool, host, level, tmpl, rng, label, incident):
    msg = tmpl.format(h=host, v=rng.randint(1, 999), n=rng.randint(1000, 99999))
    return {"ts": round(ts, 3), "source": tool, "host": host, "ident": tool, "level": level, "msg": msg, "label": label, "incident": incident}


def generate(seed=1, days=1, events_per_day=20000, storms_per_day=5, singles_per_day=40, topo_doc=None):
    """-> (events [ts szerint rendezve], topologia-dokumentum, igazsag {incidens: {root, kind, events}})."""
    rng = random.Random(seed)
    doc = topo_doc or build_topology()
    topo = topology.Topology(doc)
    ids = sorted(topo.assets)
    leaf = [i for i in ids if i.startswith(("vm-", "esx-", "svc-"))]
    events, truth, n_inc = [], {}, 0
    span = days * 86400
    # 1) zaj es tajekoztato esemenyek (a flapping: ugyanaz a CI+sablon rovid idon belul tobbszor)
    total = int(events_per_day * days)
    budget = total
    while budget > 0:
        pool, label = (NOISE, "noise") if rng.random() < 0.74 else (NEUTRAL, "neutral")
        tool, level, tmpl = rng.choice(pool)
        host = rng.choice(leaf)
        burst = rng.randint(3, 8) if (label == "noise" and level == "warning" and rng.random() < 0.5) else 1
        t0 = START + rng.random() * span
        for k in range(burst):
            events.append(_event(t0 + k * rng.uniform(20, 300), tool, host, level, tmpl, rng, label, None))
        budget -= burst
    # 2) onallo kritikus esemenyek (mind sajat incidens)
    for _ in range(int(singles_per_day * days)):
        n_inc += 1
        inc, host = f"inc-{n_inc:04d}", rng.choice(leaf)
        tool, level, tmpl = rng.choice(CRITICAL)
        events.append(_event(START + rng.random() * span, tool, host, level, tmpl, rng, "must_keep", inc))
        truth[inc] = {"root": host, "kind": "single", "events": 1}
    # 3) eseményviharok: egy gyoker kiesese -> a fuggo entitasok mind megszolalnak ~2 percen belul
    for _ in range(int(storms_per_day * days)):
        kind = rng.choices(["esx", "acc", "core"], weights=[60, 30, 10])[0]
        prefix, root_tmpls = STORM[kind]
        root = rng.choice([i for i in ids if i.startswith(prefix)])
        affected = [root] + sorted(correlation.topo_down(topo, root, 3))
        n_inc += 1
        inc, t0, count = f"inc-{n_inc:04d}", START + rng.random() * span, 0
        for ci in affected:
            tmpls = root_tmpls if ci == root else DEPENDENT
            for tool, level, tmpl in rng.sample(tmpls, k=min(len(tmpls), rng.randint(1, 2))):
                events.append(_event(t0 + (0 if ci == root else rng.uniform(1, 120)), tool, ci, level, tmpl, rng, "must_keep", inc))
                count += 1
        truth[inc] = {"root": root, "kind": f"storm-{kind}", "events": count}
    events.sort(key=lambda e: e["ts"])
    return events, doc, truth
