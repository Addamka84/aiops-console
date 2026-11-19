"""Demo-betolto: szintetikus (evalkit) esemenyfolyam -> VictoriaLogs, a konzol bealitasa.  Stdlib + az evalkit/src modulok.

Parancsok (a stacks/aiops-console mappabol; Dockerben lasd demo/docker-compose.yml):
  python demo/loader.py setup                 vart a konzolra, betolti a topologiat, az ismert zajlistat, a beallitasokat
  python demo/loader.py seed  [--days 3]      mult feltoltese (zaj, tajekoztato, kritikus, viharok), a vegen: most
  python demo/loader.py live  [--speed 1]     folyamatos 'elo' folyam (valos ideju bejegyzesek)
  python demo/loader.py storm [--root esx-02] egy eseményvihar azonnal (elo bemutatohoz: 'kihuzzuk a konnektort')

Mit ir a VictoriaLogs-ba: minden esemenyt syslog-sorkent (pipeline:syslog: host, appname, severity, _msg), a kritikus/hiba-szintu
esemenyekbol (must_keep) ezen felul riasztas-rekordot (appname:alert, alert_status:firing), ahogy egy riasztas-szabaly (vmalert) tenne.
Kornyezeti valtozok: VL_URL, CONSOLE_URL, CONSOLE_ADMIN_TOKEN.
FIGYELEM: minden adat szintetikus; a szoveg-alakok monitoring-eszkozokre hasonlitanak, nem gyartoi formatumok.
"""
import argparse
import datetime as dt
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from evalkit import synth  # noqa: E402
import correlation  # noqa: E402
import topology  # noqa: E402

VL_URL = os.environ.get("VL_URL", "http://127.0.0.1:9428").rstrip("/")
CONSOLE_URL = os.environ.get("CONSOLE_URL", "http://127.0.0.1:8095").rstrip("/")
SEVERITY = {"debug": "debug", "info": "info", "warning": "warning", "error": "err", "critical": "crit"}
ALERT_LEVELS = ("error", "critical")
BATCH = 4000


def iso_us(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def records(e, ts):
    """Egy szintetikus esemeny -> VictoriaLogs-rekordok (syslog-sor, kritikusnal riasztas is)."""
    t = iso_us(ts)
    out = [{"_time": t, "pipeline": "syslog", "host": e["host"], "appname": e["source"], "severity": SEVERITY[e["level"]], "_msg": e["msg"]}]
    if e["level"] in ALERT_LEVELS:
        slug = re.sub(r"[^A-Za-z0-9]+", "_", re.sub(r"\d+", "N", e["msg"].replace(e["host"], "HOST"))).strip("_")[:48]
        name = f"{e['source']}_{slug}"
        alerts = [{"labels": {"alertname": name, "host": e["host"], "severity": SEVERITY[e["level"]], "monitor": e["source"]}}]
        out.append({"_time": t, "pipeline": "alert", "appname": "alert", "alert_status": "firing", "alertname": name, "alert_root": e["host"],
                    "alert_count": "1", "alerts": json.dumps(alerts), "_msg": f"[FIRING] {e['source']}: {e['msg']}"})
    return out


def vl_insert(recs):
    for i in range(0, len(recs), BATCH):
        chunk = recs[i:i + BATCH]
        body = "\n".join(json.dumps(r, ensure_ascii=False) for r in chunk).encode("utf-8")
        qs = urllib.parse.urlencode({"_stream_fields": "pipeline,host,appname", "_msg_field": "_msg", "_time_field": "_time"})
        req = urllib.request.Request(VL_URL + "/insert/jsonline?" + qs, data=body, headers={"Content-Type": "application/stream+json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            r.read()


def wait_for(url, what, tries=90):
    for _ in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                r.read()
            return
        except (OSError, urllib.error.URLError):
            time.sleep(2)
    sys.exit(f"{what} nem erheto el: {url}")


def console_put(key, content, comment):
    tok = os.environ.get("CONSOLE_ADMIN_TOKEN", "")
    if not tok:
        sys.exit("CONSOLE_ADMIN_TOKEN kell a setup-hoz")
    body = json.dumps({"content": content, "comment": comment}).encode("utf-8")
    req = urllib.request.Request(f"{CONSOLE_URL}/api/v1/config/{key}", data=body, method="PUT",
                                 headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json", "X-Actor": "demo-loader"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
    except urllib.error.HTTPError as e:
        sys.exit(f"{key}: HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}")


def cmd_setup(a):
    wait_for(CONSOLE_URL + "/api/v1/health", "konzol")
    known = json.load(open(os.path.join(ROOT, "evalkit", "examples", "known.good.json"), encoding="utf-8"))
    console_put("topology", synth.build_topology(), "demo: szintetikus eszkozmodell (CMDB)")
    console_put("known", known, "demo: zajszabalyok a szintetikus esemenyfolyamhoz")
    console_put("settings", {"NOVELTY_MODE": "report", "NOVELTY_LEARN_HOURS": 24, "NOVELTY_BACKFILL_DAYS": 3, "NOVELTY_INTERVAL_MIN": 5, "CORRELATE_MODE": "on",
                             "CORRELATE_SETTLE_S": 90, "SUPERVISOR_MODE": "propose", "SUPERVISOR_API": "mock", "SUPERVISOR_INTERVAL_MIN": 60},
                "demo: korrelacio, ujdonsag-figyeles, mock Supervisor (modell nelkul)")
    print("setup kesz: topologia, ismert zaj, beallitasok betoltve")
    return 0


def cmd_seed(a):
    ev, _, truth = synth.generate(a.seed, a.days, a.events_per_day, a.storms_per_day, a.singles_per_day)
    end = max(e["ts"] for e in ev)                  # tenyleges utolso esemeny (a flapping-sorozatok tulnyulhatnak a napon)
    # a mult utolso pillanata 15 perccel ezelott van: a konzol az indulas utani riasztasokat dolgozza fel, a multat nem (igy nem nyilik 'regi' incidens)
    shift = time.time() - 900 - end
    recs = []
    for e in ev:
        recs += records(e, e["ts"] + shift)
    vl_insert(recs)
    print(f"seed kesz: {len(ev)} esemeny, {len(recs)} rekord, {len(truth)} incidens a mult {a.days} napjaban")
    return 0


def storm_events(topo, rng, root=None, spread_s=60.0):
    """Egy vihar esemenyei (relativ idovel): a gyoker + a fuggo eszkozok, mint a synth.generate-ben."""
    kind_of = {"esx": "esx", "sw-acc": "acc", "sw-core": "core"}
    if not root:
        kind = rng.choices(["esx", "acc", "core"], weights=[60, 30, 10])[0]
        prefix = synth.STORM[kind][0]
        root = rng.choice([i for i in sorted(topo.assets) if i.startswith(prefix)])
    kind = next((v for k, v in kind_of.items() if root.startswith(k)), None)
    if not kind or root not in topo.assets:
        sys.exit(f"ismeretlen gyoker: {root} (esx-NN, sw-acc-NN vagy sw-core-N)")
    root_tmpls = synth.STORM[kind][1]
    out = []
    for ci in [root] + sorted(correlation.topo_down(topo, root, 3)):
        tmpls = root_tmpls if ci == root else synth.DEPENDENT
        for tool, level, tmpl in rng.sample(tmpls, k=min(len(tmpls), rng.randint(1, 2))):
            e = synth._event(0, tool, ci, level, tmpl, rng, "must_keep", "demo")
            out.append((0.0 if ci == root else rng.uniform(1, spread_s), e))
    out.sort(key=lambda x: x[0])
    return root, out


def emit_timed(items, speed=1.0):
    """[(relativ ido, esemeny)] kibocsatasa valos idoben (az esemenyek 'most' idobelyeget kapnak)."""
    t0 = time.time()
    for rel, e in items:
        wait = t0 + rel / speed - time.time()
        if wait > 0:
            time.sleep(wait)
        vl_insert(records(e, time.time()))


def cmd_storm(a):
    topo = topology.Topology(synth.build_topology())
    root, items = storm_events(topo, random.Random(a.seed if a.seed is not None else time.time()), a.root, a.spread)
    print(f"vihar: gyoker {root}, {len(items)} riasztas ~{a.spread:.0f} masodpercen belul; a konzol ~90 mp 'leulepedes' utan egy incidenst nyit")
    emit_timed(items)
    return 0


NOVEL = [   # soha nem latott uzenet-alakok (az ujdonsag-figyeles 'new pattern' leletet ad rolluk)
    ("solarwinds", "vm-app-03", "warning", "Licensing: feature pack 'Advanced Reporting' will be disabled in {v} days"),
    ("dynatrace", "vm-db-01", "error", "Problem P-{n}: Unexpected TLS handshake failure from peer, cipher negotiation aborted"),
    ("vrops", "esx-04", "warning", "Symptom: datastore latency anomaly detected on LUN {v}"),
]


def cmd_novel(a):
    """Nehany, a mult 3 napban soha elo uzenet-forma: az ujdonsag-figyeles a kovetkezo vizsgalatnal (alapbol ~5 percen belul) felveszi leletkent."""
    rng = random.Random(time.time())
    recs = []
    for tool, host, level, tmpl in NOVEL:
        for _ in range(a.count):
            e = {"ts": time.time(), "source": tool, "host": host, "ident": tool, "level": level, "msg": tmpl.format(v=rng.randint(2, 40), n=rng.randint(1000, 99999)),
                 "label": "neutral", "incident": None}
            recs += records(e, time.time() - rng.uniform(0, 30))[:1]       # csak syslog-sor, nem riasztas
    vl_insert(recs)
    print(f"{len(recs)} uj mintaju sor kiirva ({len(NOVEL)} uj uzenet-forma); a konzol Status/Novelty oldalan a kovetkezo vizsgalat utan jelenik meg")
    return 0


def cmd_live(a):
    topo = topology.Topology(synth.build_topology())
    rng, n = random.Random(a.seed), 0
    print(f"elo folyam (sebesseg {a.speed}x): ~{a.events_per_day / 86400 * a.speed:.2f} esemeny/s; Ctrl+C a leallitashoz")
    while True:
        # egy orara eso esemenyfolyam, a nap veletlen reszebol; a viharokat a 'storm' parancs adja (vagy a ritka, automatikus)
        ev, _, _ = synth.generate(rng.randrange(1 << 30), 1 / 24, a.events_per_day, a.storms_per_day, a.singles_per_day, topo_doc=synth.build_topology())
        base = min((e["ts"] for e in ev), default=0)
        emit_timed([(e["ts"] - base, e) for e in ev], speed=a.speed)
        n += 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="loader")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup")
    for name in ("seed", "live"):
        s = sub.add_parser(name)
        s.add_argument("--days", type=float, default=3)
        s.add_argument("--events-per-day", type=int, default=20000)
        s.add_argument("--storms-per-day", type=int, default=3)
        s.add_argument("--singles-per-day", type=int, default=30)
        s.add_argument("--seed", type=int, default=21)
        if name == "live":
            s.add_argument("--speed", type=float, default=1.0)
    nv = sub.add_parser("novel")
    nv.add_argument("--count", type=int, default=3, help="sorok szama uzenet-formankent")
    st = sub.add_parser("storm")
    st.add_argument("--root", help="gyoker eszkoz (alapbol veletlen), pl. esx-02, sw-acc-01, sw-core-1")
    st.add_argument("--spread", type=float, default=60.0, help="a riasztasok szorodasa masodpercben")
    st.add_argument("--seed", type=int)
    a = ap.parse_args(argv)
    return {"setup": cmd_setup, "seed": cmd_seed, "storm": cmd_storm, "novel": cmd_novel, "live": cmd_live}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
