"""A demo-betolto (demo/loader.py): rekord-alak, vihar, setup (a konzol sajat ellenorzoivel), kulso szolgaltatas nelkul (helyi stub-szerver)."""
import http.server
import json
import os
import random
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")
sys.path.insert(0, os.path.join(HERE, "..", "demo"))

import aiops  # noqa: E402
import topology  # noqa: E402
import loader  # noqa: E402
from evalkit import synth  # noqa: E402


class Stub(http.server.BaseHTTPRequestHandler):
    log = []

    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        Stub.log.append((self.command, self.path, self.headers.get("Authorization", ""), self.rfile.read(n).decode("utf-8")))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    do_POST = do_PUT = do_GET = _do

    def log_message(self, *a):
        pass


class LoaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), Stub)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        loader.VL_URL = cls.url
        loader.CONSOLE_URL = cls.url
        os.environ["CONSOLE_ADMIN_TOKEN"] = "t" * 40

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        Stub.log.clear()

    def test_records_syslog_and_alert(self):
        crit = {"ts": 1, "source": "dynatrace", "host": "esx-01", "level": "critical", "msg": "Problem P-123: Host unavailable esx-01", "label": "must_keep", "incident": "i"}
        info = dict(crit, level="info", msg="OneAgent heartbeat OK, version 5", label="noise", incident=None)
        r = loader.records(crit, 1_700_000_000.5)
        self.assertEqual([x["pipeline"] for x in r], ["syslog", "alert"])
        self.assertEqual(r[0]["severity"], "crit")
        self.assertEqual((r[1]["appname"], r[1]["alert_status"], r[1]["alert_root"]), ("alert", "firing", "esx-01"))
        lab = json.loads(r[1]["alerts"])[0]["labels"]
        self.assertEqual((lab["host"], lab["monitor"]), ("esx-01", "dynatrace"))
        self.assertTrue(aiops.SAFE_LABEL.match(lab["alertname"]), lab["alertname"])        # a konzol labelszurojen atmegy
        self.assertEqual([x["pipeline"] for x in loader.records(info, 1.0)], ["syslog"])   # info/warning: nincs riasztas
        self.assertTrue(r[0]["_time"].endswith("Z") and "." in r[0]["_time"])

    def test_alertname_does_not_contain_host_numbers(self):
        a = loader.records({"ts": 1, "source": "solarwinds", "host": "sw-acc-02", "level": "critical", "msg": "Node sw-acc-02 is down", "label": "must_keep", "incident": "i"}, 1.0)[1]
        b = loader.records({"ts": 1, "source": "solarwinds", "host": "sw-acc-03", "level": "critical", "msg": "Node sw-acc-03 is down", "label": "must_keep", "incident": "i"}, 1.0)[1]
        self.assertEqual(a["alertname"], b["alertname"])                  # azonos riasztas-tipus, kulonbozo alert_root

    def test_storm_events(self):
        topo = topology.Topology(synth.build_topology())
        root, items = loader.storm_events(topo, random.Random(5), "esx-02", 60)
        self.assertEqual(root, "esx-02")
        self.assertEqual(items[0][1]["host"], "esx-02")                   # a gyoker elol, 0 s
        self.assertEqual(items[0][0], 0.0)
        self.assertGreater(len({e["host"] for _, e in items}), 3)         # a fuggo eszkozok is megszolalnak
        self.assertTrue(all(0 <= rel <= 60 for rel, _ in items))
        with self.assertRaises(SystemExit):
            loader.storm_events(topo, random.Random(1), "nincs-ilyen", 60)

    def test_seed_writes_in_past_and_batches(self):
        rc = loader.main(["seed", "--days", "0.05", "--events-per-day", "20000", "--storms-per-day", "20", "--singles-per-day", "40"])
        self.assertEqual(rc, 0)
        posts = [x for x in Stub.log if x[0] == "POST"]
        self.assertTrue(posts and all("/insert/jsonline" in p[1] and "_stream_fields" in p[1] for p in posts))
        recs = [json.loads(line) for p in posts for line in p[3].splitlines()]
        self.assertGreater(len(recs), 500)
        self.assertTrue(any(r["pipeline"] == "alert" for r in recs))
        import calendar
        import time
        newest = max(r["_time"] for r in recs)
        t = calendar.timegm(time.strptime(newest[:19], "%Y-%m-%dT%H:%M:%S"))
        self.assertLess(t, time.time() - 600)                             # a mult: legalabb ~10 perccel ezelott er veget

    def test_setup_payloads_pass_console_validators(self):
        rc = loader.main(["setup"])
        self.assertEqual(rc, 0)
        puts = {x[1].rsplit("/", 1)[1]: json.loads(x[3]) for x in Stub.log if x[0] == "PUT"}
        self.assertEqual(set(puts), {"topology", "known", "settings"})
        self.assertFalse(topology.validate(puts["topology"]["content"]))
        self.assertFalse(aiops.validate_known(puts["known"]["content"]))
        self.assertTrue(all(x[2] == "Bearer " + "t" * 40 for x in Stub.log if x[0] == "PUT"))
        self.assertEqual(puts["settings"]["content"]["SUPERVISOR_API"], "mock")
        import settings
        self.assertEqual(settings.validate(puts["settings"]["content"])[1], [])               # a konzol beallitas-ellenorzojen is atmegy (pl. az intervallum minimuma)

    def test_novel_writes_syslog_only(self):
        self.assertEqual(loader.main(["novel", "--count", "2"]), 0)
        recs = [json.loads(line) for x in Stub.log if x[0] == "POST" for line in x[3].splitlines()]
        self.assertEqual(len(recs), 6)
        self.assertTrue(all(r["pipeline"] == "syslog" for r in recs))


if __name__ == "__main__":
    unittest.main()
