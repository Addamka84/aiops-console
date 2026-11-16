"""Detektorok (detectors.py): ellenorzes, kiertekeles, szuneteltetes, akciok, bizonyitek, visszateszt, API.
Futtatas (a stacks/aiops-console mappabol): python3 -m unittest discover -s tests
"""
import datetime as dt
import json
import os
import queue
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402
import console  # noqa: E402
import detectors  # noqa: E402
import runtime  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from store import Store  # noqa: E402

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


def det(**kw):
    d = {"id": "plex-errors", "name": "Plex errors", "query": 'appname:"plex" _msg:~"(?i)error"', "threshold": 5, "window_min": 15}
    d.update(kw)
    return d


def known(noise=()):
    return aiops.Known(data={"noise": list(noise), "known_issues": [], "context": []})


class ValidateTests(unittest.TestCase):
    def errs(self, *items):
        return detectors.validate({"detectors": list(items)})

    def test_valid_and_empty(self):
        self.assertEqual(detectors.validate({}), [])
        self.assertEqual(self.errs(det()), [])
        self.assertEqual(self.errs(det(mode="absent", query="host:homeassistant", window_min=30)), [])
        self.assertEqual(self.errs(det(group_by=["host", "appname"], action="direct", severity="high", enabled=False)), [])

    def test_structure(self):
        self.assertTrue(detectors.validate([]))
        self.assertTrue(detectors.validate({"detectors": "x"}))
        self.assertTrue(detectors.validate({"detectors": [], "x": 1}))
        self.assertTrue(self.errs("x"))

    def test_field_errors(self):
        for bad in (dict(id="Bad Id"), dict(mode="sometimes"), dict(action="page"), dict(severity="urgent"), dict(threshold=0), dict(threshold="5"),
                    dict(window_min=4), dict(window_min=1441), dict(cooldown_min=1), dict(enabled="yes"), dict(group_by="host"),
                    dict(group_by=["a b"]), dict(group_by=["a", "b", "c", "d"]), dict(name=""), dict(surprise=1), dict(note="x" * 301)):
            self.assertTrue(self.errs(det(**bad)), bad)
        self.assertTrue(any("duplicate" in e for e in self.errs(det(), det())))

    def test_query_rules(self):
        for bad in ("", "   ", "a | stats count()", "a\nb", "a; b", "_time:5m a", "x (_time: 1h)", 'a "b', "a (b", "x" * 301):
            self.assertIsNotNone(detectors.check_query(bad), bad)
        for good in ('appname:plex', '"Out of memory"', '_msg:~"(?i)a|b"' if False else '_msg:~"(?i)fatal"', "host:x AND -appname:y", "(a OR b) c", "*"):
            self.assertIsNone(detectors.check_query(good), good)

    def test_regex_alternation_and_parentheses_inside_quotes_are_fine(self):
        for good in ('_msg:~"(ERROR|CRITICAL) "', '_msg:~"ERROR \\\\(MainThread\\\\)" host:x', '_msg:~"a;b" AND -"x|y"', '"say \\"hi|there\\""'):
            self.assertIsNone(detectors.check_query(good), good)
        for bad in ('_msg:~"ERROR" | stats count()', '"unterminated', 'a "b" | c', '(_msg:~"(x)" ', 'a ; b'):
            self.assertIsNotNone(detectors.check_query(bad), bad)

    def test_absent_cannot_group(self):
        self.assertTrue(self.errs(det(mode="absent", group_by=["host"])))


class EvaluateTests(unittest.TestCase):
    def setUp(self):
        self.q = aiops.vl_query
        self.calls = []

    def tearDown(self):
        aiops.vl_query = self.q

    def fake(self, rows):
        def f(query, timeout=None):
            self.calls.append(query)
            return list(rows)
        aiops.vl_query = f

    def test_count_filters_by_threshold_and_groups(self):
        self.fake([{"host": "a", "hits": "3"}, {"host": "b", "hits": "9"}, {"host": "c", "hits": "5"}])
        out = detectors.evaluate(det(group_by=["host"]), NOW)
        self.assertEqual([(o["group"], o["hits"]) for o in out], [({"host": "b"}, 9), ({"host": "c"}, 5)])   # >= 5, csokkeno sorrend
        self.assertIn("_time:15m", self.calls[0])
        self.assertIn("stats by (host) count() as hits", self.calls[0])

    def test_absent_fires_only_without_matches(self):
        self.fake([])
        self.assertEqual(detectors.evaluate(det(mode="absent"), NOW), [{"group": {}, "hits": 0}])
        self.fake([{"hits": "0"}])
        self.assertEqual(detectors.evaluate(det(mode="absent"), NOW), [{"group": {}, "hits": 0}])
        self.fake([{"hits": "12"}])
        self.assertEqual(detectors.evaluate(det(mode="absent"), NOW), [])

    def test_run_once_queues_hits_and_isolates_errors(self):
        aiops.DETECTOR_STATUS.clear()
        while not aiops.DETECTOR_HITS.empty():
            aiops.DETECTOR_HITS.get_nowait()
        aiops.DETECTORS = [detectors.full(det()), detectors.full(det(id="off", enabled=False)), detectors.full(det(id="bad"))]

        def f(query, timeout=None):
            if "plex" in query and "bad" not in query:
                return [{"hits": "7"}]
            raise OSError("vl down")
        aiops.vl_query = f
        # a 'bad' ugyanazt a szurot hasznalja, ezert az is az elso lesz: kulon, hibat dobo szuroval
        aiops.DETECTORS[2] = detectors.full(det(id="bad", query="appname:bad"))
        try:
            detectors.run_once(NOW)
        finally:
            aiops.DETECTORS = []
        hit = aiops.DETECTOR_HITS.get_nowait()
        self.assertEqual((hit["detector"]["id"], hit["hits"]), ("plex-errors", 7))
        self.assertTrue(aiops.DETECTOR_HITS.empty())                         # a letiltott nem fut, a hibas nem ad talalatot
        self.assertIn("vl down", aiops.DETECTOR_STATUS["bad"]["error"])
        self.assertEqual(aiops.DETECTOR_STATUS["plex-errors"]["error"], "")
        self.assertNotIn("off", aiops.DETECTOR_STATUS)


class PollTests(unittest.TestCase):
    def setUp(self):
        self.saved = (aiops.vl_insert, aiops.send_notification, aiops.CFG["MAX_INCIDENTS_PER_HOUR"])
        self.events, self.sent = [], []
        aiops.vl_insert = lambda ev, timeout=None: self.events.extend(ev)
        aiops.send_notification = lambda p: self.sent.append(p) or True
        while not aiops.DETECTOR_HITS.empty():
            aiops.DETECTOR_HITS.get_nowait()
        aiops.DETECTOR_STATUS.clear()
        self.state = {"pending": [], "recent_alert_keys": {}, "incident_times": []}

    def tearDown(self):
        aiops.vl_insert, aiops.send_notification, aiops.CFG["MAX_INCIDENTS_PER_HOUR"] = self.saved

    def hit(self, d, group=None, hits=9):
        aiops.DETECTOR_HITS.put({"detector": detectors.full(d), "group": group or {}, "hits": hits})

    def test_triage_creates_an_incident_with_the_detector_spec(self):
        self.hit(det(group_by=["host"]), {"host": "h3"}, 9)
        aiops.poll_detectors(self.state, NOW)
        job = self.state["pending"][0]
        self.assertEqual((job["kind"], job["detector"]["id"], job["detector"]["group"]), ("incident", "plex-errors", {"host": "h3"}))
        self.assertIn("[DETECTOR] Plex errors: 9 matching lines in the last 15 min", job["alert_text"])
        self.assertIn("host=h3", job["alert_text"])
        self.assertEqual(self.sent, [])
        self.assertEqual([e["kind"] for e in self.events], ["detector"])
        self.assertEqual(aiops.DETECTOR_STATUS["plex-errors"]["last_fired"], aiops.iso(NOW))

    def test_cooldown_per_group(self):
        self.hit(det(group_by=["host"], cooldown_min=60), {"host": "a"})
        self.hit(det(group_by=["host"], cooldown_min=60), {"host": "a"})   # ugyanaz a csoport: kimarad
        self.hit(det(group_by=["host"], cooldown_min=60), {"host": "b"})   # masik csoport: tuzel
        aiops.poll_detectors(self.state, NOW)
        self.assertEqual(len(self.state["pending"]), 2)
        self.hit(det(group_by=["host"], cooldown_min=60), {"host": "a"})
        aiops.poll_detectors(self.state, NOW)
        self.assertEqual(len(self.state["pending"]), 2)                      # meg a szuneteltetesben
        for k in self.state["recent_alert_keys"]:
            self.state["recent_alert_keys"][k] -= 61 * 60
        self.hit(det(group_by=["host"], cooldown_min=60), {"host": "a"})
        aiops.poll_detectors(self.state, NOW)
        self.assertEqual(len(self.state["pending"]), 3)                      # lejart: ujra tuzel

    def test_incident_cap_applies_to_triage_only(self):
        aiops.CFG["MAX_INCIDENTS_PER_HOUR"] = 1
        self.hit(det(id="a"))
        self.hit(det(id="b"))
        self.hit(det(id="c", action="none"))
        aiops.poll_detectors(self.state, NOW)
        self.assertEqual([j["detector"]["id"] for j in self.state["pending"]], ["a"])
        self.assertEqual(len(self.events), 2)                                # a ('b' korlaton kivul) nem rogzul, a 'none' igen

    def test_direct_notifies_without_a_model(self):
        self.hit(det(action="direct", severity="high"), None, 12)
        aiops.poll_detectors(self.state, NOW)
        self.assertEqual(self.state["pending"], [])
        self.assertEqual((self.sent[0]["kind"], self.sent[0]["severity"], self.sent[0]["title"]), ("detector", "high", "AIOps detector: Plex errors"))
        self.assertIn("12 matching lines", self.sent[0]["message"])

    def test_none_only_records(self):
        self.hit(det(action="none", severity="low"))
        aiops.poll_detectors(self.state, NOW)
        self.assertEqual((self.state["pending"], self.sent, len(self.events)), ([], [], 1))
        self.assertEqual((self.events[0]["action"], self.events[0]["severity"]), ("none", "low"))

    def test_old_detector_keys_are_pruned(self):
        self.state["recent_alert_keys"] = {"det:x|{}": 1.0, "Alert|": 1.0}
        aiops.poll_detectors(self.state, NOW)
        self.assertEqual(list(self.state["recent_alert_keys"]), ["Alert|"])


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.saved = (aiops.vl_query, aiops.vl_insert, aiops.collect, aiops.build_input, aiops.review_stats, aiops.ollama_chat)
        self.rows = [{"host": "h3", "appname": "plex", "_msg": "Error: boom <N>", "hits": "4"}]
        self.queries, self.inserted, self.extra = [], [], []

        def q(query, timeout=None):
            self.queries.append(query)
            return list(self.rows)

        def bi(kn, a, b, extra_lines=None, raw=None):
            self.extra.append(extra_lines)
            return "input"

        def stop(*a, **k):
            raise aiops.OllamaError("stop")
        aiops.vl_query = q
        aiops.vl_insert = lambda ev, timeout=None: self.inserted.extend(ev)
        aiops.collect, aiops.build_input, aiops.review_stats, aiops.ollama_chat = lambda a, b: {}, bi, lambda *a, **k: {}, stop

    def tearDown(self):
        (aiops.vl_query, aiops.vl_insert, aiops.collect, aiops.build_input, aiops.review_stats, aiops.ollama_chat) = self.saved
        aiops.STATUS.pop("last_skipped_incident", None)

    def job(self, **kw):
        d = {"id": "plex-errors", "name": "Plex errors", "query": "appname:plex", "mode": "count", "group": {"host": "h3"}, "window_min": 15}
        d.update(kw)
        return {"kind": "incident", "key": "det:plex-errors|{}", "alert_text": "[DETECTOR] x", "alert_labels": [], "detector": d,
                "window_from": "2026-11-16T11:00:00Z", "window_to": "2026-11-16T12:00:00Z"}

    class Pool:
        def pick(self):
            return {"url": "http://x"}

        def mark_down(self, ep, why):
            pass

    def test_real_lines_reach_the_model_input_and_the_query_is_scoped(self):
        self.assertEqual(aiops.run_job(self.job(), known(), self.Pool()), "retry")
        text = "\n".join(self.extra[0])
        self.assertIn("Log lines behind the alert", text)
        self.assertIn("Error: boom", text)
        self.assertIn('host:"h3"', self.queries[0])
        self.assertIn("(appname:plex)", self.queries[0])

    def test_noise_covered_detector_is_skipped(self):
        self.assertEqual(aiops.run_job(self.job(), known(noise=["boom"]), self.Pool()), "done")
        self.assertEqual([e["kind"] for e in self.inserted], ["incident_skipped"])
        self.assertEqual(self.extra, [])

    def test_absent_detector_has_no_evidence_but_runs(self):
        self.assertEqual(aiops.run_job(self.job(mode="absent", group={}), known(), self.Pool()), "retry")
        self.assertEqual(self.queries, [])                                   # nincs mit lekerdezni: nincs egyezo sor
        self.assertNotIn("could NOT be retrieved", "\n".join(self.extra[0]))

    def test_evidence_failure_does_not_block(self):
        def boom(q, timeout=None):
            raise OSError("vl down")
        aiops.vl_query = boom
        self.assertEqual(aiops.run_job(self.job(), known(), self.Pool()), "retry")
        self.assertIn("could NOT be retrieved", "\n".join(self.extra[0]))

    def test_group_values_are_escaped(self):
        self.assertEqual(detectors.group_filter({"host": 'a"b\\c', "bad field": "x"}), 'host:"a\\"b\\\\c"')


class BacktestTests(unittest.TestCase):
    def setUp(self):
        self.saved = (aiops.vl_stats_range, aiops.vl_query)

    def tearDown(self):
        aiops.vl_stats_range, aiops.vl_query = self.saved

    def run_bt(self, d, series, samples=()):
        aiops.vl_stats_range = lambda q, a, b, step, timeout=None: series
        aiops.vl_query = lambda q, timeout=None: list(samples)
        return detectors.backtest(d, 24, NOW)

    def ts(self, minutes_ago):
        return int(NOW.timestamp()) // 900 * 900 - minutes_ago * 60

    def test_count_events_cooldown_and_samples(self):
        series = [{"metric": {"host": "a"}, "values": [[self.ts(300), "9"], [self.ts(285), "9"], [self.ts(60), "2"], [self.ts(30), "7"]]},
                  {"metric": {"host": "b"}, "values": [[self.ts(100), "20"]]}]
        r = self.run_bt(det(group_by=["host"], threshold=5, cooldown_min=60), series, [{"_msg": "Error <N>", "hits": "42"}])
        by = [(e["group"]["host"], e["hits"], e["fires"]) for e in r["events"]]
        self.assertEqual(by, [("a", 9, True), ("a", 9, False), ("b", 20, True), ("a", 7, True)])   # 2. 'a' a szuneteltetesben; a 2-es a kuszob alatt
        self.assertEqual((r["firings"], r["events_total"], r["total"]), (3, 4, 47))
        self.assertEqual(r["samples"], [{"msg": "Error <N>", "hits": 42}])
        self.assertFalse(r["no_match"])

    def test_the_running_bucket_is_ignored(self):
        cur = int(NOW.timestamp()) // 900 * 900
        r = self.run_bt(det(threshold=1), [{"metric": {}, "values": [[cur, "99"]]}])
        self.assertEqual(r["events"], [])

    def test_absent_lists_silent_buckets(self):
        have = [self.ts(m) for m in range(15, 24 * 60, 15) if not 120 <= m <= 180]   # kb. 2-3 ora hianyzik
        r = self.run_bt(det(mode="absent", cooldown_min=120), [{"metric": {}, "values": [[t, "3"] for t in have]}])
        self.assertEqual(r["events_total"], 5)                               # a 2-3 oras rés 5 vodor; az adat elotti vedrek nem szamitanak
        self.assertEqual(r["firings"], 1)                                    # egy osszefuggo elhallgatas, a szuneteltetes miatt egyetlen riasztas
        r2 = self.run_bt(det(mode="absent", cooldown_min=60), [{"metric": {}, "values": [[t, "3"] for t in have]}])
        self.assertEqual(r2["firings"], 2)                                   # 75 perces rés, 60 perces szuneteltetes: emlekeztetove ujra tuzel
        self.assertFalse(r["no_match"])

    def test_no_match_is_reported_not_fired(self):
        r = self.run_bt(det(), [])
        self.assertTrue(r["no_match"])
        r2 = self.run_bt(det(mode="absent"), [])
        self.assertTrue(r2["no_match"])
        self.assertEqual(r2["events"], [])                                   # rossz szuro, nem 'elhallgatas'

    def test_invalid_query_is_rejected(self):
        with self.assertRaises(ValueError):
            detectors.backtest(det(query="a | stats count()"), 24, NOW)


class ApiTests(unittest.TestCase):
    R = {"Authorization": "Bearer r-token"}
    A = {"Authorization": "Bearer a-token"}

    def setUp(self):
        self.saved = (aiops.DETECTORS, aiops.vl_stats_range, aiops.vl_query)
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))

    def tearDown(self):
        aiops.DETECTORS, aiops.vl_stats_range, aiops.vl_query = self.saved

    def test_put_validates_and_hot_reloads(self):
        bad = self.c.put("/api/v1/config/detectors", headers=self.A, json={"content": {"detectors": [det(query="a | b")]}})
        self.assertEqual(bad.status_code, 422)
        self.assertEqual(self.c.put("/api/v1/config/detectors", headers=self.R, json={"content": {"detectors": [det()]}}).status_code, 403)
        ok = self.c.put("/api/v1/config/detectors", headers=self.A, json={"content": {"detectors": [det(), det(id="x", enabled=False)]}, "comment": "seed"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual([d["id"] for d in aiops.DETECTORS], ["plex-errors", "x"])
        self.assertEqual(aiops.DETECTORS[0]["cooldown_min"], 60)                # az alapertekek kitoltve
        self.assertEqual(self.c.get("/api/v1/status", headers=self.R).json()["config"]["detectors_rev"], ok.json()["rev"])

    def test_proposal(self):
        p = self.c.post("/api/v1/proposals", headers=self.R, json={"key": "detectors", "comment": "watch plex", "content": {"detectors": [det()]}})
        self.assertEqual(p.status_code, 200, p.text)
        self.assertEqual(self.c.post(f"/api/v1/proposals/{p.json()['id']}/approve", headers=self.A).status_code, 200)
        self.assertEqual(len(aiops.DETECTORS), 1)

    def test_backtest_endpoint(self):
        t = int(aiops.utcnow().timestamp()) // 900 * 900 - 3600
        aiops.vl_stats_range = lambda q, a, b, step, timeout=None: [{"metric": {}, "values": [[t, "8"]]}]
        aiops.vl_query = lambda q, timeout=None: [{"_msg": "Error <N>", "hits": "8"}]
        r = self.c.post("/api/v1/test/detector", headers=self.R, json={"detector": det(), "hours": 24})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((r.json()["firings"], r.json()["total"]), (1, 8))
        self.assertEqual(self.c.post("/api/v1/test/detector", headers=self.R, json={"detector": det(query="a | b")}).status_code, 422)
        self.assertEqual(self.c.post("/api/v1/test/detector", headers=self.R, json={"detector": det(), "hours": 0}).status_code, 422)
        self.assertEqual(self.c.post("/api/v1/test/detector", json={"detector": det()}).status_code, 401)

    def test_backtest_vl_error_is_502(self):
        def boom(*a, **k):
            raise OSError("vl down")
        aiops.vl_stats_range = boom
        self.assertEqual(self.c.post("/api/v1/test/detector", headers=self.R, json={"detector": det()}).status_code, 502)

    def test_status_endpoint(self):
        self.c.put("/api/v1/config/detectors", headers=self.A, json={"content": {"detectors": [det()]}, "comment": "seed"})
        aiops.DETECTOR_STATUS["plex-errors"] = {"last_eval": "2026-11-16T12:00:00Z", "last_hits": 1, "error": ""}
        aiops.vl_query = lambda q, timeout=None: [{"_time": "2026-11-16T11:00:00Z", "detector": "plex-errors", "hits": "9"}]
        j = self.c.get("/api/v1/detectors/status", headers=self.R).json()
        self.assertEqual((j["mode"], j["detectors"][0]["id"], j["detectors"][0]["last_hits"], len(j["recent"])), ("on", "plex-errors", 1, 1))

        def boom(*a, **k):
            raise OSError("down")
        aiops.vl_query = boom
        j2 = self.c.get("/api/v1/detectors/status", headers=self.R).json()
        self.assertEqual((j2["recent"], j2["recent_error"]), ([], "VictoriaLogs unavailable"))

    def test_settings_are_editable(self):
        r = self.c.put("/api/v1/config/settings", headers=self.A, json={"content": {"DETECTOR_MODE": "off", "DETECTOR_INTERVAL_S": 120}})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((aiops.CFG["DETECTOR_MODE"], aiops.CFG["DETECTOR_INTERVAL_S"]), ("off", 120))
        self.assertEqual(self.c.put("/api/v1/config/settings", headers=self.A, json={"content": {"DETECTOR_MODE": "maybe"}}).status_code, 422)
        self.c.put("/api/v1/config/settings", headers=self.A, json={"content": {}})


class PollIncidentsRegressionTests(unittest.TestCase):
    def test_two_new_alerts_in_one_poll_are_both_processed(self):
        saved = aiops.vl_query
        rows = [{"_time": "2026-11-16T07:10:00.5Z", "alertname": "A", "alert_root": "", "alert_count": "1", "alerts": "", "_msg": "[FIRING] A"},
                {"_time": "2026-11-16T07:10:30.5Z", "alertname": "B", "alert_root": "", "alert_count": "1", "alerts": "", "_msg": "[FIRING] B"}]
        aiops.vl_query = lambda q, timeout=None: list(rows)
        try:
            state = {"pending": [], "last_alert_ts": "2026-11-16T07:00:00.000000Z", "recent_alert_keys": {}, "incident_times": []}
            aiops.poll_incidents(state, NOW)
        finally:
            aiops.vl_query = saved
        self.assertEqual([j["key"] for j in state["pending"]], ["A|", "B|"])
        self.assertEqual(state["last_alert_ts"], "2026-11-16T07:10:30.500000Z")


if __name__ == "__main__":
    unittest.main()
