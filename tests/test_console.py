"""Tesztek a konfig-tarhoz, a beallitasokhoz, a futasidejű osszekotéshez es a REST API-hoz.
Futtatas (a stacks/aiops-console mappabol): python3 -m unittest discover -s tests -v
"""
import copy
import json
import os
import queue
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from fastapi.testclient import TestClient  # noqa: E402

import aiops  # noqa: E402
import console  # noqa: E402
import runtime  # noqa: E402
import settings  # noqa: E402
from store import Store, StoreError  # noqa: E402

with open(os.environ["KNOWN_FILE"], encoding="utf-8") as _f:
    FIXTURE = json.load(_f)


def reset_cfg():
    settings.apply({})
    aiops.CFG["HA_WEBHOOK_URL"] = ""
    while not aiops.COMMANDS.empty():
        aiops.COMMANDS.get_nowait()


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.s = Store()

    def test_put_current_revisions_rollback(self):
        self.assertEqual(self.s.revision_id("known"), 0)
        self.assertIsNone(self.s.current("known"))
        r1 = self.s.put("known", {"noise": ["a"]}, "seed", "first")
        r2 = self.s.put("known", {"noise": ["a", "b"]}, "admin", "second")
        self.assertEqual(self.s.revision_id("known"), r2)
        self.assertEqual(self.s.current("known")["content"], {"noise": ["a", "b"]})
        self.assertEqual([r["id"] for r in self.s.revisions("known")], [r2, r1])
        self.assertNotIn("content", self.s.revisions("known")[0])
        r3 = self.s.rollback("known", r1, "admin")
        self.assertEqual(self.s.current("known")["content"], {"noise": ["a"]})
        self.assertGreater(r3, r2)  # a visszaallitas is uj verzio: a tortenet nem vesz el
        with self.assertRaises(StoreError):
            self.s.revision("known", 9999)

    def test_keys_are_independent(self):
        self.s.put("known", {"x": 1}, "a")
        self.assertEqual(self.s.revision_id("settings"), 0)

    def test_revision_pruning(self):
        import store as store_mod
        old = store_mod.KEEP_REVISIONS
        store_mod.KEEP_REVISIONS = 5
        try:
            for i in range(12):
                self.s.put("known", {"n": i}, "a")
            self.assertEqual(len(self.s.revisions("known", 200)), 5)
            self.assertEqual(self.s.current("known")["content"], {"n": 11})
        finally:
            store_mod.KEEP_REVISIONS = old

    def test_proposal_approve_applies_and_audits(self):
        self.s.put("known", {"noise": []}, "seed")
        base = self.s.revision_id("known")
        pid = self.s.add_proposal("known", {"noise": ["x"]}, "read:claude", "add x", base)
        self.assertEqual(self.s.proposal(pid)["status"], "pending")
        rid = self.s.decide(pid, True, "admin")
        self.assertEqual(self.s.current("known")["content"], {"noise": ["x"]})
        self.assertEqual(self.s.current("known")["id"], rid)
        self.assertIn("approved by admin", self.s.current("known")["author"])
        with self.assertRaises(StoreError):
            self.s.decide(pid, True, "admin")  # mar eldontott
        self.assertTrue(any(a["action"] == "proposal.approve" for a in self.s.audit_list()))

    def test_stale_proposal_needs_force_and_reject_changes_nothing(self):
        self.s.put("known", {"noise": []}, "seed")
        pid = self.s.add_proposal("known", {"noise": ["x"]}, "read", "x", self.s.revision_id("known"))
        self.s.put("known", {"noise": ["other"]}, "admin")  # kozben valtozott
        with self.assertRaises(StoreError) as cm:
            self.s.decide(pid, True, "admin")
        self.assertIn("stale", str(cm.exception))
        self.assertEqual(self.s.current("known")["content"], {"noise": ["other"]})
        self.s.decide(pid, True, "admin", force=True)
        self.assertEqual(self.s.current("known")["content"], {"noise": ["x"]})
        p2 = self.s.add_proposal("known", {"noise": ["y"]}, "read", "y", self.s.revision_id("known"))
        self.s.decide(p2, False, "admin")
        self.assertEqual(self.s.proposal(p2)["status"], "rejected")
        self.assertEqual(self.s.current("known")["content"], {"noise": ["x"]})


class ValidationTests(unittest.TestCase):
    def test_known_ok_and_fixture_ok(self):
        self.assertEqual(aiops.validate_known(FIXTURE), [])
        self.assertEqual(aiops.validate_known({}), [])

    def test_known_errors(self):
        errs = aiops.validate_known({"noise": ["ok", "(unclosed"], "known_issues": [
            {"id": "a", "note": "n", "match": "x"}, {"id": "a", "note": "n", "match": "y"},
            {"id": "", "note": "n", "match": "y"}, {"id": "b", "match": "z"}, {"id": "c", "note": "n", "match": "["}],
            "bogus": 1, "context": "not a list"})
        text = " | ".join(errs)
        for needle in ("noise[1]: invalid regex", "duplicate id 'a'", "'id' is required", "'note' is required",
                       "known_issues[4].match: invalid regex", "bogus: unknown top-level key", "context: must be a list"):
            self.assertIn(needle, text)
        self.assertEqual(aiops.validate_known({"_comment": "free text allowed"}), [])
        self.assertTrue(aiops.validate_known([1]))

    def test_settings_validate(self):
        clean, errs = settings.validate({"NUM_CTX": "4096", "DIGEST_UTC": "07:15", "NOTIFY_MIN_SEVERITY": "high",
                                         "OLLAMA_URLS": "http://a:11434/, http://b:11434"})
        self.assertEqual(errs, [])
        self.assertEqual(clean["NUM_CTX"], 4096)
        self.assertEqual(clean["OLLAMA_URLS"], ["http://a:11434", "http://b:11434"])
        for bad in ({"NUM_CTX": 5}, {"NUM_CTX": True}, {"DIGEST_UTC": "25:00"}, {"NOTIFY_MIN_SEVERITY": "urgent"},
                    {"OLLAMA_URLS": ["ftp://x"]}, {"OLLAMA_URLS": []}, {"HA_WEBHOOK_URL": "http://x"}, {"VL_URL": "http://x"},
                    {"KEEP_ALIVE": "forever"}, {"BACKOFF_MIN": 600, "BACKOFF_MAX": 100}, {"MODEL": " "}):
            self.assertTrue(settings.validate(bad)[1], bad)

    def test_settings_apply_and_restore(self):
        try:
            settings.apply({"NUM_CTX": 4096, "OLLAMA_URLS": ["http://z:1"]})
            self.assertEqual(aiops.CFG["NUM_CTX"], 4096)
            self.assertEqual(aiops.CFG["OLLAMA_URLS"], ["http://z:1"])
            settings.apply({})  # a felulirasok torlese = vissza a kornyezeti alapertekekre
            self.assertEqual(aiops.CFG["NUM_CTX"], aiops.ENV_CFG["NUM_CTX"])
            self.assertEqual(aiops.CFG["OLLAMA_URLS"], aiops.ENV_CFG["OLLAMA_URLS"])
            aiops.CFG["OLLAMA_URLS"].append("x")  # a masolat nem szennyezi az alapertekeket
            self.assertNotIn("x", aiops.ENV_CFG["OLLAMA_URLS"])
        finally:
            reset_cfg()


class PatchTests(unittest.TestCase):
    def test_patch_ops(self):
        doc = {"noise": ["a", "b"], "known_issues": [{"id": "k1", "note": "n", "match": "m"}], "context": ["c"]}
        out = runtime.apply_known_patch(doc, {"add_noise": ["c"], "remove_noise": ["a"], "remove_known_issue_ids": ["k1"],
                                              "add_known_issues": [{"id": "k2", "note": "n2", "match": "m2"}], "set_context": ["new"]})
        self.assertEqual(out["noise"], ["b", "c"])
        self.assertEqual([k["id"] for k in out["known_issues"]], ["k2"])
        self.assertEqual(out["context"], ["new"])
        self.assertEqual(doc["noise"], ["a", "b"])  # az eredeti nem valtozik

    def test_patch_errors(self):
        doc = {"noise": ["a"], "known_issues": []}
        for bad in ({"remove_noise": ["zzz"]}, {"add_noise": ["a"]}, {"remove_known_issue_ids": ["nope"]}, {"bogus": 1}):
            with self.assertRaises(runtime.DocError):
                runtime.apply_known_patch(doc, bad)


class RuntimeTests(unittest.TestCase):
    def tearDown(self):
        reset_cfg()

    def test_bootstrap_from_file_and_default(self):
        rt = runtime.Runtime(Store())
        rt.bootstrap()
        cur = rt.store.current("known")
        self.assertEqual(cur["author"], "seed:file")
        self.assertEqual(cur["content"], FIXTURE)
        old = aiops.CFG["KNOWN_FILE"]
        try:
            aiops.CFG["KNOWN_FILE"] = "/nonexistent/known.json"
            rt2 = runtime.Runtime(Store())
            rt2.bootstrap()
            self.assertEqual(rt2.store.current("known")["author"], "seed:default")
            self.assertEqual(aiops.validate_known(rt2.store.current("known")["content"]), [])
        finally:
            aiops.CFG["KNOWN_FILE"] = old

    def test_bootstrap_is_idempotent(self):
        rt = runtime.Runtime(Store())
        rt.bootstrap()
        n = rt.store.revision_id("known")
        rt.bootstrap()
        self.assertEqual(rt.store.revision_id("known"), n)

    def test_hot_reload_of_known_and_settings(self):
        rt = runtime.Runtime(Store())
        rt.bootstrap()
        k1 = rt.get_known()
        self.assertIs(rt.get_known(), k1)  # valtozas nelkul ugyanaz a peldany
        self.assertEqual(k1.classify_row("homesrv | frobnicate | boom")[0], "keep")
        doc = copy.deepcopy(FIXTURE)
        doc["noise"].append(r"\| frobnicate \|")
        rt.store.put("known", doc, "admin")
        k2 = rt.get_known()
        self.assertIsNot(k2, k1)
        self.assertEqual(k2.classify_row("homesrv | frobnicate | boom")[0], "noise")
        rt.store.put("settings", {"NOTIFY_MIN_SEVERITY": "critical"}, "admin")
        rt.get_known()
        self.assertEqual(aiops.CFG["NOTIFY_MIN_SEVERITY"], "critical")
        rt.store.put("settings", {}, "admin")  # felulirasok torlese
        rt.get_known()
        self.assertEqual(aiops.CFG["NOTIFY_MIN_SEVERITY"], aiops.ENV_CFG["NOTIFY_MIN_SEVERITY"])


class AnalyzeTests(unittest.TestCase):
    RAW = {
        "a": [{"host": "ap", "appname": "hostapd", "severity": "warning", "_msg": "x", "hits": "50"}],
        "b": [{"_HOSTNAME": "homenas2", "SYSLOG_IDENTIFIER": "smartd", "_msg": "Device: x, FAILED SMART self-check", "hits": "3"},
              {"_HOSTNAME": "homesrv", "SYSLOG_IDENTIFIER": "kernel", "_msg": "nfs: server <N> not responding", "hits": "7"}],
        "d": [{"host": "homesrv", "appname": "frobnicate", "_msg": "auth error", "hits": "20"}],
    }

    def test_counts_per_rule(self):
        k = aiops.Known(data=FIXTURE)
        r = aiops.analyze_known(k, self.RAW)
        self.assertEqual(r["rows"], 4)
        self.assertEqual(r["noise_patterns"], 1)
        self.assertEqual(r["noise_lines"], 50)
        self.assertEqual(r["known_patterns"], 1)
        self.assertEqual(r["kept_patterns"], 2)
        self.assertEqual(r["kept_top"][0]["hits"], 20)  # hit szerint rendezve
        hostapd = [n for n in r["noise"] if "hostapd" in n["regex"]][0]
        self.assertEqual(hostapd["lines"], 50)
        self.assertIn(hostapd["index"], range(len(k.noise)))
        self.assertGreater(len(r["unused_noise"]), 30)  # a legtobb szabaly ebben a mintaban nem talal

    def test_candidate_rule_changes_outcome(self):
        doc = copy.deepcopy(FIXTURE)
        doc["noise"].append(r"\| frobnicate \|")
        r = aiops.analyze_known(aiops.Known(data=doc), self.RAW)
        self.assertEqual(r["kept_patterns"], 1)
        self.assertEqual(r["noise_lines"], 70)


class SnoozeTests(unittest.TestCase):
    LINE = "homesrv | frobnicate | auth error"

    def doc(self, until, rx=r"\| frobnicate \|"):
        d = copy.deepcopy(FIXTURE)
        d["snoozes"] = [{"id": "s1", "regex": rx, "until": until}]
        return d

    def fmt(self, hours):
        return aiops.iso(aiops.utcnow().replace(tzinfo=None) + aiops.dt.timedelta(hours=hours))

    def test_active_snooze_acts_as_noise_and_expires(self):
        k = aiops.Known(data=self.doc(self.fmt(2)))
        self.assertEqual(k.classify_idx(self.LINE)[0], "snooze")
        self.assertEqual(k.classify_row(self.LINE), ("noise", None))
        later = aiops.utcnow().replace(tzinfo=None) + aiops.dt.timedelta(hours=3)
        self.assertEqual(k.classify_idx(self.LINE, now=later)[0], "keep")  # lejart: ugyanaz a Known-peldany mar nem nemit

    def test_expired_snooze_does_not_match(self):
        k = aiops.Known(data=self.doc("2020-01-01T00:00:00Z"))
        self.assertEqual(k.classify_idx(self.LINE)[0], "keep")

    def test_validation(self):
        self.assertEqual(aiops.validate_known(self.doc(self.fmt(1))), [])
        self.assertEqual(aiops.validate_known(self.doc("2020-01-01T00:00:00Z")), [])  # a lejart marad ervenyes
        for bad in (self.doc("tomorrow"), self.doc(self.fmt(1), rx="("), self.doc(self.fmt(1), rx="")):
            self.assertTrue(aiops.validate_known(bad))
        dup = self.doc(self.fmt(1))
        dup["snoozes"].append(dict(dup["snoozes"][0]))
        self.assertTrue(any("duplicate" in e for e in aiops.validate_known(dup)))

    def test_patch_add_remove_prune(self):
        d = runtime.apply_known_patch(FIXTURE, {"add_snoozes": [{"regex": "x", "hours": 2, "note": "n"}]})
        self.assertEqual(len(d["snoozes"]), 1)
        sid = d["snoozes"][0]["id"]
        self.assertEqual(aiops.validate_known(d), [])
        d2 = runtime.apply_known_patch(d, {"remove_snooze_ids": [sid]})
        self.assertNotIn("snoozes", d2)
        with self.assertRaises(runtime.DocError):
            runtime.apply_known_patch(d2, {"remove_snooze_ids": ["nope"]})
        old = self.doc("2020-01-01T00:00:00Z")
        pruned = runtime.apply_known_patch(old, {"prune_expired_snoozes": True})
        self.assertNotIn("snoozes", pruned)

    def test_patch_limits(self):
        for bad in ({"regex": "x"}, {"regex": "x", "hours": 0}, {"regex": "x", "hours": 24 * 91},
                    {"regex": "x", "hours": 1, "until": self.fmt(1)}, {"regex": "x", "until": "2020-01-01T00:00:00Z"},
                    {"regex": "x", "hours": True}, {"regex": "x", "hours": 1, "foo": 1}):
            with self.assertRaises(runtime.DocError, msg=str(bad)):
                runtime.apply_known_patch(FIXTURE, {"add_snoozes": [bad]})

    def test_analyze_counts_snoozed_separately(self):
        r = aiops.analyze_known(aiops.Known(data=self.doc(self.fmt(1))), AnalyzeTests.RAW)
        self.assertEqual((r["snoozed_patterns"], r["snoozed_lines"]), (1, 20))
        self.assertEqual(r["kept_patterns"], 1)
        self.assertEqual(r["noise_lines"], 50)


class ApiTests(unittest.TestCase):
    TOK = {"read": "r-token", "admin": "a-token"}
    R = {"Authorization": "Bearer r-token"}
    A = {"Authorization": "Bearer a-token"}

    def setUp(self):
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens=dict(self.TOK)))
        self._collect = aiops.collect
        aiops.collect = lambda t_from, t_to: copy.deepcopy(AnalyzeTests.RAW) | {"c": [], "e": []}

    def tearDown(self):
        aiops.collect = self._collect
        reset_cfg()

    def test_auth(self):
        self.assertEqual(self.c.get("/api/v1/status").status_code, 401)
        self.assertEqual(self.c.get("/api/v1/status", headers={"Authorization": "Bearer nope"}).status_code, 401)
        self.assertEqual(self.c.get("/api/v1/status", headers=self.R).status_code, 200)
        self.assertEqual(self.c.get("/api/v1/audit", headers=self.R).status_code, 403)
        self.assertEqual(self.c.get("/api/v1/audit", headers=self.A).status_code, 200)
        self.assertEqual(self.c.put("/api/v1/config/known", json={"content": {}}, headers=self.R).status_code, 403)
        # nyitott vegpontok (health, a UI statikus fajljai, regi /last JSON)
        self.assertEqual(self.c.get("/api/v1/health").status_code, 200)
        self.assertIn("last_digest", self.c.get("/last").json())

    def test_novelty_endpoints(self):
        self.assertEqual(self.c.get("/api/v1/novelty").status_code, 401)
        st = self.rt.store
        st.nov_add_findings([{"ts": "2026-11-16T06:00:00Z", "kind": "new", "key": "k1", "source": "docker", "host": "h", "ident": "app",
                              "level": "error", "tmpl": "boom <N>", "hits": 3, "baseline": 0},
                             {"ts": "2026-11-16T06:05:00Z", "kind": "spike", "key": "k2", "source": "syslog", "host": "h", "ident": "x",
                              "level": "info", "tmpl": "noisy", "hits": 900, "baseline": 4.5}])
        r = self.c.get("/api/v1/novelty", headers=self.R)
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        self.assertEqual(len(j["findings"]), 2)
        self.assertEqual((j["status"]["open_findings"], j["status"]["mode"] in ("off", "report")), (2, True))
        self.assertEqual(self.c.get("/api/v1/novelty?status=bogus", headers=self.R).status_code, 422)
        fid = j["findings"][0]["id"]
        self.assertEqual(self.c.post(f"/api/v1/novelty/{fid}/dismiss", headers=self.R).status_code, 403)   # olvaso token nem intezhet el
        self.assertEqual(self.c.post(f"/api/v1/novelty/{fid}/dismiss", headers=self.A).status_code, 200)
        self.assertEqual(self.c.post(f"/api/v1/novelty/{fid}/dismiss", headers=self.A).status_code, 404)  # mar elintezett
        self.assertEqual(len(self.c.get("/api/v1/novelty", headers=self.R).json()["findings"]), 1)
        self.assertEqual(len(self.c.get("/api/v1/novelty?status=all", headers=self.R).json()["findings"]), 2)
        self.assertEqual(self.c.post("/api/v1/novelty/dismiss-all", headers=self.A).json()["dismissed"], 1)
        self.assertEqual(self.c.get("/api/v1/novelty", headers=self.R).json()["findings"], [])

    def test_novelty_settings_are_editable(self):
        r = self.c.put("/api/v1/config/settings", headers=self.A, json={"content": {"NOVELTY_MODE": "off", "NOVELTY_SPIKE_FACTOR": 50}})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((aiops.CFG["NOVELTY_MODE"], aiops.CFG["NOVELTY_SPIKE_FACTOR"]), ("off", 50))
        bad = self.c.put("/api/v1/config/settings", headers=self.A, json={"content": {"NOVELTY_MODE": "alert"}})
        self.assertEqual(bad.status_code, 422)

    def test_stats_endpoints(self):
        self.assertEqual(self.c.get("/api/v1/stats/volume").status_code, 401)
        calls = []
        orig_stats, orig_q = aiops.vl_stats_range, aiops.vl_query
        base = int(aiops.utcnow().timestamp()) // 3600 * 3600
        aiops.vl_stats_range = lambda q, a, b, step, timeout=None: (calls.append((q, step)) or
                                                                       [{"metric": {"pipeline": "docker"}, "values": [[base, "42"]]}])
        stats = {"hours": 24, "window_lines": 1000, "candidate_lines": 50, "noise_lines": 20, "kept_patterns": 3}
        aiops.vl_query = lambda q, timeout=None: (calls.append((q, None)) or [
            {"_time": "2026-11-15T06:30:00Z", "kind": "digest", "window": "x..y", "model": "m", "issue_count": "2", "max_severity": "high",
             "all_clear": "false", "dropped_known": "1", "secs": "12.5", "prompt_tokens": "900", "stats": json.dumps(stats)},
            {"_time": "2026-11-14T06:30:00Z", "kind": "digest", "issue_count": "0", "secs": "9", "stats": ""}])
        try:
            v = self.c.get("/api/v1/stats/volume?hours=24&by=pipeline", headers=self.R)
            self.assertEqual(v.status_code, 200, v.text)
            self.assertEqual(v.json()["series"][0]["name"], "docker")
            self.assertEqual(v.json()["total"], 42)
            self.c.get("/api/v1/stats/volume?hours=24&by=pipeline", headers=self.R)
            self.assertEqual(len([c for c in calls if c[1] == "1h"]), 1)  # 60 mp-es gyorsitotar
            self.assertEqual(self.c.get("/api/v1/stats/volume?hours=5", headers=self.R).status_code, 422)
            self.assertEqual(self.c.get("/api/v1/stats/volume?by=message", headers=self.R).status_code, 422)
            r = self.c.get("/api/v1/stats/runs", headers=self.R)
            self.assertEqual(r.status_code, 200, r.text)
            runs = r.json()
            self.assertEqual(runs[0]["stats"]["window_lines"], 1000)
            self.assertEqual((runs[0]["issue_count"], runs[0]["all_clear"], runs[0]["secs"]), (2, False, 12.5))
            self.assertEqual(runs[1]["stats"], {})  # a regi (statisztika nelkuli) futas is megjelenik
            self.assertIn("kind:digest", [c[0] for c in calls if c[1] is None][-1])
            self.assertEqual(self.c.get("/api/v1/stats/runs?kind=bogus", headers=self.R).status_code, 422)
        finally:
            aiops.vl_stats_range, aiops.vl_query = orig_stats, orig_q

    def test_stats_vl_error_is_502(self):
        orig = aiops.vl_query
        def boom(q, timeout=None):
            raise OSError("down")
        aiops.vl_query = boom
        try:
            self.assertEqual(self.c.get("/api/v1/stats/runs", headers=self.R).status_code, 502)
        finally:
            aiops.vl_query = orig

    def test_snooze_endpoints(self):
        body = {"regex": r"\| frobnicate \|", "hours": 2, "note": "noisy upgrade"}
        self.assertEqual(self.c.post("/api/v1/snoozes", json=body, headers=self.R).status_code, 403)
        self.assertEqual(self.c.post("/api/v1/snoozes", json=dict(body, hours=0), headers=self.A).status_code, 422)
        self.assertEqual(self.c.post("/api/v1/snoozes", json=dict(body, regex="("), headers=self.A).status_code, 422)
        r = self.c.post("/api/v1/snoozes", json=body, headers=self.A)
        self.assertEqual(r.status_code, 200, r.text)
        sid = r.json()["snooze"]["id"]
        lst = self.c.get("/api/v1/snoozes", headers=self.R).json()
        self.assertEqual([(s["id"], s["active"]) for s in lst], [(sid, True)])
        self.assertTrue(7000 < lst[0]["remaining_s"] <= 7200)
        # hat a futo Known-ra is: a regex-teszt mar nem latja a sort a megmaradtak kozott
        t = self.c.post("/api/v1/test/known", json={"hours": 24}, headers=self.R).json()
        self.assertEqual(t["snoozed_lines"], 20)
        # olvaso token: javaslat
        p = self.c.post("/api/v1/proposals", json={"key": "known", "comment": "snooze",
                                                    "patch": {"add_snoozes": [{"regex": "zzz", "hours": 1}]}}, headers=self.R)
        self.assertEqual(p.status_code, 200, p.text)
        self.assertEqual(self.c.delete(f"/api/v1/snoozes/{sid}", headers=self.R).status_code, 403)
        self.assertEqual(self.c.delete("/api/v1/snoozes/nope", headers=self.A).status_code, 404)
        self.assertEqual(self.c.delete(f"/api/v1/snoozes/{sid}", headers=self.A).status_code, 200)
        self.assertEqual(self.c.get("/api/v1/snoozes", headers=self.R).json(), [])

    def test_ui_static_files_and_headers(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/html", r.headers["content-type"])
        self.assertIn("script-src 'self'", r.headers["content-security-policy"])
        self.assertIn("frame-ancestors 'none'", r.headers["content-security-policy"])
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertIn("/ui/app.js", r.text)
        js = self.c.get("/ui/app.js")
        self.assertEqual((js.status_code, js.headers["content-type"].split(";")[0]), (200, "text/javascript"))
        self.assertEqual(self.c.get("/ui/app.css").status_code, 200)
        for bad in ("/ui/index.html", "/ui/console.py", "/ui/../console.py", "/ui/%2e%2e/console.py"):
            self.assertEqual(self.c.get(bad).status_code, 404, bad)
        # a UI-fajlok nem tartalmaznak titkot / nem hasznalnak innerHTML-t (XSS-vedelem: csak textContent / DOM-epites)
        self.assertNotIn("innerHTML", js.text)
        self.assertNotIn("eval(", js.text)

    def test_whoami_and_diff_endpoints(self):
        self.assertEqual(self.c.get("/api/v1/whoami", headers=self.R | {"X-Actor": "bob"}).json(), {"role": "read", "actor": "read:bob"})
        self.assertEqual(self.c.get("/api/v1/whoami", headers=self.A).json()["role"], "admin")
        self.assertEqual(self.c.get("/api/v1/whoami").status_code, 401)
        doc = copy.deepcopy(FIXTURE)
        doc["noise"].append("zzz-new")
        d = self.c.post("/api/v1/config/known/diff", json={"content": doc}, headers=self.R).json()
        self.assertTrue(d["changed"])
        self.assertIn('+  "zzz-new"', d["diff"])
        same_doc = self.c.post("/api/v1/config/known/diff", json={"content": FIXTURE}, headers=self.R).json()
        self.assertEqual((same_doc["changed"], same_doc["diff"]), (False, ""))
        # visszaallitas-elonezet: jelenlegi -> regi verzio
        first = self.c.get("/api/v1/config/known/revisions", headers=self.R).json()[0]["id"]
        self.c.put("/api/v1/config/known", json={"content": doc, "comment": "add"}, headers=self.A)
        rd = self.c.get(f"/api/v1/config/known/revisions/{first}/diff", headers=self.R).json()
        self.assertTrue(rd["changed"])
        self.assertIn('-  "zzz-new"', rd["diff"])
        self.assertEqual(self.c.get("/api/v1/config/known/revisions/9999/diff", headers=self.R).status_code, 404)
        self.assertEqual(self.c.post("/api/v1/config/nope/diff", json={"content": {}}, headers=self.R).status_code, 404)

    def test_no_tokens_configured_is_503(self):
        c = TestClient(console.create_app(self.rt, tokens={"read": "", "admin": ""}))
        self.assertEqual(c.get("/api/v1/status", headers=self.A).status_code, 503)
        self.assertEqual(c.get("/api/v1/health").status_code, 200)

    def test_config_get_put_validate_revisions_rollback(self):
        g = self.c.get("/api/v1/config/known", headers=self.R).json()
        self.assertEqual(g["content"], FIXTURE)
        doc = copy.deepcopy(FIXTURE)
        doc["noise"].append(r"\| frobnicate \|")
        r = self.c.put("/api/v1/config/known", json={"content": doc, "comment": "frobnicate"}, headers=self.A | {"X-Actor": "addam"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["changed"])
        self.assertEqual(self.rt.get_known().classify_row("homesrv | frobnicate | x")[0], "noise")  # azonnal ervenyes
        self.assertFalse(self.c.put("/api/v1/config/known", json={"content": doc}, headers=self.A).json()["changed"])  # nincs valtozas = nincs uj verzio
        bad = self.c.put("/api/v1/config/known", json={"content": {"noise": ["("]}}, headers=self.A)
        self.assertEqual(bad.status_code, 422)
        self.assertIn("invalid regex", bad.json()["detail"]["errors"][0])
        revs = self.c.get("/api/v1/config/known/revisions", headers=self.R).json()
        self.assertEqual(len(revs), 2)
        self.assertEqual(revs[0]["author"], "admin:addam")
        rb = self.c.post(f"/api/v1/config/known/rollback/{revs[1]['id']}", headers=self.A)
        self.assertEqual(rb.status_code, 200)
        self.assertEqual(self.rt.get_known().classify_row("homesrv | frobnicate | x")[0], "keep")
        self.assertEqual(self.c.get("/api/v1/config/nope", headers=self.R).status_code, 404)
        self.assertEqual(self.c.get("/api/v1/config/known/revisions/99999", headers=self.R).status_code, 404)

    def test_raw_export(self):
        r = self.c.get("/api/v1/config/known?raw=true", headers=self.R)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(json.loads(r.text), FIXTURE)
        self.assertEqual(json.loads(self.c.get("/api/v1/config/settings?raw=true", headers=self.R).text), {})

    def test_settings_roundtrip_and_effect(self):
        g = self.c.get("/api/v1/config/settings", headers=self.R).json()
        self.assertEqual(g["content"], {})
        self.assertIn("NUM_CTX", [s["key"] for s in g["spec"]])
        self.assertNotIn("HA_WEBHOOK_URL", [s["key"] for s in g["spec"]])  # titok: nem szerkesztheto
        r = self.c.put("/api/v1/config/settings", json={"content": {"NOTIFY_MIN_SEVERITY": "high", "DIGEST_UTC": "07:00"}}, headers=self.A)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(aiops.CFG["NOTIFY_MIN_SEVERITY"], "high")
        self.assertEqual(self.c.get("/api/v1/status", headers=self.R).json()["settings"]["DIGEST_UTC"], "07:00")
        self.assertEqual(self.c.put("/api/v1/config/settings", json={"content": {"HA_WEBHOOK_URL": "http://x"}}, headers=self.A).status_code, 422)

    def test_proposal_flow(self):
        p = self.c.post("/api/v1/proposals", json={"key": "known", "comment": "silence frobnicate", "patch": {"add_noise": [r"\| frobnicate \|"]}},
                        headers=self.R | {"X-Actor": "claude"})
        self.assertEqual(p.status_code, 200)
        pid = p.json()["id"]
        self.assertIn('+  "\\\\| frobnicate \\\\|"', p.json()["diff"])
        self.assertEqual(self.rt.get_known().classify_row("homesrv | frobnicate | x")[0], "keep")  # javaslat nem valtoztat
        lst = self.c.get("/api/v1/proposals?status=pending", headers=self.R).json()
        self.assertEqual([x["id"] for x in lst], [pid])
        self.assertEqual(lst[0]["author"], "read:claude")
        self.assertEqual(self.c.post(f"/api/v1/proposals/{pid}/approve", headers=self.R).status_code, 403)  # a read token nem hagyhat jova
        ok = self.c.post(f"/api/v1/proposals/{pid}/approve", headers=self.A)
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(self.rt.get_known().classify_row("homesrv | frobnicate | x")[0], "noise")
        self.assertEqual(self.c.post(f"/api/v1/proposals/{pid}/approve", headers=self.A).status_code, 409)  # mar eldontott

    def test_proposal_stale_and_reject_and_invalid(self):
        p = self.c.post("/api/v1/proposals", json={"key": "known", "comment": "a", "patch": {"add_noise": ["aaa"]}}, headers=self.R).json()["id"]
        self.c.put("/api/v1/config/settings", json={"content": {"NUM_CTX": 4096}}, headers=self.A)  # mas kulcs: nem avitja el
        self.assertFalse(self.c.get(f"/api/v1/proposals/{p}", headers=self.R).json()["stale"])
        doc = copy.deepcopy(FIXTURE)
        doc["noise"].append("bbb")
        self.c.put("/api/v1/config/known", json={"content": doc}, headers=self.A)  # ez elavitja
        self.assertTrue(self.c.get(f"/api/v1/proposals/{p}", headers=self.R).json()["stale"])
        self.assertEqual(self.c.post(f"/api/v1/proposals/{p}/approve", headers=self.A).status_code, 409)
        self.assertEqual(self.c.post(f"/api/v1/proposals/{p}/reject", headers=self.A).status_code, 200)
        for body in ({"key": "known", "comment": "x"},  # se content, se patch
                     {"key": "known", "comment": "x", "patch": {"add_noise": ["("]}},  # ervenytelen regex
                     {"key": "known", "comment": "x", "patch": {"remove_noise": ["no-such"]}},
                     {"key": "known", "comment": "x", "patch": {"add_noise": ["bbb"]}},  # mar benne van
                     {"key": "settings", "comment": "x", "patch": {"NUM_CTX": 1}}):
            self.assertEqual(self.c.post("/api/v1/proposals", json=body, headers=self.R).status_code, 422, body)

    def test_settings_proposal_patch_merge_and_delete(self):
        self.c.put("/api/v1/config/settings", json={"content": {"NUM_CTX": 4096, "MODEL": "m"}}, headers=self.A)
        pid = self.c.post("/api/v1/proposals", json={"key": "settings", "comment": "c", "patch": {"NUM_CTX": None, "NOTIFY_DIGEST": "issues"}},
                          headers=self.R).json()["id"]
        self.c.post(f"/api/v1/proposals/{pid}/approve", headers=self.A)
        self.assertEqual(self.c.get("/api/v1/config/settings", headers=self.R).json()["content"], {"MODEL": "m", "NOTIFY_DIGEST": "issues"})

    def test_regex_test_endpoint(self):
        base = self.c.post("/api/v1/test/known", json={"hours": 24}, headers=self.R).json()
        self.assertEqual(base["kept_patterns"], 2)
        cand = self.c.post("/api/v1/test/known", json={"hours": 24, "patch": {"add_noise": [r"\| frobnicate \|"]}}, headers=self.R).json()
        self.assertEqual(cand["kept_patterns"], 1)
        self.assertEqual(cand["baseline"]["kept_patterns"], 2)
        self.assertEqual(self.c.post("/api/v1/test/known", json={"hours": 0}, headers=self.R).status_code, 422)
        self.assertEqual(self.c.post("/api/v1/test/known", json={"content": {}, "patch": {}}, headers=self.R).status_code, 422)
        self.assertEqual(self.c.post("/api/v1/test/known", json={"patch": {"add_noise": ["("]}}, headers=self.R).status_code, 422)

        def boom(a, b):
            raise OSError("VL down")
        aiops.collect = boom
        self.rt._raw.clear()
        self.assertEqual(self.c.post("/api/v1/test/known", json={"hours": 24}, headers=self.R).status_code, 502)

    def test_jobs_queue_commands(self):
        self.assertEqual(self.c.post("/api/v1/jobs/digest", json={"hours": 6}, headers=self.R).status_code, 403)
        self.assertEqual(self.c.post("/api/v1/jobs/digest", json={"hours": 6}, headers=self.A).json(), {"queued": True, "hours": 6})
        self.assertEqual(aiops.COMMANDS.get_nowait(), {"cmd": "digest", "hours": 6})
        self.assertEqual(self.c.post("/api/v1/jobs/digest", json={"hours": 999}, headers=self.A).status_code, 422)
        self.assertEqual(self.c.post("/api/v1/jobs/notify-test", headers=self.A).status_code, 409)  # nincs webhook
        aiops.CFG["HA_WEBHOOK_URL"] = "http://ha.invalid/api/webhook/x"
        self.assertEqual(self.c.post("/api/v1/jobs/notify-test", headers=self.A).status_code, 200)
        self.assertEqual(aiops.COMMANDS.get_nowait(), {"cmd": "notify-test"})

    def test_status_content(self):
        s = self.c.get("/api/v1/status", headers=self.R).json()
        for k in ("started", "pending", "endpoints", "config", "settings", "notify_configured", "next_digest_utc"):
            self.assertIn(k, s)
        self.assertFalse(s["notify_configured"])
        self.assertNotIn("HA_WEBHOOK_URL", json.dumps(s))  # a webhook-cim (titok) nem szivarog


class CommandTests(unittest.TestCase):
    def tearDown(self):
        reset_cfg()

    def test_digest_command_enqueues_manual_job(self):
        state = {"pending": []}
        aiops.COMMANDS.put({"cmd": "digest", "hours": 6})
        aiops.handle_commands(state)
        self.assertEqual(len(state["pending"]), 1)
        j = state["pending"][0]
        self.assertEqual((j["kind"], j["manual"]), ("digest", True))
        t0, t1 = aiops.parse_vl_time(j["window_from"]), aiops.parse_vl_time(j["window_to"])
        self.assertEqual(int((t1 - t0).total_seconds()), 6 * 3600)

    def test_notify_test_command_without_webhook_records_failure(self):
        aiops.COMMANDS.put({"cmd": "notify-test"})
        aiops.handle_commands({"pending": []})
        self.assertFalse(aiops.STATUS["last_command"]["ok"])

    def test_queue_empty_is_fine(self):
        aiops.handle_commands({"pending": []})


if __name__ == "__main__":
    unittest.main()
