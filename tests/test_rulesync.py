"""Szabaly-kiadas (rulesync.py) hamis vmalerttel: fajlirás, reload, ellenorzes, visszaallitas, API.
Futtatas (a stacks/aiops-console mappabol): python3 -m unittest discover -s tests
"""
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import unittest
from _base import IsolatedTestCase
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402
import console  # noqa: E402
import rules  # noqa: E402
import rulesync  # noqa: E402
import runtime  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from store import Store  # noqa: E402


class FakeVmalert:
    """A vmalert viselkedese: /-/reload beolvassa a mappa *.yml fajljait; 'BadRule' tartalmu fajl = sikertelen reload (a regi szabalyok maradnak)."""

    def __init__(self, folder):
        self.folder, self.groups, self.ok, self.reloads = folder, {}, 1, 0
        self.external = {"logstack-events": ["KumaMonitorDown"]}
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype="application/json"):
                data = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                if self.path == "/-/reload":
                    outer.reload()
                    return self._send(200, "")
                self._send(404, "")

            def do_GET(self):
                if self.path == "/metrics":
                    return self._send(200, f"# x\nvmalert_config_last_reload_successful {outer.ok}\n", "text/plain")
                if self.path == "/api/v1/rules":
                    groups = [{"name": n, "file": "/x/" + n, "rules": [{"name": r, "health": "ok", "state": "inactive", "lastError": ""} for r in rs]}
                              for n, rs in {**outer.external, **outer.groups}.items()]
                    return self._send(200, json.dumps({"status": "success", "data": {"groups": groups}}))
                self._send(404, "")

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def reload(self):
        self.reloads += 1
        groups = {}
        for fn in sorted(os.listdir(self.folder)):
            if not fn.endswith(".yml"):
                continue
            text = open(os.path.join(self.folder, fn), encoding="utf-8").read()
            if "BadRule" in text:
                self.ok = 0
                return
            cur = None
            for line in text.splitlines():
                m = re.match(r'\s+- name: "(.+)"', line)
                if m:
                    cur = groups.setdefault(m.group(1), [])
                m = re.match(r"\s+- alert: (\S+)", line)
                if m and cur is not None:
                    cur.append(m.group(1))
        self.groups, self.ok = groups, 1

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def rule(**kw):
    r = {"id": "ContainerLogFlood", "kind": "count", "query": "pipeline:docker", "group_by": ["host"], "threshold": 5, "window_min": 1}
    r.update(kw)
    return r


class SyncCase(IsolatedTestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.vm = FakeVmalert(self.dir)
        self.saved = (dict(aiops.CFG), aiops.vl_query, rulesync.FAIL_FAST_S, rulesync.POLL_S)
        aiops.CFG.update(VMALERT_URL=self.vm.url, RULES_DIR=self.dir, RULES_SYNC="on", RULES_SYNC_TIMEOUT_S=5)
        rulesync.FAIL_FAST_S, rulesync.POLL_S = 0, 0.05
        self.queries = []
        aiops.vl_query = lambda q, timeout=None, **kw: self.queries.append((q, kw)) or []
        self.path = os.path.join(self.dir, rules.FILE_NAME)

    def tearDown(self):
        aiops.CFG.clear()
        aiops.CFG.update(self.saved[0])
        aiops.vl_query, rulesync.FAIL_FAST_S, rulesync.POLL_S = self.saved[1:]
        self.vm.stop()
        shutil.rmtree(self.dir, ignore_errors=True)


class ApplyTests(SyncCase):
    def test_off_or_unconfigured_does_nothing(self):
        aiops.CFG["RULES_SYNC"] = "off"
        st = rulesync.apply({"rules": [rule()]}, 3)
        self.assertEqual(st["state"], "off")
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(self.vm.reloads, 0)
        aiops.CFG.update(RULES_SYNC="on", RULES_DIR="")
        self.assertEqual(rulesync.apply({"rules": [rule()]}, 3)["state"], "off")

    def test_apply_writes_reloads_and_verifies(self):
        doc = {"rules": [rule(), rule(id="Slow", interval_min=5, window_min=5)]}
        st = rulesync.apply(doc, 4)
        self.assertEqual((st["state"], st["applied_rev"], st["rules"]), ("ok", 4, 2), st)
        self.assertEqual(open(self.path, encoding="utf-8").read(), rules.render(doc, 4)["files"][rules.FILE_NAME])
        self.assertEqual(sorted(self.vm.groups), ["aiops-console-1m", "aiops-console-5m"])
        self.assertEqual(self.vm.reloads, 1)
        self.assertEqual([f for f in os.listdir(self.dir)], [rules.FILE_NAME])        # nincs ideiglenes fajl
        self.assertEqual(len(self.queries), 2)                                          # a szaraz futtatas minden szabalyra lefutott
        self.assertTrue(self.queries[0][0].startswith("_time:1m (pipeline:docker)"))

    def test_second_apply_of_the_same_revision_is_a_no_op_unless_forced(self):
        doc = {"rules": [rule()]}
        rulesync.apply(doc, 4)
        st = rulesync.apply(doc, 4)
        self.assertEqual((st["state"], st["message"]), ("ok", "already in sync"))
        self.assertEqual(self.vm.reloads, 1)
        rulesync.apply(doc, 4, force=True)
        self.assertEqual(self.vm.reloads, 2)

    def test_disabling_all_rules_removes_the_file(self):
        rulesync.apply({"rules": [rule()]}, 1)
        st = rulesync.apply({"rules": [rule(enabled=False)]}, 2)
        self.assertEqual(st["state"], "ok", st)
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(self.vm.groups, {})

    def test_invalid_document_is_not_applied(self):
        st = rulesync.apply({"rules": [rule(query="a | b")]}, 2)
        self.assertEqual(st["state"], "error")
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(self.vm.reloads, 0)

    def test_victorialogs_rejection_stops_the_apply_before_any_write(self):
        def reject(q, timeout=None, **kw):
            raise urllib.error.HTTPError("http://vl", 400, "Bad Request", {}, None)
        aiops.vl_query = reject
        st = rulesync.apply({"rules": [rule()]}, 2)
        self.assertEqual(st["state"], "error")
        self.assertIn("rejected the expression", st["message"])
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(self.vm.reloads, 0)

    def test_victorialogs_down_stops_the_apply(self):
        def down(q, timeout=None, **kw):
            raise urllib.error.URLError("refused")
        aiops.vl_query = down
        st = rulesync.apply({"rules": [rule()]}, 2)
        self.assertEqual(st["state"], "error")
        self.assertIn("not reachable", st["message"])
        self.assertFalse(os.path.exists(self.path))

    def test_slow_dry_run_is_an_error(self):              # alpha.30 (audit M3): egy percenkent futo, 20 mp-nel lassabb szabaly nem mehet ki
        def slow(q, timeout=None, **kw):
            raise TimeoutError("slow")
        aiops.vl_query = slow
        st = rulesync.apply({"rules": [rule()]}, 2)
        self.assertEqual(st["state"], "error")
        self.assertIn("dry run took over", st["message"])
        self.assertFalse(os.path.exists(self.path))

    def test_dry_run_is_time_bounded_and_row_limited(self):
        doc = {"rules": [rule(), {"id": "Raw", "kind": "raw", "interval_min": 5, "expr": "a | stats count() as n"},
                         {"id": "Quiet", "kind": "silence", "query": "pipeline:syslog", "group_by": ["host"], "window_min": 15}]}
        rulesync.apply(doc, 3)
        spans = [round((kw["end"] - kw["start"]).total_seconds() / 60) for _, kw in self.queries]
        self.assertEqual(spans, [1, 5, 24 * 60])                     # count: window, raw: interval, silence: history
        self.assertTrue(all(q.endswith(f"| limit {rulesync.DRY_MAX_SERIES + 1}") and kw["max_bytes"] for q, kw in self.queries))

    def test_too_many_result_rows_is_an_alert_flood(self):
        aiops.vl_query = lambda q, timeout=None, **kw: [{"hits": 1}] * (rulesync.DRY_MAX_SERIES + 1)
        st = rulesync.apply({"rules": [rule()]}, 2)
        self.assertEqual(st["state"], "error")
        self.assertIn("alert flood", st["message"])

    def test_failed_reload_restores_the_previous_file_and_keeps_the_old_state(self):
        good = {"rules": [rule()]}
        rulesync.apply(good, 1)
        before = open(self.path, encoding="utf-8").read()
        st = rulesync.apply({"rules": [rule(), rule(id="BadRule")]}, 2)
        self.assertEqual(st["state"], "error", st)
        self.assertEqual(st["applied_rev"], 1)                      # a kiadott revizio nem lepett elore
        self.assertIn("previous file was restored", st["message"])
        self.assertEqual(open(self.path, encoding="utf-8").read(), before)
        self.assertEqual(self.vm.ok, 1)                              # a visszaallitas utan a vmalert ujra rendben
        self.assertEqual(self.vm.groups, {"aiops-console-1m": ["ContainerLogFlood"]})

    def test_failed_first_apply_removes_the_new_file(self):
        st = rulesync.apply({"rules": [rule(id="BadRule")]}, 1)
        self.assertEqual(st["state"], "error")
        self.assertFalse(os.path.exists(self.path))

    def test_unwritable_folder_is_an_error(self):
        aiops.CFG["RULES_DIR"] = os.path.join(self.dir, "missing")
        st = rulesync.apply({"rules": [rule()]}, 1)
        self.assertEqual(st["state"], "error")
        self.assertEqual(self.vm.reloads, 0)

    def test_vmalert_unreachable_restores(self):
        rulesync.apply({"rules": [rule()]}, 1)
        before = open(self.path, encoding="utf-8").read()
        self.vm.stop()
        aiops.CFG["RULES_SYNC_TIMEOUT_S"] = 5
        st = rulesync.apply({"rules": [rule(), rule(id="Other")]}, 2)
        self.assertEqual(st["state"], "error")
        self.assertEqual(open(self.path, encoding="utf-8").read(), before)
        self.vm = FakeVmalert(self.dir)                              # a tearDown-nak legyen mit leallitania


class KickAndApiTests(SyncCase):
    R = {"Authorization": "Bearer r-token"}
    A = {"Authorization": "Bearer a-token"}

    def setUp(self):
        super().setUp()
        self.env_saved = aiops.ENV_CFG["RULES_SYNC"]
        aiops.ENV_CFG["RULES_SYNC"] = "on"          # a Runtime.bootstrap a beallitasokat az env-alapertekekre allitja vissza
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))

    def tearDown(self):
        # a hatterszal ne fusson at a kovetkezo tesztbe (2026-11-27: egy atfuto szal a regi tarba irta az auditot, a CI-ben idonkent elbukott)
        end = time.monotonic() + 10
        while rulesync._worker["thread"] is not None and time.monotonic() < end:
            time.sleep(0.05)
        aiops.ENV_CFG["RULES_SYNC"] = self.env_saved
        super().tearDown()

    def wait(self, state, timeout=5):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if rulesync.status()["state"] == state and rulesync._worker["thread"] is None:
                return
            time.sleep(0.05)
        self.fail(f"state {rulesync.status()}")

    def test_saving_a_revision_applies_it_in_the_background_and_audits(self):
        r = self.c.put("/api/v1/config/rules", headers=self.A, json={"content": {"rules": [rule()]}, "comment": "x"})
        self.assertEqual(r.status_code, 200, r.text)
        self.wait("ok")
        self.assertEqual(rulesync.status()["applied_rev"], r.json()["rev"])
        self.assertTrue(os.path.exists(self.path))
        self.assertTrue(any(a["action"] == "rules-sync" and a["actor"] == "system" for a in self.rt.store.audit_list(20)))

    def test_running_worker_switches_to_the_new_store(self):
        # egy mar futo szal (pl. az elozo Runtime-e) a legutobb atadott tarat hasznalja
        other = Store()
        rulesync._worker["store"] = other
        r = self.c.put("/api/v1/config/rules", headers=self.A, json={"content": {"rules": [rule()]}, "comment": "x"})
        self.wait("ok")
        self.assertEqual(rulesync._worker["store"], self.rt.store)
        self.assertEqual(rulesync.status()["applied_rev"], r.json()["rev"])
        self.assertFalse(other.audit_list(20))

    def test_status_api_shows_state_and_the_live_vmalert_groups(self):
        self.c.put("/api/v1/config/rules", headers=self.A, json={"content": {"rules": [rule()]}})
        self.wait("ok")
        j = self.c.get("/api/v1/rules/sync", headers=self.R).json()
        self.assertEqual((j["state"], j["configured"], j["sync"]), ("ok", True, "on"))
        self.assertEqual([(x["group"], x["rule"], x["health"]) for x in j["vmalert"]], [("aiops-console-1m", "ContainerLogFlood", "ok")])   # a kulso csoport nincs benne
        self.assertEqual(self.c.get("/api/v1/status", headers=self.R).json()["rules_sync"]["state"], "ok")
        self.assertEqual(self.c.get("/api/v1/rules/sync").status_code, 401)

    def test_turning_the_setting_on_applies_the_saved_revision(self):
        self.assertEqual(self.c.put("/api/v1/config/settings", headers=self.A, json={"content": {"RULES_SYNC": "off"}}).status_code, 200)
        self.c.put("/api/v1/config/rules", headers=self.A, json={"content": {"rules": [rule()]}})
        self.wait("off")
        self.assertFalse(os.path.exists(self.path))
        r = self.c.put("/api/v1/config/settings", headers=self.A, json={"content": {"RULES_SYNC": "on"}})
        self.assertEqual(r.status_code, 200, r.text)
        self.wait("ok")
        self.assertTrue(os.path.exists(self.path))

    def test_manual_resync_needs_admin_and_an_enabled_sync(self):
        self.assertEqual(self.c.post("/api/v1/rules/sync", headers=self.R).status_code, 403)
        aiops.CFG["RULES_SYNC"] = "off"
        self.assertEqual(self.c.post("/api/v1/rules/sync", headers=self.A).status_code, 409)
        aiops.CFG["RULES_SYNC"] = "on"
        self.c.put("/api/v1/config/rules", headers=self.A, json={"content": {"rules": [rule()]}})
        self.wait("ok")
        n = self.vm.reloads
        self.assertEqual(self.c.post("/api/v1/rules/sync", headers=self.A).json(), {"requested": True})
        end = time.monotonic() + 5
        while self.vm.reloads == n and time.monotonic() < end:
            time.sleep(0.05)
        self.assertEqual(self.vm.reloads, n + 1)

    def test_setting_is_validated(self):
        self.assertEqual(self.c.put("/api/v1/config/settings", headers=self.A, json={"content": {"RULES_SYNC": "maybe"}}).status_code, 422)
        self.assertEqual(self.c.put("/api/v1/config/settings", headers=self.A, json={"content": {"VMALERT_URL": "http://x"}}).status_code, 422)


if __name__ == "__main__":
    unittest.main()
