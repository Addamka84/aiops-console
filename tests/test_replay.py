"""alpha.39: visszajatszas es osszevetes - munkaleiras mentese/visszaallitasa, run_job replay-modja, API."""
import datetime as dt
import json
import os
import sys
import time
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)
os.environ.setdefault("KNOWN_FILE", os.path.join(HERE, "fixtures", "known.json"))

import aiops  # noqa: E402
import console  # noqa: E402
import runtime  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from store import Store  # noqa: E402
from test_aiops import make_ollama, make_vl, start  # noqa: E402

DET = {"id": "nfs", "mode": "count", "group": {"host": "homesrv"}, "window_min": 15, "severity": "high"}
JOB = {"kind": "incident", "key": "JournaldCritical|homesrv", "alert_text": "[FIRING] JournaldCritical x1 homesrv / systemd",
       "items": [{"text": "[FIRING] JournaldCritical x1 homesrv / systemd token=abc123secretvalue",
                  "alert_labels": [{"alertname": "JournaldCritical", "host": "homesrv", "SYSLOG_IDENTIFIER": "systemd"}], "detector": None},
                 {"text": "[DETECTOR] nfs", "alert_labels": [], "detector": DET}],
       "correlation": {"root": "homesrv", "cis": ["homesrv"], "confidence": 1.0}}


def head(**kw):
    h = {"kind": "incident", "id": "incident-2026-11-25T10:30:57Z", "window": "2026-11-25T10:00:00Z..2026-11-25T10:30:00Z",
         "alert": "[FIRING] JournaldCritical x1 homesrv / systemd"}
    h.update(kw)
    return h


class JobMetaTests(IsolatedTestCase):
    def test_roundtrip(self):
        meta = aiops.job_meta(JOB)
        self.assertNotIn("abc123secretvalue", meta)                       # a riasztas szovege is redaktalva
        job, notes = aiops.job_from_head(head(job=meta))
        self.assertEqual(notes, [])
        self.assertEqual((job["window_from"], job["window_to"]), ("2026-11-25T10:00:00Z", "2026-11-25T10:30:00Z"))
        self.assertEqual(job["items"][0]["alert_labels"], JOB["items"][0]["alert_labels"])
        self.assertEqual(job["items"][1]["detector"], DET)
        self.assertEqual(job["alert_labels"], JOB["items"][0]["alert_labels"])
        self.assertEqual(job["correlation"]["root"], "homesrv")
        self.assertEqual(job["key"], "JournaldCritical|homesrv")

    def test_single_detector_item_backward_shape(self):
        job, _ = aiops.job_from_head(head(job=aiops.job_meta({"items": [{"text": "d", "alert_labels": [], "detector": DET}]})))
        self.assertEqual(job["detector"], DET)

    def test_too_long_is_shortened(self):
        big = dict(DET, query="x" * 9000)
        meta = aiops.job_meta({"items": [{"text": "t", "alert_labels": [{"host": "h"}], "detector": big}]})
        self.assertLessEqual(len(meta), aiops.JOB_META_MAX)
        job, notes = aiops.job_from_head(head(job=meta))
        self.assertIsNone(job["items"][0]["detector"])
        self.assertEqual(job["items"][0]["alert_labels"], [{"host": "h"}])
        self.assertTrue(notes)

    def test_old_head_without_meta(self):
        job, notes = aiops.job_from_head(head(alert_items=json.dumps(["a1", "a2"])))
        self.assertEqual([i["text"] for i in job["items"]], ["a1", "a2"])
        self.assertEqual(job["alert_labels"], [])
        self.assertIn("before alpha.39", notes[0])

    def test_old_head_correlation_recomputed_from_topology(self):
        import topology
        old = aiops.TOPOLOGY
        aiops.TOPOLOGY = topology.Topology({"assets": [
            {"id": "esx-02", "kind": "host"},
            {"id": "vm-app-04", "kind": "vm", "runs_on": "esx-02"}, {"id": "vm-app-06", "kind": "vm", "runs_on": "esx-02"}]})
        try:
            job, notes = aiops.job_from_head(head(alert_items=json.dumps(["esx-02 down", "vm-app-04 unreachable", "vm-app-06 unreachable"])))
        finally:
            aiops.TOPOLOGY = old
        self.assertEqual(job["correlation"]["root"], "esx-02")
        self.assertTrue(any("recomputed" in n for n in notes))

    def test_digest(self):
        job, notes = aiops.job_from_head({"kind": "digest", "window": "2026-11-24T06:30:00Z..2026-11-25T06:30:00Z"})
        self.assertEqual(job["kind"], "digest")
        self.assertNotIn("items", job)

    def test_bad_window_or_kind(self):
        with self.assertRaises(aiops.ReplayError):
            aiops.job_from_head(head(window="a..b"))
        with self.assertRaises(aiops.ReplayError):
            aiops.job_from_head({"kind": "heartbeat", "window": "2026-11-24T06:30:00Z..2026-11-25T06:30:00Z"})


class RunJobReplayTests(IsolatedTestCase):
    def setUp(self):
        aiops.CFG.update(PROBE_TIMEOUT=1, GEN_TIMEOUT=5, BACKOFF_MIN=2, BACKOFF_MAX=8)
        self.saved_url = aiops.CFG["VL_URL"]
        self.rows = {"pipeline:syslog": [{"host": "homesrv", "appname": "kernel", "severity": "err", "_msg": "nfs: server not responding", "hits": "4"}],
                     "appname:in(kuma,alert)": [], "Linux version": []}

    def tearDown(self):
        aiops.CFG["VL_URL"] = self.saved_url

    def test_no_insert_model_override_result_returned(self):
        inserts, calls = [], []
        content = {"summary": "NFS trouble", "all_clear": False, "issues": [
            {"id": "n", "title": "NFS server unresponsive", "severity": "medium", "status": "ongoing", "known_issue": False, "hosts": ["homesrv"],
             "evidence": "not responding", "likely_cause": "NAS", "suggested_action": "check"}]}
        vl, vl_url = start(make_vl(self.rows, inserts))
        ol, ol_url = start(make_ollama(models=("qwen3.5:9b", "qwen3.8:27b"), chat_content=content, calls=calls))
        before = dict(aiops.STATUS)
        try:
            aiops.CFG["VL_URL"] = vl_url
            job = {"kind": "digest", "window_from": "2026-11-12T00:00:00Z", "window_to": "2026-11-13T00:00:00Z"}
            res = aiops.run_job(job, aiops.Known(), aiops.EndpointPool([ol_url], "qwen3.8:27b"), model="qwen3.8:27b", replay=True)
        finally:
            vl.shutdown()
            ol.shutdown()
        self.assertEqual(inserts, [])
        self.assertEqual(res["model"], "qwen3.8:27b")
        self.assertEqual([i["title"] for i in res["issues"]], ["NFS server unresponsive"])
        chat = [c for c in calls if c[0] == "POST"][0][2]
        self.assertEqual(chat["model"], "qwen3.8:27b")
        self.assertEqual(aiops.STATUS.get("last_digest"), before.get("last_digest"))

    def test_missing_model_raises(self):
        vl, vl_url = start(make_vl(self.rows, []))
        ol, ol_url = start(make_ollama(models=("qwen3.5:9b",)))
        try:
            aiops.CFG["VL_URL"] = vl_url
            job = {"kind": "digest", "window_from": "2026-11-12T00:00:00Z", "window_to": "2026-11-13T00:00:00Z"}
            with self.assertRaises(aiops.ReplayError):
                aiops.run_job(job, aiops.Known(), aiops.EndpointPool([ol_url], "nope:1b"), model="nope:1b", replay=True)
        finally:
            vl.shutdown()
            ol.shutdown()


def recent(days_ago=1):
    t = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(days=days_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ"), (t + dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


class ReplayApiTests(IsolatedTestCase):
    R = {"Authorization": "Bearer r-token"}
    A = {"Authorization": "Bearer a-token"}

    def setUp(self):
        f, t = recent(1)
        of, ot = recent(40)
        self.heads = [{"_time": t, "_msg": "[AI digest] two issues", "kind": "digest", "id": "digest-2026-11-25T06:30:00Z", "window": f"{f}..{t}",
                       "model": "qwen3.5:9b", "max_severity": "high", "issue_count": "1", "secs": "40"},
                      {"_time": ot, "_msg": "[AI digest] old", "kind": "digest", "id": "digest-2026-10-01T06:30:00Z", "window": f"{of}..{ot}"}]
        self.issues = [{"parent": "digest-2026-11-25T06:30:00Z", "title": "NFS down", "severity": "high", "hosts": "homesrv"}]
        self.saved = (aiops.vl_query, aiops.run_job)

        def fake(q, timeout=None, **kw):
            if "kind:in(digest,incident)" in q:
                if "id:=" in q:
                    return [h for h in self.heads if json.dumps(h["id"]) in q]
                return list(self.heads)
            if "kind:issue" in q:
                return list(self.issues)
            return []
        self.gate = {"block": False}

        def fake_run(job, known, pool, dry_run=False, model=None, replay=False):
            while self.gate["block"]:
                time.sleep(0.01)
            if model == "broken":
                raise aiops.ReplayError("no reachable LLM endpoint serves the model broken")
            return {"kind": job["kind"], "model": model, "summary": "one issue", "issues": [{"title": "NFS down", "severity": "medium"}],
                    "secs": 12, "job": "x"}
        aiops.vl_query, aiops.run_job = fake, fake_run
        self.store = Store()
        self.rt = runtime.Runtime(self.store)
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))

    def tearDown(self):
        self.gate["block"] = False
        aiops.vl_query, aiops.run_job = self.saved

    def wait(self, rid):
        for _ in range(300):
            r = self.c.get(f"/api/v1/replays/{rid}", headers=self.R).json()
            if r["status"] != "running":
                return r
            time.sleep(0.01)
        self.fail("replay did not finish")

    def test_run_and_compare(self):
        r = self.c.post("/api/v1/replays", headers=self.A, json={"source": "digest-2026-11-25T06:30:00Z", "model": "qwen3.8:27b"})
        self.assertEqual(r.status_code, 200, r.text)
        d = self.wait(r.json()["id"])
        self.assertEqual(d["status"], "done")
        self.assertEqual(d["model"], "qwen3.8:27b")
        self.assertEqual(d["result"]["issues"][0]["severity"], "medium")
        self.assertNotIn("job", d["result"])
        self.assertEqual(d["original"]["summary"], "two issues")
        self.assertEqual(d["original"]["issues"][0]["title"], "NFS down")
        lst = self.c.get("/api/v1/replays", headers=self.R).json()
        self.assertEqual(lst["running"], 0)
        self.assertEqual(lst["replays"][0]["summary"]["max_severity"], "medium")
        audit = self.c.get("/api/v1/audit?limit=5", headers=self.A).json()
        self.assertTrue(any(a["action"] == "replay" for a in audit))

    def test_default_model(self):
        r = self.c.post("/api/v1/replays", headers=self.A, json={"source": "digest-2026-11-25T06:30:00Z"})
        self.assertEqual(self.wait(r.json()["id"])["model"], aiops.CFG["MODEL"])

    def test_error_is_recorded(self):
        r = self.c.post("/api/v1/replays", headers=self.A, json={"source": "digest-2026-11-25T06:30:00Z", "model": "broken"})
        d = self.wait(r.json()["id"])
        self.assertEqual(d["status"], "error")
        self.assertIn("no reachable", d["error"])

    def test_one_at_a_time(self):
        self.gate["block"] = True
        r1 = self.c.post("/api/v1/replays", headers=self.A, json={"source": "digest-2026-11-25T06:30:00Z"})
        self.assertEqual(r1.status_code, 200)
        r2 = self.c.post("/api/v1/replays", headers=self.A, json={"source": "digest-2026-11-25T06:30:00Z"})
        self.assertEqual(r2.status_code, 409)
        self.gate["block"] = False
        self.wait(r1.json()["id"])

    def test_validation(self):
        bad = [({"source": "digest-2026-10-01T06:30:00Z"}, 422),            # 30 napnal regebbi ablak
               ({"source": "digest-2026-11-20T06:30:00Z"}, 404),            # nincs ilyen
               ({"source": "heartbeat-x"}, 422),
               ({"source": "digest-2026-11-25T06:30:00Z", "model": "bad model;rm"}, 422)]
        for body, code in bad:
            self.assertEqual(self.c.post("/api/v1/replays", headers=self.A, json=body).status_code, code, body)

    def test_read_token_cannot_start_but_can_list(self):
        self.assertEqual(self.c.post("/api/v1/replays", headers=self.R, json={"source": "digest-2026-11-25T06:30:00Z"}).status_code, 403)
        self.assertEqual(self.c.get("/api/v1/replays", headers=self.R).status_code, 200)
        src = self.c.get("/api/v1/replays/sources", headers=self.R).json()
        self.assertEqual([s["id"] for s in src], ["digest-2026-11-25T06:30:00Z", "digest-2026-10-01T06:30:00Z"])

    def test_restart_marks_running_as_error(self):
        import tempfile
        d = tempfile.mkdtemp()
        path = os.path.join(d, "c.db")
        st = Store(path)
        rid = st.replay_add("a", "digest-x", "digest", "m", [])
        st.db.close()
        st2 = Store(path)                                   # ujraindulas: a 'running' futas 'error' lesz
        r = st2.replay_get(rid)
        st2.db.close()
        self.assertEqual((r["status"], r["error"]), ("error", "interrupted by a restart"))


if __name__ == "__main__":
    unittest.main()
