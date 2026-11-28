"""alpha.37: karbantartasi ablakok - validacio, aktiv ablak, topologias kiterjesztes, riasztas/detektor elnyomasa, API."""
import datetime as dt
import os
import sys
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ.setdefault("KNOWN_FILE", os.path.join(HERE, "fixtures", "known.json"))

import aiops  # noqa: E402
import maintenance  # noqa: E402
import topology  # noqa: E402

TOPO = topology.Topology({"assets": [
    {"id": "router", "kind": "network", "ip": "192.0.2.1"},
    {"id": "homenas2", "kind": "host", "ip": "192.0.2.172", "depends_on": [{"id": "router", "type": "network"}]},
    {"id": "homesrv", "kind": "host", "ip": "192.0.2.2", "aliases": ["srv-main"], "depends_on": [{"id": "router", "type": "network"}]},
    {"id": "adguard", "kind": "container", "runs_on": "homesrv"},
    {"id": "homesrv3", "kind": "host", "ip": "192.0.2.125", "depends_on": [{"id": "homenas2", "type": "storage"}]},
]})
NOW = dt.datetime(2026, 11, 25, 12, 0)


def win(**kw):
    w = {"id": "swap", "targets": ["homesrv"], "start": "2026-11-25T11:00:00Z", "end": "2026-11-25T13:00:00Z", "include_dependents": True}
    w.update(kw)
    return w


class ValidateTests(IsolatedTestCase):
    def test_valid(self):
        self.assertEqual(maintenance.validate({"windows": [win()]}, TOPO), [])
        self.assertEqual(maintenance.validate({"windows": [win(targets=["srv-main"])]}, TOPO), [])     # alias is jo

    def test_invalid(self):
        bad = [win(targets=[]), win(targets=["nope"]), win(end="2026-11-25T10:00:00Z"), win(end="2026-12-05T13:00:00Z"),
               win(id="Bad Id"), win(start="tomorrow"), win(include_dependents="yes"), win(extra=1)]
        for w in bad:
            self.assertTrue(maintenance.validate({"windows": [w]}, TOPO), w)
        self.assertTrue(maintenance.validate({"windows": [win(), win()]}, TOPO))                     # azonos id
        self.assertTrue(maintenance.validate({"windows": "x"}, TOPO))
        self.assertEqual(maintenance.validate({"windows": [win(targets=["nope"])]}, None), [])       # topologia nelkul szoveges cel

    def test_expanded_with_and_without_dependents(self):
        self.assertEqual(maintenance.expanded(TOPO, win())[0], {"homesrv", "adguard"})
        self.assertEqual(maintenance.expanded(TOPO, win(include_dependents=False))[0], {"homesrv"})
        self.assertIn("homesrv3", maintenance.expanded(TOPO, win(targets=["homenas2"]))[0])        # tarolas-fuggo is


class MatchTests(IsolatedTestCase):
    def setUp(self):
        maintenance.set_active({"windows": [win(), win(id="later", targets=["homenas2"], start="2026-11-25T14:00:00Z", end="2026-11-25T15:00:00Z")]})

    def tearDown(self):
        maintenance.set_active({})

    def test_active_window_matches_target_and_dependent(self):
        self.assertEqual(maintenance.match(TOPO, "[FIRING] JournaldCritical: homesrv / systemd-journal-upload", now=NOW)["id"], "swap")
        self.assertEqual(maintenance.match(TOPO, "adguard upstream errors", now=NOW)["id"], "swap")
        self.assertIsNone(maintenance.match(TOPO, "homesrv3 pulseaudio error", now=NOW))
        self.assertIsNone(maintenance.match(TOPO, "homenas2 disk", now=NOW))                        # a 'later' ablak meg nem aktiv
        self.assertEqual(maintenance.match(TOPO, "homenas2 disk", now=dt.datetime(2026, 11, 25, 14, 30))["id"], "later")
        self.assertIsNone(maintenance.match(TOPO, "homesrv down", now=dt.datetime(2026, 11, 25, 13, 0)))  # az 'end' mar nem resze

    def test_text_target_without_topology(self):
        maintenance.set_active({"windows": [win(targets=["nihil"])]})
        self.assertIsNotNone(maintenance.match(None, "Uptime Kuma: GameSRV on nihil DOWN", now=NOW))
        self.assertIsNone(maintenance.match(None, "nihilist", now=NOW))


class PollTests(IsolatedTestCase):
    def setUp(self):
        self.saved = (aiops.vl_query, dict(aiops.CFG), aiops.TOPOLOGY)
        rows = [{"_time": "2026-11-25T12:00:01.1Z", "alertname": "JournaldCritical", "alert_root": "", "_msg": "[FIRING] JournaldCritical: homesrv / x", "alerts": ""},
                {"_time": "2026-11-25T12:00:02.1Z", "alertname": "KumaMonitorDown", "alert_root": "", "_msg": "[FIRING] Kuma: homesrv3 DOWN", "alerts": ""}]
        aiops.vl_query = lambda q, timeout=None, **kw: rows
        aiops.CFG.update({"CORRELATE_MODE": "off"})
        aiops.TOPOLOGY = TOPO
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        maintenance.set_active({"windows": [win(start=maintenance.fmt_ts(now - dt.timedelta(minutes=5)),
                                                end=maintenance.fmt_ts(now + dt.timedelta(hours=1)))]})

    def tearDown(self):
        aiops.vl_query = self.saved[0]
        aiops.CFG.clear()
        aiops.CFG.update(self.saved[1])
        aiops.TOPOLOGY = self.saved[2]
        maintenance.set_active({})

    def test_alert_in_window_is_only_logged(self):
        st = {"pending": [], "last_alert_ts": "2026-11-25T12:00:00.000000Z", "recent_alert_keys": {}, "incident_times": []}
        aiops.poll_incidents(st, dt.datetime(2026, 11, 25, 12, 5, tzinfo=dt.timezone.utc))
        self.assertEqual([j["key"] for j in st["pending"]], ["KumaMonitorDown|"])

    def test_detector_hit_in_window_is_only_logged(self):
        aiops.DETECTOR_HITS.put({"detector": {"id": "d1", "name": "x", "query": "q", "mode": "count", "cooldown_min": 60, "action": "triage",
                                              "window_min": 15, "severity": "medium", "threshold": 1},
                                 "group": {"host": "homesrv"}, "hits": 3})
        st = {"pending": [], "recent_alert_keys": {}, "incident_times": []}
        aiops.poll_detectors(st, dt.datetime(2026, 11, 25, 12, 5, tzinfo=dt.timezone.utc))
        self.assertEqual(st["pending"], [])
        self.assertEqual(st["recent_alert_keys"], {})


class ApiTests(IsolatedTestCase):
    A = {"Authorization": "Bearer a-token"}
    R = {"Authorization": "Bearer r-token"}

    def setUp(self):
        import console
        import runtime
        from fastapi.testclient import TestClient
        from store import Store
        self.saved = aiops.TOPOLOGY
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        aiops.TOPOLOGY = TOPO
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))

    def tearDown(self):
        aiops.TOPOLOGY = self.saved
        maintenance.set_active({})

    def test_add_list_end_and_status(self):
        r = self.c.post("/api/v1/maintenance", headers=self.A, json={"targets": ["homesrv"], "hours": 2, "note": "hardware swap"})
        self.assertEqual(r.status_code, 200, r.text)
        wid = r.json()["id"]
        self.assertEqual(r.json()["window"]["covers"], ["adguard", "homesrv"])
        lst = self.c.get("/api/v1/maintenance", headers=self.R).json()
        self.assertEqual([w["state"] for w in lst["windows"]], ["active"])
        st = self.c.get("/api/v1/status", headers=self.R).json()
        self.assertEqual(st["maintenance_active"][0]["targets"], ["homesrv"])
        self.assertEqual(self.c.post(f"/api/v1/maintenance/{wid}/end", headers=self.A).status_code, 200)
        self.assertEqual([w["state"] for w in self.c.get("/api/v1/maintenance", headers=self.R).json()["windows"]], ["ended"])
        self.assertEqual(self.c.get("/api/v1/status", headers=self.R).json()["maintenance_active"], [])

    def test_upcoming_cancel_removes_and_validation(self):
        r = self.c.post("/api/v1/maintenance", headers=self.A, json={"targets": ["homenas2"], "hours": 1, "start": "2099-01-01T00:00:00Z", "id": "future"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.c.post("/api/v1/maintenance/future/end", headers=self.A).status_code, 200)
        self.assertEqual(self.c.get("/api/v1/maintenance", headers=self.R).json()["windows"], [])
        self.assertEqual(self.c.post("/api/v1/maintenance", headers=self.A, json={"targets": ["nope"], "hours": 1}).status_code, 422)
        self.assertEqual(self.c.post("/api/v1/maintenance", headers=self.A, json={"targets": ["homesrv"], "hours": 500}).status_code, 422)
        self.assertEqual(self.c.post("/api/v1/maintenance", headers=self.R, json={"targets": ["homesrv"], "hours": 1}).status_code, 403)
        self.assertEqual(self.c.post("/api/v1/maintenance/none/end", headers=self.A).status_code, 404)

    def test_proposal_path_for_read_token(self):
        doc = {"windows": [win(start="2099-01-01T00:00:00Z", end="2099-01-01T02:00:00Z")]}
        r = self.c.post("/api/v1/proposals", headers=self.R, json={"key": "maintenance", "content": doc, "comment": "swap"})
        self.assertEqual(r.status_code, 200, r.text)


if __name__ == "__main__":
    unittest.main()
