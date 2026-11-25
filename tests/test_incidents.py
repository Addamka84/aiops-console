"""alpha.35: incidens-munkalap - lista, reszletek, allapot, jegyzet, visszajelzes, minosegi statisztika."""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ.setdefault("KNOWN_FILE", os.path.join(HERE, "fixtures", "known.json"))

import aiops  # noqa: E402
import console  # noqa: E402
import runtime  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from store import Store  # noqa: E402

I1, I2 = "incident-2026-11-25T07:23:52Z", "incident-2026-11-24T10:00:00Z"
HEADS = [
    {"_time": "2026-11-25T07:23:52Z", "_msg": "[AI incident] one incident, likely origin esx-02", "kind": "incident", "id": I1,
     "alert": "esx-02 host unavailable", "max_severity": "critical", "issue_count": "1", "correlated_alerts": "8", "root_hypothesis": "esx-02",
     "root_confidence": "1.0", "window": "a..b", "model": "m", "guard_notes": "x -> y | z", "stats": "{\"kept_lines\": 3}",
     "alert_items": json.dumps(["esx-02 host unavailable", "vm-app-06 not reachable"])},
    {"_time": "2026-11-24T10:00:00Z", "_msg": "[AI incident] disk", "kind": "incident", "id": I2, "alert": "disk full on nas",
     "max_severity": "high", "issue_count": "0"},
]
ISSUES = [
    {"parent": I1, "title": "minor", "severity": "low", "hosts": "vm-app-06"},
    {"parent": I1, "title": "esx-02 failure", "severity": "critical", "hosts": "esx-02, vm-app-06", "evidence": "ev"},
]


class IncidentApiTests(unittest.TestCase):
    R = {"Authorization": "Bearer r-token"}
    A = {"Authorization": "Bearer a-token"}

    def setUp(self):
        self.saved = aiops.vl_query
        self.qs = []

        def fake(q, timeout=None, **kw):
            self.qs.append(q)
            if "kind:incident" in q:
                if "id:=" in q:
                    return [h for h in HEADS if json.dumps(h["id"]) in q]
                return list(HEADS)
            if "kind:issue" in q:
                return list(ISSUES)
            return []
        aiops.vl_query = fake
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))

    def tearDown(self):
        aiops.vl_query = self.saved

    def test_list_with_default_state_and_top_issue_title(self):
        r = self.c.get("/api/v1/incidents", headers=self.R)
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        self.assertEqual([x["id"] for x in j], [I1, I2])
        self.assertEqual(j[0]["title"], "esx-02 failure")              # a legsulyosabb ugy cime
        self.assertEqual(j[1]["title"], "disk full on nas")            # ugy nelkul a riasztas
        self.assertEqual({x["state"] for x in j}, {"open"})
        self.assertIn('parent:in("incident-2026-11-25T07:23:52Z","incident-2026-11-24T10:00:00Z")', self.qs[1])

    def test_detail_timeline_and_items(self):
        j = self.c.get(f"/api/v1/incidents/{I1}", headers=self.R).json()
        self.assertEqual(j["alert_items"], ["esx-02 host unavailable", "vm-app-06 not reachable"])
        self.assertEqual(j["guard_notes"], ["x -> y", "z"])
        self.assertEqual([i["severity"] for i in j["issues"]], ["critical", "low"])
        self.assertEqual(j["issues"][0]["hosts"], ["esx-02", "vm-app-06"])
        self.assertEqual(j["events"], [])

    def test_state_note_feedback_flow_and_audit(self):
        self.assertEqual(self.c.post(f"/api/v1/incidents/{I1}/state", headers=self.A, json={"state": "acknowledged", "owner": "ops"}).status_code, 200)
        self.assertEqual(self.c.post(f"/api/v1/incidents/{I1}/notes", headers=self.A, json={"text": "checking the uplink, token=abc123secret"}).status_code, 200)
        fb = {"root_cause": "correct", "severity": "too_high", "grouping": "right", "comment": "good"}
        self.assertEqual(self.c.post(f"/api/v1/incidents/{I1}/feedback", headers=self.A, json=fb).status_code, 200)
        self.assertEqual(self.c.post(f"/api/v1/incidents/{I1}/state", headers=self.A, json={"state": "resolved"}).status_code, 200)
        j = self.c.get(f"/api/v1/incidents/{I1}", headers=self.R).json()
        self.assertEqual((j["state"], j["owner"]), ("resolved", "ops"))
        self.assertEqual([e["kind"] for e in j["events"]], ["state", "note", "feedback", "state"])
        self.assertNotIn("abc123secret", j["events"][1]["body"]["text"])       # titokszures a jegyzeten
        self.assertEqual(j["feedback"]["severity"], "too_high")
        lst = self.c.get("/api/v1/incidents?state=unresolved", headers=self.R).json()
        self.assertEqual([x["id"] for x in lst], [I2])
        audit = [a["action"] for a in self.c.get("/api/v1/audit", headers=self.A).json()]
        self.assertIn("incident.feedback", audit)

    def test_quality(self):
        self.c.post(f"/api/v1/incidents/{I1}/feedback", headers=self.A, json={"root_cause": "correct", "severity": "right", "grouping": "right"})
        self.c.post(f"/api/v1/incidents/{I2}/feedback", headers=self.A, json={"root_cause": "n/a", "severity": "too_low", "grouping": "should_split"})
        q = self.c.get("/api/v1/incidents/quality?days=30", headers=self.R).json()
        self.assertEqual((q["incidents"], q["with_feedback"]), (2, 2))
        self.assertEqual(q["root_cause"], {"good": 1, "rated": 1, "rate": 1.0})     # az n/a nem szamit
        self.assertEqual(q["severity"]["rate"], 0.5)
        self.assertEqual(q["grouping"]["rate"], 0.5)
        self.assertEqual(q["severity_too_low"], 1)

    def test_validation_and_roles(self):
        self.assertEqual(self.c.post(f"/api/v1/incidents/{I1}/state", headers=self.R, json={"state": "resolved"}).status_code, 403)
        self.assertEqual(self.c.post(f"/api/v1/incidents/{I1}/state", headers=self.A, json={"state": "closed"}).status_code, 422)
        self.assertEqual(self.c.post(f"/api/v1/incidents/{I1}/feedback", headers=self.A,
                                     json={"root_cause": "maybe", "severity": "right", "grouping": "right"}).status_code, 422)
        self.assertEqual(self.c.post("/api/v1/incidents/incident-2026-01-01T00:00:00Z/notes", headers=self.A, json={"text": "x"}).status_code, 404)
        self.assertEqual(self.c.get("/api/v1/incidents/bad id", headers=self.R).status_code, 404)
        self.assertEqual(self.c.get("/api/v1/incidents?state=weird", headers=self.R).status_code, 422)
        self.assertEqual(self.c.get("/api/v1/incidents").status_code, 401)

    def test_vl_down(self):
        def boom(q, timeout=None, **kw):
            raise OSError("down")
        aiops.vl_query = boom
        self.assertEqual(self.c.get("/api/v1/incidents", headers=self.R).status_code, 502)
        self.assertEqual(self.c.get(f"/api/v1/incidents/{I1}", headers=self.R).status_code, 502)


class EventTests(unittest.TestCase):
    def test_alert_items_stored_on_incident_head(self):
        res = {"kind": "incident", "summary": "s", "model": "m", "endpoint": "e", "window": "w", "all_clear": False, "issues": [],
               "dropped_known": 0, "secs": 1, "prompt_tokens": 1, "out_tokens": 1, "alert": "a", "alert_items": ["x", "y"]}
        head = aiops.to_events(res)[0]
        self.assertEqual(json.loads(head["alert_items"]), ["x", "y"])
        res2 = dict(res, kind="digest")
        self.assertNotIn("alert_items", aiops.to_events(res2)[0])


if __name__ == "__main__":
    unittest.main()
