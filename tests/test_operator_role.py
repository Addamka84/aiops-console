"""alpha.42: operator szerepkor (CONSOLE_OPERATOR_TOKEN) a read es az admin kozott.
Az operator a napi uzemeltetest vegzi (incidens, visszajatszas, karbantartas, leletek, kezi digest); konfigot nem ir, javaslatot nem hagy jova."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ.setdefault("KNOWN_FILE", os.path.join(HERE, "fixtures", "known.json"))

import aiops  # noqa: E402
import maintenance  # noqa: E402
import topology  # noqa: E402

TOK = {"read": "r-token-0123456789-0123456789-0123", "operator": "o-token-0123456789-0123456789-0123",
       "admin": "a-token-0123456789-0123456789-0123"}
TOPO = topology.Topology({"assets": [{"id": "srv1", "kind": "host"}]})


def hdr(role):
    return {"Authorization": "Bearer " + TOK[role], "X-Actor": "tester"}


class OperatorRole(unittest.TestCase):
    def setUp(self):
        import console
        import runtime
        from fastapi.testclient import TestClient
        from store import Store
        self.saved = aiops.TOPOLOGY
        aiops.TOPOLOGY = TOPO
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens=dict(TOK)))
        while not aiops.COMMANDS.empty():
            aiops.COMMANDS.get_nowait()

    def tearDown(self):
        aiops.TOPOLOGY = self.saved
        maintenance.set_active({})
        while not aiops.COMMANDS.empty():
            aiops.COMMANDS.get_nowait()

    def test_whoami(self):
        self.assertEqual(self.c.get("/api/v1/whoami", headers=hdr("operator")).json(), {"role": "operator", "actor": "operator:tester"})

    def test_operator_reads(self):
        self.assertEqual(self.c.get("/api/v1/status", headers=hdr("operator")).status_code, 200)

    def test_maintenance_window_allowed_and_audited(self):
        r = self.c.post("/api/v1/maintenance", headers=hdr("operator"), json={"targets": ["srv1"], "hours": 2})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.c.post(f"/api/v1/maintenance/{r.json()['id']}/end", headers=hdr("operator")).status_code, 200)
        actors = {a.get("actor") for a in self.c.get("/api/v1/audit", headers=hdr("admin")).json()}
        self.assertIn("operator:tester", actors)

    def test_read_still_forbidden_for_operational_actions(self):
        self.assertEqual(self.c.post("/api/v1/maintenance", headers=hdr("read"), json={"targets": ["srv1"], "hours": 1}).status_code, 403)
        self.assertEqual(self.c.post("/api/v1/jobs/digest", headers=hdr("read"), json={"hours": 6}).status_code, 403)

    def test_manual_digest(self):
        r = self.c.post("/api/v1/jobs/digest", headers=hdr("operator"), json={"hours": 6})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(aiops.COMMANDS.get_nowait(), {"cmd": "digest", "hours": 6})

    def test_novelty_dismiss_allowed(self):
        self.assertEqual(self.c.post("/api/v1/novelty/dismiss-all", headers=hdr("operator")).status_code, 200)
        self.assertEqual(self.c.post("/api/v1/novelty/999/dismiss", headers=hdr("operator")).status_code, 404)   # jogosult, csak nincs ilyen

    def test_incident_and_replay_endpoints_pass_auth(self):
        # a szerepkor atmegy (403 helyett validacio / nem talalhato): a vegpontok sajat logikajat a test_incidents / test_replay nezi
        r = self.c.post("/api/v1/incidents/incident-x/state", headers=hdr("operator"), json={"state": "bogus"})
        self.assertNotEqual(r.status_code, 403, r.text)
        r = self.c.post("/api/v1/replays", headers=hdr("operator"), json={"source": "x", "model": "bad model!"})
        self.assertNotEqual(r.status_code, 403, r.text)

    def test_config_write_forbidden(self):
        self.assertEqual(self.c.put("/api/v1/config/known", headers=hdr("operator"), json={"content": {}, "comment": "x"}).status_code, 403)
        self.assertEqual(self.c.post("/api/v1/config/known/rollback/1", headers=hdr("operator")).status_code, 403)
        self.assertEqual(self.c.post("/api/v1/snoozes", headers=hdr("operator"), json={"regex": "x y z", "hours": 1}).status_code, 403)
        self.assertEqual(self.c.post("/api/v1/jobs/notify-test", headers=hdr("operator")).status_code, 403)

    def test_cannot_approve_but_can_propose(self):
        r = self.c.post("/api/v1/proposals", headers=hdr("operator"),
                        json={"key": "known", "comment": "noise", "patch": {"add_noise": ["\\| zzz-operator-test \\|"]}})
        self.assertEqual(r.status_code, 200, r.text)
        pid = r.json()["id"]
        self.assertEqual(self.c.post(f"/api/v1/proposals/{pid}/approve", headers=hdr("operator")).status_code, 403)
        self.assertEqual(self.c.post(f"/api/v1/proposals/{pid}/reject", headers=hdr("operator")).status_code, 403)
        self.assertEqual(self.c.post(f"/api/v1/proposals/{pid}/approve", headers=hdr("admin")).status_code, 200)

    def test_audit_admin_only(self):
        self.assertEqual(self.c.get("/api/v1/audit", headers=hdr("operator")).status_code, 403)
        self.assertEqual(self.c.get("/api/v1/audit", headers=hdr("read")).status_code, 403)

    def test_forbidden_message_names_the_role(self):
        self.assertIn("operator token required", self.c.post("/api/v1/jobs/digest", headers=hdr("read"), json={}).text)
        self.assertIn("admin token required", self.c.get("/api/v1/audit", headers=hdr("operator")).text)


class TokenSetup(unittest.TestCase):
    def app(self, tokens):
        import console
        import runtime
        from fastapi.testclient import TestClient
        from store import Store
        rt = runtime.Runtime(Store())
        rt.bootstrap()
        return TestClient(console.create_app(rt, tokens=tokens))

    def test_operator_only_config_works(self):
        c = self.app({"read": "", "operator": TOK["operator"], "admin": ""})
        self.assertEqual(c.get("/api/v1/whoami", headers=hdr("operator")).json()["role"], "operator")

    def test_no_operator_token_rejects_it(self):
        c = self.app({"read": TOK["read"], "admin": TOK["admin"]})        # a regi ket-tokenes beallitas valtozatlanul mukodik
        self.assertEqual(c.get("/api/v1/whoami", headers=hdr("operator")).status_code, 401)
        self.assertEqual(c.get("/api/v1/whoami", headers=hdr("admin")).json()["role"], "admin")

    def test_same_token_resolves_to_higher_role(self):
        c = self.app({"read": TOK["operator"], "operator": TOK["operator"], "admin": TOK["admin"]})
        self.assertEqual(c.get("/api/v1/whoami", headers=hdr("operator")).json()["role"], "operator")

    def test_ui_has_operator_gate(self):
        js = open(os.path.join(HERE, "..", "src", "ui", "app.js"), encoding="utf-8").read()
        self.assertIn("const canOperate = () => S.role === 'admin' || S.role === 'operator';", js)
        self.assertGreaterEqual(js.count("canOperate()"), 9)


if __name__ == "__main__":
    unittest.main()
