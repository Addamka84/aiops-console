"""A demo al-modell (demo/mock_llm.py): a korrelátor hipotézisét fogalmazza át, a konzol sémájának megfelelő válasszal; kontextus nélkül nem talál ki semmit."""
import json
import os
import sys
import threading
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "demo"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402
import mock_llm  # noqa: E402

PROMPT = ("== Root-cause HYPOTHESIS computed from the topology (not a certainty): esx-02 (it explains 7 of 8 affected items, confidence 0.88).\n"
          "   Potentially impacted items (downstream of the hypothesis): 12.\n")


class MockLlmTests(unittest.TestCase):
    def test_incident_answer_matches_schema(self):
        a = mock_llm.answer(PROMPT)
        self.assertEqual(set(a), {"summary", "all_clear", "issues"})
        self.assertFalse(a["all_clear"])
        i = a["issues"][0]
        self.assertEqual(set(i), set(aiops.SCHEMA["properties"]["issues"]["items"]["required"]))
        self.assertIn(i["severity"], aiops.SEVERITIES)
        self.assertEqual(i["hosts"], ["esx-02"])
        self.assertIn("demo-model", i["evidence"])
        self.assertIn("12 downstream", i["evidence"])

    def test_no_hypothesis_invents_nothing(self):
        a = mock_llm.answer("== Alerts: something\nlines")
        self.assertTrue(a["all_clear"] and a["issues"] == [])
        self.assertIn("Demo model", a["summary"])

    def test_http_endpoints(self):
        srv = mock_llm.http.server.HTTPServer(("127.0.0.1", 0), mock_llm.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            tags = json.load(urllib.request.urlopen(base + "/api/tags"))
            self.assertEqual(tags["models"][0]["name"], mock_llm.MODEL)
            req = urllib.request.Request(base + "/api/chat", json.dumps({"messages": [{"role": "system", "content": "s"}, {"role": "user", "content": PROMPT}]}).encode())
            resp = json.load(urllib.request.urlopen(req))
            self.assertEqual(resp["done_reason"], "stop")
            self.assertEqual(json.loads(resp["message"]["content"])["issues"][0]["hosts"], ["esx-02"])
        finally:
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
