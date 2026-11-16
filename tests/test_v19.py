"""v1.9.0: OpenAI-compatible model endpoint and flapping alerts."""
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402

GOOD = {"summary": "ok", "all_clear": True, "issues": []}


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def fake_openai(models=("big-model",), content=None, calls=None, reject_schema=False, status=200, finish="stop", key=None):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authed(self):
            return key is None or self.headers.get("Authorization") == "Bearer " + key

        def do_GET(self):
            if calls is not None:
                calls.append(("GET", self.path))
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            self._send(200, {"data": [{"id": m} for m in models]})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
            if calls is not None:
                calls.append(("POST", self.path, body))
            if not self._authed():
                return self._send(401, {"error": "unauthorized"})
            if reject_schema and body["response_format"]["type"] == "json_schema":
                return self._send(400, {"error": "json_schema not supported"})
            if status != 200:
                return self._send(status, {"error": "boom"})
            self._send(200, {"choices": [{"message": {"content": json.dumps(content or GOOD)}, "finish_reason": finish}],
                             "usage": {"prompt_tokens": 321, "completion_tokens": 12}})
    return H


class OpenAITests(unittest.TestCase):
    def setUp(self):
        self.saved = dict(aiops.CFG)
        aiops.CFG.update({"LLM_API": "openai", "MODEL": "big-model", "PROBE_TIMEOUT": 2, "GEN_TIMEOUT": 5, "LLM_API_KEY": ""})
        aiops._OPENAI_NO_SCHEMA.clear()

    def tearDown(self):
        aiops.CFG.clear()
        aiops.CFG.update(self.saved)
        aiops._OPENAI_NO_SCHEMA.clear()

    def test_probe_and_chat_roundtrip(self):
        calls = []
        srv, url = serve(fake_openai(calls=calls))
        try:
            pool = aiops.EndpointPool([url], "big-model")
            ep = pool.pick()
            self.assertEqual(ep["url"], url)
            resp = aiops.ollama_chat(url, "sys", "user")
        finally:
            srv.shutdown()
        self.assertEqual(resp["message"]["content"], json.dumps(GOOD))
        self.assertEqual((resp["prompt_eval_count"], resp["eval_count"]), (321, 12))
        self.assertEqual(calls[0], ("GET", "/v1/models"))
        post = [c for c in calls if c[0] == "POST"][0]
        self.assertEqual(post[1], "/v1/chat/completions")
        self.assertEqual(post[2]["response_format"]["type"], "json_schema")          # the output schema is requested
        self.assertEqual(post[2]["messages"][0], {"role": "system", "content": "sys"})
        self.assertEqual(aiops.parse_output(resp["message"]["content"])["all_clear"], True)

    def test_probe_rejects_a_missing_model_and_a_bad_key(self):
        srv, url = serve(fake_openai(models=("other",), key="secret"))
        try:
            self.assertFalse(aiops.EndpointPool([url], "big-model")._probe({"url": url})[0])        # 401: no key
            aiops.CFG["LLM_API_KEY"] = "secret"
            ok, why = aiops.EndpointPool([url], "big-model")._probe({"url": url})
            self.assertFalse(ok)
            self.assertIn("nincs a vegponton", why)                                                  # authenticated, but the model is not served
            self.assertTrue(aiops.EndpointPool([url], "other")._probe({"url": url})[0])
        finally:
            srv.shutdown()

    def test_api_key_is_sent_as_a_bearer_token(self):
        calls = []
        srv, url = serve(fake_openai(calls=calls, key="k-123"))
        aiops.CFG["LLM_API_KEY"] = "k-123"
        try:
            self.assertIsNotNone(aiops.ollama_chat(url, "s", "u"))
        finally:
            srv.shutdown()
        with self.assertRaises(aiops.OllamaError):
            srv2, url2 = serve(fake_openai(key="k-123"))
            aiops.CFG["LLM_API_KEY"] = ""
            try:
                aiops.ollama_chat(url2, "s", "u")
            finally:
                srv2.shutdown()

    def test_servers_without_json_schema_support_fall_back_to_json_object(self):
        calls = []
        srv, url = serve(fake_openai(calls=calls, reject_schema=True))
        try:
            r1 = aiops.ollama_chat(url, "s", "u")
            r2 = aiops.ollama_chat(url, "s", "u")
        finally:
            srv.shutdown()
        fmts = [c[2]["response_format"]["type"] for c in calls if c[0] == "POST"]
        self.assertEqual(fmts, ["json_schema", "json_object", "json_object"])        # remembered after the first rejection
        self.assertEqual(r1["message"], r2["message"])

    def test_truncated_and_failing_answers_are_errors(self):
        for kw in ({"finish": "length"}, {"status": 500}):
            srv, url = serve(fake_openai(**kw))
            try:
                with self.assertRaises(aiops.OllamaError):
                    aiops.ollama_chat(url, "s", "u")
            finally:
                srv.shutdown()

    def test_unreachable_endpoint_is_an_error_not_a_crash(self):
        with self.assertRaises(aiops.OllamaError):
            aiops.ollama_chat("http://127.0.0.1:1", "s", "u")

    def test_ollama_mode_is_unchanged(self):
        aiops.CFG["LLM_API"] = "ollama"
        calls = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                calls.append((self.path, json.loads(self.rfile.read(n))))
                data = json.dumps({"message": {"content": json.dumps(GOOD)}, "done_reason": "stop"}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        srv, url = serve(H)
        try:
            aiops.ollama_chat(url, "s", "u")
        finally:
            srv.shutdown()
        self.assertEqual(calls[0][0], "/api/chat")


class KumaLabelTests(unittest.TestCase):
    def test_the_monitor_label_is_kept_and_resolves_through_a_topology_alias(self):
        import topology
        labs = aiops.alert_labels(json.dumps([{"labels": {"alertname": "KumaMonitorDown", "monitor": "GameSRV - CS1.6", "severity": "warning", "junk": "x"}}]))
        self.assertEqual(labs, [{"alertname": "KumaMonitorDown", "severity": "warning", "monitor": "GameSRV - CS1.6"}])
        topo = topology.Topology({"assets": [{"id": "nihil", "kind": "device", "aliases": ["GameSRV"]}]})
        saved = aiops.TOPOLOGY
        aiops.TOPOLOGY = topo
        try:
            st = {"pending": [], "recent_alert_keys": {}, "incident_times": [], "alert_items": []}
            aiops.queue_alert(st, aiops.utcnow(), "KumaMonitorDown|", "[FIRING] KumaMonitorDown x1", labs, None)
        finally:
            aiops.TOPOLOGY = saved
        self.assertEqual(st["alert_items"][0]["cis"], ["nihil"])


class FlappingTests(unittest.TestCase):
    def setUp(self):
        self.saved = dict(aiops.CFG)
        aiops.CFG.update({"FLAP_COUNT": 4, "FLAP_WINDOW_H": 6, "FLAP_COOLDOWN_MIN": 180})

    def tearDown(self):
        aiops.CFG.clear()
        aiops.CFG.update(self.saved)

    def test_firings_are_counted_in_the_window_and_old_ones_expire(self):
        st = {}
        self.assertEqual([aiops.note_firing(st, "A|") for _ in range(3)], [1, 2, 3])
        st["alert_history"]["A|"] = [time.time() - 7 * 3600] + st["alert_history"]["A|"]
        self.assertEqual(aiops.note_firing(st, "A|"), 4)                       # the 7-hour-old one does not count
        st["alert_history"]["OLD|"] = [time.time() - 9 * 3600]
        aiops.note_firing(st, "B|")
        self.assertNotIn("OLD|", st["alert_history"])                           # stale keys are dropped

    def test_decision_rules(self):
        lab = [{"alertname": "KumaMonitorDown", "severity": "warning"}]
        self.assertEqual(aiops.flap_decision(3, lab, 99999), (False, ""))                                   # below the count
        sup, note = aiops.flap_decision(5, lab, 60)
        self.assertTrue(sup)
        self.assertIn("flapping: this alert fired 5 times", note)
        self.assertEqual(aiops.flap_decision(5, lab, 4 * 3600)[0], False)                                   # cooldown over: analyse again (with a note)
        self.assertIn("flapping", aiops.flap_decision(5, lab, 4 * 3600)[1])
        crit = [{"alertname": "X", "severity": "critical"}]
        self.assertEqual(aiops.flap_decision(9, crit, 60)[0], False)                                        # critical is never skipped
        aiops.CFG["FLAP_COUNT"] = 0
        self.assertEqual(aiops.flap_decision(99, lab, 1), (False, ""))                                      # off

    def test_poll_incidents_skips_a_flapping_alert_but_keeps_the_first_and_critical_ones(self):
        saved = (aiops.vl_query, aiops.vl_insert)
        events = []
        aiops.vl_insert = lambda ev, timeout=None: events.extend(ev)
        now = aiops.dt.datetime(2026, 11, 16, 12, 0, tzinfo=aiops.dt.timezone.utc)
        lab = json.dumps([{"labels": {"alertname": "KumaMonitorDown", "severity": "warning"}}])
        state = {"pending": [], "last_alert_ts": "2026-11-16T11:00:00.000000Z", "recent_alert_keys": {}, "incident_times": [], "alert_items": []}
        try:
            for i in range(6):   # the monitor goes down six times in a few minutes
                row = {"_time": f"2026-11-16T11:{10 + i}:00.5Z", "alertname": "KumaMonitorDown", "alert_root": "", "alert_count": "1", "alerts": lab, "_msg": "[FIRING] monitor"}
                aiops.vl_query = lambda q, timeout=None, row=row: [row]
                state["last_alert_ts"] = "2026-11-16T11:00:00.000000Z"
                aiops.poll_incidents(state, now)
                if i == 3:   # simulate the 30-minute cooldown having passed after the 4th firing
                    state["recent_alert_keys"]["KumaMonitorDown|"] -= 1900
            made = len(state["pending"]) + len(state["alert_items"])
        finally:
            aiops.vl_query, aiops.vl_insert = saved
        self.assertEqual(made, 1)                                               # only the first firing became an incident (cooldown hides the rest)
        self.assertEqual(state["alert_history"]["KumaMonitorDown|"][-1] > 0, True)
        self.assertEqual(len(state["alert_history"]["KumaMonitorDown|"]), 6)    # ... but all six were counted
        self.assertTrue(any(e["kind"] == "alert_flapping" for e in events))     # the 5th/6th firing was recognised as flapping and recorded


if __name__ == "__main__":
    unittest.main()
