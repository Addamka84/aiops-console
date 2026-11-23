"""A masodik biztonsagi audit (2026-11-23, docs/aiops-biztonsagi-audit-2.md) javitasainak tesztjei (alpha.30).
Futtatas (a stacks/aiops-console mappabol): python3 -m unittest discover -s tests
"""
import datetime as dt
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402
import console  # noqa: E402
import detectors  # noqa: E402
import regex_guard  # noqa: E402
import rules  # noqa: E402
import runtime  # noqa: E402
import settings  # noqa: E402
import supervisor  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from redact import redact  # noqa: E402
from store import Store  # noqa: E402


class H1RegexGuardTests(unittest.TestCase):
    def setUp(self):
        regex_guard._OK.clear()

    def test_prefixed_and_polynomial_bypasses_are_rejected_without_running(self):
        for rx in (r"myapp \| (x+)+ zz", r"^ERR(a|aa)+$", r"kernel: (x+x+)+y", r"((?:x+))+ zz", r".*.*.*.*QQQ", r".*\s*.*foo", r"\w+\d+x",
                   r"a.*b.*c.*d.*e", "x" * 501):
            self.assertIsNotNone(regex_guard.structural_problem(rx), rx)
            self.assertIsNotNone(regex_guard.check([rx]), rx)

    def test_ordinary_noise_regexes_pass(self):
        for rx in (r"\| plex \| .*Connection reset", r"\d+\.\d+\.\d+\.\d+", r"[a-z]+\d+", r"(?i)GET /health", r"foo (bar|baz) qux", r"a{2,5}b",
                   r"^\S+ \S+ \S+ x", r"(?:<N>|\d+)-(?:<N>|\d+) INFO .*Frigate.*\"GET /api/.*|\"POST /api/.*", r"(a.*b|c.*d).*e.*f"):
            self.assertIsNone(regex_guard.check([rx]), rx)

    def test_attack_strings_start_with_the_regex_prefix(self):
        self.assertTrue(any(s.startswith("myapp | x") for s in regex_guard.attack_strings(r"myapp \| x+ zz")))

    def test_the_check_fails_closed(self):
        saved = regex_guard.subprocess.run
        try:
            regex_guard.subprocess.run = lambda *a, **k: subprocess.CompletedProcess(a, 1, b"", b"")
            self.assertIn("not accepted", regex_guard.check([r"myapp \| plain text here"]) or "")
            regex_guard._OK.clear()

            def boom(*a, **k):
                raise OSError("no fork")
            regex_guard.subprocess.run = boom
            self.assertIn("not accepted", regex_guard.check([r"myapp \| other text here"]) or "")
        finally:
            regex_guard.subprocess.run = saved

    def test_supervisor_runs_the_guard_and_bans_alternation(self):
        refs = ["host | myapp | said hello world chatter <N> times"]
        self.assertIn("nested", supervisor.check_noise_regex(r"myapp \| said hello (x+)+ chatter", refs, []) or "")
        self.assertIn("alternation", supervisor.check_noise_regex(r"(?:said hello world chatter|Failed password for)", refs, []) or "")
        self.assertIsNone(supervisor.check_noise_regex(r"said hello world chatter (?:<N>|\d+) times", refs, []))

    def test_security_events_are_canaries(self):
        refs = ["host | sshd | Accepted publickey for root from <N>"]
        self.assertIn("too broad", supervisor.check_noise_regex(r"Accepted publickey for root from", refs, []) or "")
        self.assertIn("too broad", supervisor.check_noise_regex(r"session opened for user root", ["h | sshd | session opened for user root"], []) or "")


class M1M2M3QueryAndRuleTests(unittest.TestCase):
    def test_parentheses_cannot_close_the_wrapper(self):
        for q in ("x) OR (y", "*) OR (*", "a) (b"):
            self.assertIsNotNone(detectors.check_query(q), q)
        self.assertIsNone(detectors.check_query("(a) OR (b)"))
        self.assertIsNone(detectors.check_query('_msg:~"(x) OR (y"'))              # idezojelen belul szoveg
        self.assertTrue(rules.validate({"rules": [{"id": "X", "kind": "count", "query": "x) OR (y"}]}))
        self.assertIsNotNone(rules.check_expr("x) OR (y | stats count()"))

    def test_note_is_not_a_template(self):
        bad = {"rules": [{"id": "X", "kind": "count", "query": "a", "note": '{{ range query "x" }}{{ end }}'}]}
        self.assertTrue(any("not a template" in e for e in rules.validate(bad)))
        self.assertTrue(rules.validate({"rules": [{"id": "X", "kind": "count", "query": "a", "note": "a\nb"}]}))
        self.assertEqual(rules.validate({"rules": [{"id": "X", "kind": "count", "query": "a", "note": "plain note"}]}), [])

    def test_high_cardinality_group_by_is_denied(self):
        for f in ("_msg", "_time", "_stream", "message"):
            self.assertTrue(rules.validate({"rules": [{"id": "X", "kind": "count", "query": "*", "group_by": [f]}]}), f)


class M5EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.saved = aiops.vl_query
        self.k = aiops.Known(data={"noise": [r"noisy"], "context": [], "known_issues": []})
        self.job = {"alert_labels": [{"alertname": "JournaldCritical", "host": "h1", "SYSLOG_IDENTIFIER": "kernel"}]}
        self.t = (dt.datetime(2026, 11, 23, 8, tzinfo=dt.timezone.utc), dt.datetime(2026, 11, 23, 9, tzinfo=dt.timezone.utc))

    def tearDown(self):
        aiops.vl_query = self.saved

    def ev(self, rows):
        aiops.vl_query = lambda q, timeout=None, **kw: list(rows)
        return aiops.alert_evidence(self.job, self.k, *self.t)

    def test_complete_err_only_noise_is_skipped(self):
        e = self.ev([{"_msg": "noisy line", "hits": "3", "prio": "3"}])
        self.assertEqual(e["kept"], [])                                 # a regi viselkedes: kimarad

    def test_a_full_page_of_noise_is_not_proof(self):
        e = self.ev([{"_msg": f"noisy {i}", "hits": "50", "prio": "3"} for i in range(aiops.EVIDENCE_ROWS)])
        self.assertIsNone(e)                                            # nem allapithato meg: az incidens nem marad ki

    def test_a_suppressed_critical_line_is_never_skipped(self):
        self.assertIsNone(self.ev([{"_msg": "noisy crit", "hits": "1", "prio": "2"}]))


class L1KnownTests(unittest.TestCase):
    def test_catch_all_known_issue_is_rejected(self):
        for m in (".", ".*", "error|fail", "(?i)e"):
            errs = aiops.validate_known({"known_issues": [{"id": "k", "note": "n", "match": m}]})
            self.assertTrue(any("too broad" in e for e in errs), (m, errs))
        self.assertEqual(aiops.validate_known({"known_issues": [{"id": "k", "note": "n", "match": r"homenas2 \| smartd \| .*/dev/sdb"}]}), [])

    def test_snooze_cap_applies_to_a_full_document(self):
        far = aiops.iso(aiops.utcnow() + dt.timedelta(days=120))
        near = aiops.iso(aiops.utcnow() + dt.timedelta(days=30))
        self.assertTrue(aiops.validate_known({"snoozes": [{"id": "s", "regex": "foo bar baz", "until": far}]}))
        self.assertEqual(aiops.validate_known({"snoozes": [{"id": "s", "regex": "foo bar baz", "until": near}]}), [])


class M6ProposalAndAuditTests(unittest.TestCase):
    R = {"Authorization": "Bearer r-token-0123456789-0123456789-0123"}

    def setUp(self):
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token-0123456789-0123456789-0123", "admin": "a-token-0123456789-0123456789-0123"}))
        self.saved = console.MAX_PENDING_PER_ACTOR
        console.MAX_PENDING_PER_ACTOR = 3

    def tearDown(self):
        console.MAX_PENDING_PER_ACTOR = self.saved

    def test_changing_x_actor_does_not_bypass_the_limit(self):
        codes = []
        for i in range(5):
            r = self.c.post("/api/v1/proposals", headers=dict(self.R, **{"X-Actor": f"bot{i}"}),
                            json={"key": "known", "comment": "x", "patch": {"add_noise": [rf"\| app{i} \| some harmless message"]}})
            codes.append(r.status_code)
        self.assertEqual(codes, [200, 200, 200, 429, 429])

    def test_audit_is_kept_by_time_not_by_row_count(self):
        s = Store()
        for i in range(2500):
            s.audit("read:x", "proposal", str(i))
        self.assertEqual(len(s.audit_list(5000)), 2500)                    # korabban 2000 sornal levagott
        s.db.execute("UPDATE audit SET ts = '2020-01-01T00:00:00Z' WHERE id <= 10")
        s._audit_pruned = -1e9
        s.audit("admin", "x", "y")
        self.assertEqual(len(s.audit_list(5000)), 2491)


class M11RedactTests(unittest.TestCase):
    def test_enterprise_secret_shapes(self):
        for raw, secret in (("AccountName=a;AccountKey=abc/DEF+ghi==;EndpointSuffix=x", "abc/DEF"), ("?sv=1&sig=AbC%2Fdef%3D&se=1", "AbC%2F"),
                            ("Server=db;Pwd=hunter2;", "hunter2"), ("login pass=secret123 ok", "secret123"),
                            ("-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END PGP PRIVATE KEY BLOCK-----", "abc"),
                            ("k AIzaSyA1234567890abcdefghijklmnopqrstu", "AIzaSy"), ("sk-proj-abcdefghijklmnopqrstuv1", "abcdefghij"),
                            ("X-Api-Key: 0123abcd", "0123abcd"), ("Cookie: session=abc123; theme=dark", "abc123"),
                            ("postgres://user:pa/ss@db:5432/x", "pa/ss"), ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_")):
            self.assertNotIn(secret, redact(raw), raw)

    def test_ordinary_text_is_untouched(self):
        for t in ("tests passed: 12", "http://host:8080/users/@me", "nfs: server homenas2 not responding, still trying"):
            self.assertEqual(redact(t), t)


class M7KeyBindingTests(unittest.TestCase):
    def setUp(self):
        self.saved = (dict(aiops.CFG), dict(aiops.ENV_CFG))
        aiops.ENV_CFG["OLLAMA_URLS"] = ["http://llm.internal:11434"]
        aiops.ENV_CFG["SUPERVISOR_URL"] = ""
        aiops.CFG.update(LLM_API_KEY="k-123", ALLOWED_LLM_HOSTS=[])

    def tearDown(self):
        aiops.CFG.clear()
        aiops.CFG.update(self.saved[0])
        aiops.ENV_CFG.clear()
        aiops.ENV_CFG.update(self.saved[1])

    def test_key_goes_only_to_env_or_allowlisted_hosts(self):
        self.assertEqual(aiops._auth("http://llm.internal:11434"), {"Authorization": "Bearer k-123"})
        self.assertEqual(aiops._auth("http://evil.example:80"), {})
        aiops.CFG["ALLOWED_LLM_HOSTS"] = ["gpu2.internal"]
        self.assertTrue(aiops._auth("https://gpu2.internal:8000"))

    def test_allowlist_restricts_the_settings(self):
        aiops.CFG["ALLOWED_LLM_HOSTS"] = ["gpu2.internal"]
        self.assertTrue(settings.validate({"OLLAMA_URLS": ["http://evil.example:11434"]})[1])
        self.assertEqual(settings.validate({"OLLAMA_URLS": ["http://gpu2.internal:11434", "http://llm.internal:11434"]})[1], [])


class VlQueryLimitTests(unittest.TestCase):
    def test_response_size_cap(self):
        from test_aiops import start
        from http.server import BaseHTTPRequestHandler

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                data = b'{"a": 1}\n' * 1000
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        srv, url = start(H)
        saved = aiops.CFG["VL_URL"]
        try:
            aiops.CFG["VL_URL"] = url
            self.assertEqual(len(aiops.vl_query("x")), 1000)
            with self.assertRaises(ValueError):
                aiops.vl_query("x", max_bytes=100)
        finally:
            aiops.CFG["VL_URL"] = saved
            srv.shutdown()


if __name__ == "__main__":
    unittest.main()
