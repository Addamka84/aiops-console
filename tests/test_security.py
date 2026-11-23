"""v2.0.0-alpha.14: biztonsagi audit javitasai (titokszuro, ReDoS-vedelem, LogsQL-szuro). Az API-vedelmek tesztjei: test_console.py (ApiTests)."""
import json
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import aiops  # noqa: E402
import detectors  # noqa: E402
import regex_guard  # noqa: E402
import supervisor  # noqa: E402
from redact import redact, redact_obj  # noqa: E402


class RedactModuleTests(unittest.TestCase):
    def test_supervisor_uses_the_shared_module(self):
        self.assertIs(supervisor.redact, redact)
        self.assertIs(supervisor.redact_obj, redact_obj)

    def test_new_secret_shapes_are_removed(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        cases = {
            "jwt": (f"user session {jwt} opened", "eyJzdWIi"),
            "aws key id": ("using AKIAIOSFODNN7EXAMPLE for s3", "AKIAIOSFODNN7EXAMPLE"),
            "url userinfo": ("connecting to https://admin:S3cretPw@db.local:5432/x", "S3cretPw"),
            "rcon (space form)": ("sv_password hunter2xyz set; rcon_password topsecret99", "topsecret99"),
            "gslt (space form)": ("sv_setsteamaccount 0123456789ABCDEF0123456789ABCDEF ok", "0123456789ABCDEF0123456789ABCDEF"),
            "md5-like key": ("apikey_seen 9e107d9d372bb6826bd81d3542a419d6 end", "9e107d9d372bb6826bd81d3542a419d6"),
        }
        for name, (text, secret) in cases.items():
            self.assertNotIn(secret, redact(text), name)

    def test_ordinary_text_is_untouched(self):
        for t in ("Withdrawing address record for fe80::1 on eth0.", "systemd-networkd-wait-online@eth0.service failed",
                  "container 4f9a2c on host homesrv-3 restarted (exit 137)", "see https://example.org/path?x=1 for details",
                  "author: read:claude, units abcdef0123 and 12345678"):
            self.assertEqual(redact(t), t)

    def test_redaction_is_applied_on_the_triage_path(self):
        # a modell bemenete es kimenete is: a naplo titka sem a modellhez, sem a tarba / ertesitesbe nem juthat
        user = redact("2026-11-17 svc error: login failed for https://bot:Pa55w0rdXY@api.local/v1 token=abcdef123456")
        self.assertNotIn("Pa55w0rdXY", user)
        self.assertNotIn("abcdef123456", user)
        out = redact_obj({"summary": "leak token=s3cr3tvalue1", "issues": [{"title": "t", "evidence": "Bearer abcdef1234567890xyz in log", "hosts": ["h"]}]})
        self.assertNotIn("s3cr3tvalue1", json.dumps(out))
        self.assertNotIn("abcdef1234567890", json.dumps(out))
        self.assertEqual(out["issues"][0]["hosts"], ["h"])


class RegexGuardTests(unittest.TestCase):
    def test_catastrophic_regexes_are_rejected_quickly(self):
        t = time.monotonic()
        for rx in (r"(a|aa)+\s+Connection reset by peer", r"(a+)+$", r"(.*a){12} end", r"(x+x+)+y"):   # (\w|\d)+ NEM jo pelda: a CPython egy karakterosztalyba vonja
            regex_guard._OK.clear()
            msg = regex_guard.check([r"normal literal text \d+ here", rx], timeout=2)
            self.assertIsNotNone(msg, rx)
            self.assertIn("catastrophic backtracking", msg)
            self.assertIn(rx[:20], msg)                                        # a gyanus regexet nevezi meg, nem a jot
        self.assertLess(time.monotonic() - t, 30)

    def test_ordinary_regexes_pass_and_are_cached(self):
        regex_guard._OK.clear()
        rxs = [r"\[homeassistant\.components\.shelly\] .*reloading entry", r"avahi-daemon.*(Withdrawing|Registering new) address record for .* on veth",
               r"supervisor\.docker\.manager\] Exporting image (?:<N>|\d+)/addon-diyhue", r"\| smartd \| .*FAILED"]
        self.assertIsNone(regex_guard.check(rxs))
        self.assertTrue(all(x in regex_guard._OK for x in rxs))

    def test_invalid_regex_is_left_to_the_other_validation(self):
        self.assertIsNone(regex_guard.check(["(unclosed"]))

    def test_the_shipped_known_config_passes(self):
        # hamis riasztas elleni biztositek: a repoban levo (eles) known.json regexei mind atmennek, kulonben minden jovahagyas elakadna
        regex_guard._OK.clear()
        known = os.path.join(HERE, "..", "..", "aiops", "known.json")
        if not os.path.exists(known):
            self.skipTest("stacks/aiops/known.json not present")
        d = json.load(open(known, encoding="utf-8"))
        rxs = list(d.get("noise", [])) + [v for k in d.get("known_issues", []) for v in (k.get("match"), k.get("match_output")) if v]
        self.assertIsNone(regex_guard.check(rxs))

    def test_validate_known_rejects_a_catastrophic_regex(self):
        regex_guard._OK.clear()
        errs = aiops.validate_known({"noise": [r"(a|aa)+\s+Connection reset by peer"]})
        self.assertTrue(any("catastrophic backtracking" in e for e in errs), errs)
        regex_guard._OK.clear()
        self.assertEqual(aiops.validate_known({"noise": [r"\| homesrv \| avahi-daemon \| Withdrawing"]}), [])

    def test_validate_known_checks_snoozes_and_known_issues_too(self):
        regex_guard._OK.clear()
        soon = aiops.iso(aiops.utcnow() + aiops.dt.timedelta(days=1))         # a 90 napos plafon a teljes dokumentumra is el (alpha.30)
        doc = {"snoozes": [{"id": "s", "regex": r"(a+)+$", "until": soon}]}
        self.assertTrue(any("catastrophic" in e for e in aiops.validate_known(doc)))
        regex_guard._OK.clear()
        doc = {"known_issues": [{"id": "k", "note": "n", "match": r"(x+x+)+y"}]}
        self.assertTrue(any("catastrophic" in e for e in aiops.validate_known(doc)))

    def test_supervisor_rejects_a_repeated_alternation(self):
        for rx in (r"avahi-daemon (Withdrawing|Registering)+ address", r"homesrv (\w|\d)* connection reset"):
            reason = supervisor.check_noise_regex(rx, ["homesrv | avahi-daemon | Withdrawing address"], [])
            self.assertIn("alternation", reason or "", rx)
        # alpha.30 (audit M4): a modell zaj-regexeben semmilyen alternacio nem lehet (egy '(zaj|Failed password for)' mas kritikus sort is elnyelne);
        # a szam-helyorzo (?:<N>|\d+) kivetel. Kezzel irt szabalyban az alternacio tovabbra is megengedett (validate_known).
        self.assertIn("alternation", supervisor.check_noise_regex(r"avahi-daemon \| (Withdrawing|Registering) address record", ["homesrv | avahi-daemon | Withdrawing address record for x"], []) or "")
        self.assertIsNone(supervisor.check_noise_regex(r"avahi-daemon \| Withdrawing address record for (?:<N>|\d+)", ["homesrv | avahi-daemon | Withdrawing address record for <N>"], []))
        self.assertEqual(aiops.validate_known({"noise": [r"\| avahi-daemon \| (Withdrawing|Registering) address record"]}), [])


class CoverageShapeTests(unittest.TestCase):
    ITEM = {"host": "homenas2", "ident": "smartd", "filter": "host:=homenas2 appname:=smartd severity:in(emerg,alert,crit,err,error)"}

    def test_narrowing_filters_pass(self):
        for q in ("host:=homenas2 appname:=smartd severity:in(emerg,alert,crit,err,error)", 'host:=homenas2 appname:=smartd "FAILED SMART self-check"',
                  'appname:=smartd host:=homenas2 "a OR b * ~ ! - x"'):    # a kifejezesen BELUL minden karakter szabad
            self.assertIsNone(supervisor.check_coverage_shape(q, self.ITEM), q)

    def test_widening_or_unanchored_filters_are_rejected(self):
        # audit: egy `... OR *` szuro a 7 napos visszateszten par tuzelest adna (24 oras szunet), tehat a "tul zajos" kuszob nem fogta meg
        for q in ("host:=homenas2 appname:=smartd OR *", "host:=homenas2 appname:=smartd or host:=other", "host:=homenas2 appname:=smartd NOT x",
                  "host:=homenas2 appname:=smartd *", "host:=homenas2 appname:=smartd ~x", "host:=homenas2 appname:=smartd -bad:x", "host:=homenas2 appname:=smartd !x"):
            self.assertIn("may only narrow", supervisor.check_coverage_shape(q, self.ITEM) or "", q)

    def test_host_and_source_must_be_whole_conjuncts(self):
        for q in ('"host:=homenas2 appname:=smartd"', "host:=homenas2x appname:=smartd", "appname:=smartd", 'host:=other "homenas2 smartd"'):
            self.assertIn("must keep the host and the source", supervisor.check_coverage_shape(q, self.ITEM) or "", q)


class QuerySafetyTests(unittest.TestCase):
    def test_check_query_rejects_pipes_hidden_behind_other_quote_styles(self):
        # a LogsQL a '...' es a `...` szoveget is idezojelnek ismeri: a "bare" ellenorzes ezeken at nem lathatna csovet
        for q in ("host:=h `\"` | stats count() | `\"`", "host:=h '\"' | delete x | '\"'", "host:=h 'a'", "host:=h `a`"):
            self.assertIsNotNone(detectors.check_query(q), q)

    def test_check_query_still_accepts_normal_filters(self):
        for q in ('host:=homenas2 appname:=smartd "FAILED SMART self-check"', "_HOSTNAME:=homesrv3 SYSLOG_IDENTIFIER:=kernel PRIORITY:in(0,1,2,3)",
                  'host:=h "it\'s a (test) | with pipe"'):
            self.assertIsNone(detectors.check_query(q), q)


if __name__ == "__main__":
    unittest.main()
