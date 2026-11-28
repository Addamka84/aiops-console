"""Bizonyitek a zajszabaly-javaslatokhoz (evidence.py), a nyitott leletek automatikus lezarasa szabalyvaltozas utan, a tomeges lezaras API,
es a javaslat-nezet figyelem-jelzese / hatasvizsgalata."""
import os
import sys
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")

from fastapi.testclient import TestClient  # noqa: E402

import console  # noqa: E402
import evidence  # noqa: E402
import runtime  # noqa: E402
from store import Store  # noqa: E402


def pat(host, ident, level, tmpl, total=3):
    return {"key": f"{host}|{ident}|{tmpl}", "source": "syslog", "host": host, "ident": ident, "level": level, "tmpl": tmpl,
            "first_seen": "2026-11-20T00:00:00Z", "last_seen": "2026-11-21T00:00:00Z", "total": total, "since": "2026-11-20T00:00:00Z", "last_spike": ""}


def finding(host, ident, level, tmpl):
    return {"ts": "2026-11-21T00:00:00Z", "kind": "new", "key": f"k-{host}-{tmpl}"[:60], "source": "syslog", "host": host, "ident": ident,
            "level": level, "tmpl": tmpl, "hits": 2, "baseline": 0}


class AttentionTests(IsolatedTestCase):
    def test_flags_security_and_availability_words_only(self):
        self.assertIn("preauth", evidence.attention([r"Connection closed by authenticating user .* port <N> \[preauth\]"]))
        self.assertTrue(evidence.attention(["Zigbee: allowing new devices to join"]))
        self.assertTrue(evidence.attention(["zh:ember: [STACK STATUS] Network closed"]))
        self.assertTrue(evidence.attention(["Out of memory: Killed process 12 (mariadbd)"]))
        self.assertEqual(evidence.attention(["custom_components.dreame_vacuum.dreame.map Get Recovery Map List"]), [])
        self.assertEqual(evidence.attention(["host thingino-kidsroom heartbeat ok"]), [])         # 'oom' csak onallo szokent jelent (nem 'room')

    def test_limit(self):
        self.assertEqual(len(evidence.attention(["preauth denied refused panic corrupt degraded unreachable"], limit=3)), 3)


class EvidenceTests(IsolatedTestCase):
    def test_impact_numbers_examples_similar_and_redaction(self):
        pats = [pat("h1", "sshd", "info", "Connection closed by authenticating user root <IP> port <N> [preauth]", 40),
                pat("h2", "sshd", "info", "Connection closed by authenticating user admin <IP> port <N> [preauth]", 10),
                pat("h1", "cron", "info", "job finished", 100),
                pat("h3", "kernel", "err", "preauth watchdog error token=abc123", 1)]
        fnd = [dict(finding("h1", "sshd", "info", "Connection closed by authenticating user root <IP> port <N> [preauth]"), id=7),
               dict(finding("h4", "cron", "info", "job finished"), id=8)]
        out = evidence.noise_evidence([r"preauth"], pats, fnd, [r"sshd.*closed", r"unrelated"], redact=lambda s: s.replace("abc123", "<redacted>"))
        e = out[0]
        self.assertEqual((e["templates"], e["hits"], e["hosts"]), (3, 51, 3))
        self.assertEqual(e["covered_open"], 1)
        self.assertEqual(e["covered_ids"], [7])
        self.assertEqual(e["important_templates"], 1)                     # az err szintu sablon
        self.assertIn("preauth", e["attention"])
        self.assertEqual(e["similar_rules"], [r"sshd.*closed"])
        self.assertEqual(e["top_hosts"][0]["host"], "h1")
        self.assertTrue(all("abc123" not in x["text"] for x in e["examples"]))

    def test_invalid_regex_is_reported_not_raised(self):
        out = evidence.noise_evidence(["(unclosed"], [], [])
        self.assertIn("invalid regex", out[0]["error"])


class ApiTests(IsolatedTestCase):
    R = {"Authorization": "Bearer r-token"}
    A = {"Authorization": "Bearer a-token"}

    def setUp(self):
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.store = self.rt.store
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))
        self.store.nov_upsert([pat("h1", "sshd", "info", "Connection closed by authenticating user root <IP> port <N> [preauth]", 40),
                               pat("h1", "cron", "info", "uniquejob finished <N>", 100)])
        self.store.nov_add_findings([finding("h1", "sshd", "info", "Connection closed by authenticating user root <IP> port <N> [preauth]"),
                                     finding("h1", "cron", "info", "uniquejob finished <N>"),
                                     finding("h2", "other", "info", "something else <N>")])

    def open_ids(self):
        return {f["ident"]: f["id"] for f in self.store.nov_findings("open", limit=100)}

    def test_new_noise_rule_closes_the_open_findings_it_covers(self):
        cur = self.store.current("known")["content"]
        doc = dict(cur, noise=list(cur.get("noise", [])) + [r"uniquejob finished"])
        self.store.put("known", doc, "t", "add rule")
        self.rt.sync()
        self.assertEqual(set(self.open_ids()), {"sshd", "other"})          # a cron lelet lezarult, a tobbi nyitva

    def test_bulk_dismiss_needs_admin_and_only_touches_open_ids(self):
        ids = self.open_ids()
        body = {"ids": [ids["sshd"], ids["other"], 99999]}
        self.assertEqual(self.c.post("/api/v1/novelty/dismiss", json=body, headers=self.R).status_code, 403)
        r = self.c.post("/api/v1/novelty/dismiss", json=body, headers=self.A)
        self.assertEqual(r.json(), {"dismissed": 2})
        self.assertEqual(set(self.open_ids()), {"cron"})
        self.assertEqual(self.c.post("/api/v1/novelty/dismiss", json={"ids": []}, headers=self.A).status_code, 422)

    def test_proposal_view_has_attention_flag_and_impact(self):
        r = self.c.post("/api/v1/proposals", json={"key": "known", "comment": "x", "patch": {"add_noise": [r"authenticating user .* \[preauth\]"]}}, headers=self.R)
        self.assertEqual(r.status_code, 200, r.text)
        pid = r.json()["id"]
        lst = {p["id"]: p for p in self.c.get("/api/v1/proposals?status=pending", headers=self.R).json()}
        self.assertIn("preauth", lst[pid]["attention"])
        self.assertNotIn("evidence", lst[pid])                              # a listaban nincs hatasvizsgalat (olcso nezet)
        ev = self.c.get(f"/api/v1/proposals/{pid}", headers=self.R).json()["evidence"][0]
        self.assertEqual((ev["templates"], ev["covered_open"]), (1, 1))
        self.assertIn("preauth", ev["attention"])

    def test_quiet_rule_has_no_attention(self):
        r = self.c.post("/api/v1/proposals", json={"key": "known", "comment": "x", "patch": {"add_noise": [r"uniquejob finished"]}}, headers=self.R)
        pid = r.json()["id"]
        lst = {p["id"]: p for p in self.c.get("/api/v1/proposals?status=pending", headers=self.R).json()}
        self.assertEqual(lst[pid]["attention"], [])


if __name__ == "__main__":
    unittest.main()
