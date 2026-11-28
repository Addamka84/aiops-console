"""A detektor-oldal felugyelete: allapot-attekintes (health), a Supervisor overview jelzesei, a '+ detector' vazlat a novelty-leletbol,
'Approve and enable' a detektor-javaslatnal, es a coverage_gap jeloltjei a hibaszintu novelty-leletekbol."""
import os
import sys
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")

from fastapi.testclient import TestClient  # noqa: E402

import aiops  # noqa: E402
import console  # noqa: E402
import detectors  # noqa: E402
import runtime  # noqa: E402
import supervisor  # noqa: E402
from store import Store  # noqa: E402

DRAFT = {"id": "gap-x", "name": "Gap: x", "enabled": False, "query": 'host:=h1 appname:=a "boom boom boom"', "note": "supervisor draft (coverage_gap)"}


def finding(host="h1", ident="agent", level="err", tmpl="Connection to <N> lost: remote end closed the socket <ID>", source="syslog", hits=3):
    return {"ts": "2026-11-21T00:00:00Z", "kind": "new", "key": f"k-{host}-{ident}-{tmpl}"[:60], "source": source, "host": host, "ident": ident,
            "level": level, "tmpl": tmpl, "hits": hits, "baseline": 0}


class HealthTests(IsolatedTestCase):
    def test_flags(self):
        dets = [dict(DRAFT), {"id": "on-quiet", "query": "a"}, {"id": "on-noisy", "query": "b"}, {"id": "off", "query": "c", "enabled": False, "note": "mine"},
                {"id": "broken", "query": "d"}]
        h = {x["id"]: x for x in detectors.health(dets, {"on-noisy": {"n": 25, "last": "2026-11-20T10:00:00Z"}},
                                                  {"broken": {"error": "bad filter"}})}
        self.assertEqual(h["gap-x"]["flags"], ["draft-disabled"])
        self.assertEqual(h["on-quiet"]["flags"], ["quiet"])
        self.assertEqual(h["on-noisy"]["flags"], ["noisy"])
        self.assertEqual(h["on-noisy"]["fired_30d"], 25)
        self.assertEqual(h["off"]["flags"], ["disabled"])
        self.assertIn("error", h["broken"]["flags"])

    def test_overview_report_mentions_waiting_drafts_and_noisy_ones(self):
        snap = {"window_hours": 24, "alerts": [], "detectors": [], "novelty": {}, "proposals": {},
                "detector_health": [{"id": "gap-x", "flags": ["draft-disabled"], "fired_30d": 0}, {"id": "n", "flags": ["noisy"], "fired_30d": 31}]}
        titles = [f["title"] for f in supervisor.rule_report(snap)["findings"]]
        self.assertTrue(any("1 approved detector draft(s) still disabled" in t for t in titles), titles)
        self.assertTrue(any("fired 31 times in 30 days" in t for t in titles), titles)


class FindingDraftTests(IsolatedTestCase):
    def test_draft_uses_host_ident_and_longest_constant_phrase(self):
        d, q = supervisor.finding_detector_draft(finding())
        self.assertEqual(q, 'host:=h1 appname:=agent pipeline:syslog "lost: remote end closed the socket"')
        self.assertFalse(d["enabled"])
        self.assertEqual((d["severity"], d["action"], d["window_min"], d["cooldown_min"]), ("medium", "triage", 60, 1440))
        self.assertTrue(d["note"].startswith("from a new-pattern"))
        self.assertEqual(detectors.validate({"detectors": [d]}), [])

    def test_journald_fields_and_critical_severity(self):
        d, q = supervisor.finding_detector_draft(finding(source="journald", host="nihil", ident="kernel", level="crit", tmpl="Out of memory: Killed process <N>"))
        self.assertTrue(q.startswith("_HOSTNAME:=nihil SYSLOG_IDENTIFIER:=kernel"))
        self.assertEqual(d["severity"], "high")

    def test_refuses_unsafe_unknown_and_duplicates(self):
        with self.assertRaises(ValueError):
            supervisor.finding_detector_draft(finding(host='h"1 | drop'))
        with self.assertRaises(ValueError):
            supervisor.finding_detector_draft(finding(source="webhook"))
        d, q = supervisor.finding_detector_draft(finding())
        with self.assertRaises(ValueError) as cm:
            supervisor.finding_detector_draft(finding(), [dict(d, query=q)])
        self.assertIn("already covered", str(cm.exception))

    def test_short_phrase_gives_a_plain_group_filter(self):
        d, q = supervisor.finding_detector_draft(finding(tmpl="a <N> b"))
        self.assertEqual(q, "host:=h1 appname:=agent pipeline:syslog")


class CoverageCandidatesTests(IsolatedTestCase):
    def test_error_level_novelty_findings_become_candidates(self):
        store = Store()
        store.nov_add_findings([finding(host="cam1", ident="motors-daemon", level="err", tmpl="motor stalled <N>"),
                                finding(host="cam1", ident="chatty", level="info", tmpl="hello <N>")])
        orig = aiops.vl_query
        aiops.vl_query = lambda q, timeout=None: []          # a tar ures: csak a novelty-jeloltek maradnak
        try:
            inp, refs = supervisor.coverage_input(dets=[], store=store)
        finally:
            aiops.vl_query = orig
        got = {(i["host"], i["ident"]) for i in inp["items"]}
        self.assertEqual(got, {("cam1", "motors-daemon")})   # az info szintu nem jelolt
        self.assertTrue(inp["items"][0]["filter"].startswith("host:=cam1 appname:=motors-daemon"))


class ApiTests(IsolatedTestCase):
    R = {"Authorization": "Bearer r-token"}
    A = {"Authorization": "Bearer a-token"}

    def setUp(self):
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.store = self.rt.store
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))
        self.orig_bt, self.orig_fired = supervisor.backtest_query, detectors.fired_30d
        supervisor.backtest_query = lambda q, hours=168: {"hours": hours, "firings": 2, "total": 9}
        detectors.fired_30d = lambda: {"gap-x": {"n": 0, "last": ""}}

    def tearDown(self):
        supervisor.backtest_query, detectors.fired_30d = self.orig_bt, self.orig_fired

    def test_detector_draft_from_finding_files_a_disabled_detector_proposal(self):
        self.store.nov_add_findings([finding()])
        fid = self.store.nov_findings("open")[0]["id"]
        r = self.c.post(f"/api/v1/novelty/{fid}/detector-draft", headers=self.R)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["backtest"]["firings"], 2)
        p = self.c.get(f"/api/v1/proposals/{r.json()['id']}", headers=self.R).json()
        self.assertEqual(p["key"], "detectors")
        self.assertIn("2 firing(s)", p["comment"])
        self.assertEqual(self.c.post("/api/v1/novelty/99999/detector-draft", headers=self.R).status_code, 404)

    def test_too_noisy_backtest_is_refused(self):
        supervisor.backtest_query = lambda q, hours=168: {"hours": hours, "firings": 999, "total": 5000}
        self.store.nov_add_findings([finding()])
        fid = self.store.nov_findings("open")[0]["id"]
        r = self.c.post(f"/api/v1/novelty/{fid}/detector-draft", headers=self.R)
        self.assertEqual(r.status_code, 422)
        self.assertIn("too noisy", r.text)

    def test_approve_with_enable_switches_only_the_new_detector_on(self):
        self.store.nov_add_findings([finding()])
        fid = self.store.nov_findings("open")[0]["id"]
        pid = self.c.post(f"/api/v1/novelty/{fid}/detector-draft", headers=self.R).json()["id"]
        r = self.c.post(f"/api/v1/proposals/{pid}/approve?enable=true", headers=self.A).json()
        self.assertEqual(r["status"], "approved")
        self.assertEqual(len(r["enabled"]), 1)
        dets = {d["id"]: d for d in self.store.current("detectors")["content"]["detectors"]}
        self.assertTrue(dets[r["enabled"][0]]["enabled"])

    def test_approve_without_enable_keeps_it_disabled(self):
        self.store.nov_add_findings([finding()])
        fid = self.store.nov_findings("open")[0]["id"]
        pid = self.c.post(f"/api/v1/novelty/{fid}/detector-draft", headers=self.R).json()["id"]
        r = self.c.post(f"/api/v1/proposals/{pid}/approve", headers=self.A).json()
        self.assertNotIn("enabled", r)
        new = [d for d in self.store.current("detectors")["content"]["detectors"] if d["id"].startswith("pat-")]
        self.assertEqual([d["enabled"] for d in new], [False])

    def test_health_endpoint_counts_waiting_drafts(self):
        cur = (self.store.current("detectors") or {"content": {"detectors": []}})["content"]
        self.store.put("detectors", dict(cur, detectors=list(cur.get("detectors", [])) + [dict(DRAFT)]), "t", "draft")
        h = self.c.get("/api/v1/detectors/health", headers=self.R).json()
        self.assertGreaterEqual(h["counts"]["draft-disabled"], 1)
        self.assertIn("gap-x", {d["id"] for d in h["detectors"]})


if __name__ == "__main__":
    unittest.main()
