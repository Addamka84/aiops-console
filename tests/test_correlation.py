"""Alert correlation through the topology (correlation.py + the wiring in aiops.py), evidence aggregation, grounding of model output."""
import os
import sys
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402
import correlation  # noqa: E402
import topology  # noqa: E402

DOC = {"assets": [
    {"id": "router", "kind": "network", "ip": "192.0.2.1", "role": "router"},
    {"id": "homenas2", "kind": "host", "ip": "192.0.2.172", "role": "NAS", "depends_on": [{"id": "router", "type": "network"}]},
    {"id": "homesrv", "kind": "host", "ip": "192.0.2.2", "depends_on": [{"id": "router", "type": "network"}, {"id": "homenas2", "type": "storage"}]},
    {"id": "homesrv3", "kind": "host", "ip": "192.0.2.125", "depends_on": [{"id": "router", "type": "network"}, {"id": "homenas2", "type": "storage"}]},
    {"id": "plex", "kind": "container", "runs_on": "homesrv3", "depends_on": [{"id": "homenas2", "type": "storage"}]},
    {"id": "adguard", "kind": "container", "runs_on": "homesrv"},
    {"id": "homeassistant", "kind": "host", "ip": "192.0.2.102", "depends_on": [{"id": "router", "type": "network"}]},
] + [{"id": f"ha-int{i}", "kind": "service", "runs_on": "homeassistant", "aliases": [f"integration{i}"]} for i in range(45)]}


def item(key, text, cis, ts=0.0):
    return {"key": key, "text": text, "ts": ts, "cis": cis, "alert_labels": [], "detector": None}


class CorrelationTests(IsolatedTestCase):
    def setUp(self):
        self.t = topology.Topology(DOC)

    def test_resolve_cis_by_name_alias_and_ip(self):
        self.assertEqual(correlation.resolve_cis(self.t, ["NFS server 192.0.2.172 not responding (homesrv3)"]), ["homenas2", "homesrv3"])
        self.assertEqual(correlation.resolve_cis(None, ["x"]), [])

    def test_dependent_alerts_cluster_and_unrelated_do_not(self):
        items = [item("nfs", "nfs down", ["homenas2"]), item("plex", "plex errors", ["plex", "homesrv3"]),
                 item("dns", "adguard upstream errors", ["adguard"]), item("none", "no ci", [])]
        groups = correlation.cluster(self.t, items)
        self.assertIn([0, 1], groups)
        self.assertTrue(any(g == [2] for g in groups) or any(2 in g and len(g) > 1 and 1 not in g for g in groups) or [2] in groups)
        self.assertNotIn(2, [i for g in groups if 0 in g for i in g])

    def test_time_window(self):
        items = [item("a", "x", ["homenas2"], 0), item("b", "y", ["homesrv3"], 5000)]
        self.assertEqual(correlation.cluster(self.t, items, window_s=600), [[0], [1]])

    def test_a_hub_is_not_evidence_for_unrelated_siblings(self):
        # two integrations of the same busy HA host (fan-out above the hub limit) must not be merged
        items = [item("a", "integration1 failed", ["ha-int1"]), item("b", "integration2 failed", ["ha-int2"])]
        self.assertEqual(correlation.cluster(self.t, items), [[0], [1]])
        # ... while two containers on a small host are siblings
        items = [item("c", "adguard", ["adguard"]), item("d", "other", ["homesrv"])]
        self.assertEqual(correlation.cluster(self.t, items), [[0, 1]])

    def test_root_cause_is_the_topmost_item_explaining_the_most(self):
        items = [item("plex", "p", ["plex", "homesrv3"]), item("nfs", "n", ["homenas2"]), item("srv", "s", ["homesrv"])]
        info = correlation.analyze(self.t, items)
        self.assertEqual(info["root"], "router" if "router" in info["cis"] else "homenas2")
        self.assertEqual(info["root"], "homenas2")
        self.assertEqual(info["confidence"], 1.0)
        self.assertEqual(info["alerts"], 3)
        self.assertGreaterEqual(info["impacted"], 4)

    def test_independent_origins_with_a_shared_silent_dependency(self):
        items = [item("a", "a", ["homesrv"]), item("b", "b", ["homesrv3"])]    # neither depends on the other; both depend on homenas2/router
        info = correlation.analyze(self.t, items)
        self.assertLess(info["confidence"], 0.8)
        self.assertEqual(info["suspected_dependency"]["ci"], "homenas2")      # the non-hub shared dependency, not the hub router

    def test_describe_marks_the_root_as_a_hypothesis(self):
        info = correlation.analyze(self.t, [item("n", "n", ["homenas2"]), item("p", "p", ["homesrv3"]), item("s", "s", ["homesrv"])])
        text = "\n".join(correlation.describe(self.t, info))
        self.assertIn("HYPOTHESIS", text)
        self.assertIn("homenas2", text)
        self.assertEqual(correlation.describe(self.t, {"root": None}), [])

    def test_no_root_hypothesis_with_a_single_dependent(self):
        """2026-11-25: a NAS SMART alert and an unrelated PulseAudio error on a dependent host became 'root homenas2, confidence 1.0'."""
        info = correlation.analyze(self.t, [item("smart", "DiskSmartFailed homenas2", ["homenas2"]), item("pa", "pulseaudio", ["homesrv3"])])
        self.assertIsNone(info["root"])
        self.assertEqual(info["confidence"], 0.0)
        self.assertEqual(correlation.describe(self.t, info), [])
        single = correlation.analyze(self.t, [item("x", "x", ["homesrv3"])])
        self.assertIsNone(single["root"])


class WiringTests(IsolatedTestCase):
    def setUp(self):
        self.saved = (aiops.TOPOLOGY, dict(aiops.CFG))
        aiops.TOPOLOGY = topology.Topology(DOC)
        aiops.CFG.update({"CORRELATE_MODE": "on", "CORRELATE_SETTLE_S": 90, "CORRELATE_WINDOW_MIN": 10})
        self.state = {"pending": [], "recent_alert_keys": {}, "incident_times": [], "alert_items": []}

    def tearDown(self):
        aiops.TOPOLOGY = self.saved[0]
        aiops.CFG.clear()
        aiops.CFG.update(self.saved[1])

    def test_related_alerts_become_one_incident_after_the_settle_window(self):
        now = aiops.utcnow()
        aiops.queue_alert(self.state, now, "NFS|", "NFS server 192.0.2.172 not responding", [], None)
        aiops.queue_alert(self.state, now, "Plex|", "plex flood on homesrv3 / plex", [{"alertname": "ContainerLogFlood", "host": "homesrv3", "appname": "plex"}], None)
        aiops.queue_alert(self.state, now, "Backup|", "backup to homenas2 failed", [], None)
        self.assertEqual(self.state["pending"], [])                      # still settling
        aiops.flush_alerts(self.state, now)
        self.assertEqual(self.state["pending"], [])
        for it in self.state["alert_items"]:
            it["ts"] -= 100                                                # the settle window has passed
        aiops.flush_alerts(self.state, now)
        self.assertEqual(len(self.state["pending"]), 1)
        job = self.state["pending"][0]
        self.assertEqual(len(job["items"]), 3)
        self.assertEqual(job["correlation"]["root"], "homenas2")
        self.assertIn("2 related alert(s)", job["alert_text"])
        self.assertEqual(self.state["alert_items"], [])
        self.assertEqual(len(self.state["incident_times"]), 1)           # one incident, not three

    def test_unrelated_alerts_stay_separate_incidents(self):
        now = aiops.utcnow()
        aiops.queue_alert(self.state, now, "NFS|", "NFS server 192.0.2.172 not responding", [], None)
        aiops.queue_alert(self.state, now, "HA|", "integration1 failed", [], None)
        for it in self.state["alert_items"]:
            it["ts"] -= 100
        aiops.flush_alerts(self.state, now)
        self.assertEqual(len(self.state["pending"]), 2)

    def test_a_steady_stream_does_not_postpone_the_incident_for_ever(self):
        now = aiops.utcnow()
        aiops.queue_alert(self.state, now, "NFS|", "NFS server 192.0.2.172 not responding", [], None)
        self.state["alert_items"][0]["ts"] -= 4 * 90 + 1                  # waiting for 4 settle windows
        aiops.queue_alert(self.state, now, "Plex|", "plex errors homesrv3", [], None)    # a fresh related alert keeps arriving
        aiops.flush_alerts(self.state, now)
        self.assertEqual(len(self.state["pending"]), 1)

    def test_mode_off_and_missing_topology_create_jobs_immediately(self):
        now = aiops.utcnow()
        aiops.CFG["CORRELATE_MODE"] = "off"
        aiops.queue_alert(self.state, now, "A|", "x homenas2", [], None)
        self.assertEqual((len(self.state["pending"]), self.state["alert_items"]), (1, []))
        aiops.CFG["CORRELATE_MODE"] = "on"
        aiops.TOPOLOGY = None
        aiops.queue_alert(self.state, now, "B|", "y", [], None)
        self.assertEqual(len(self.state["pending"]), 2)
        self.assertEqual(self.state["pending"][1]["items"][0]["text"], "y")

    def test_detector_hit_becomes_an_item_with_its_group_resolved(self):
        now = aiops.utcnow()
        det = {"id": "nfs", "name": "NFS", "query": "q", "mode": "count", "group": {"_HOSTNAME": "homesrv3"}, "window_min": 15}
        aiops.queue_alert(self.state, now, "det:nfs|{}", "[DETECTOR] NFS: 3 matching lines", [], det)
        self.assertEqual(self.state["alert_items"][0]["cis"], ["homesrv3"])
        self.assertEqual(self.state["alert_items"][0]["detector"]["id"], "nfs")


class EvidenceAggregationTests(IsolatedTestCase):
    def setUp(self):
        self.saved = aiops.item_evidence

    def tearDown(self):
        aiops.item_evidence = self.saved

    def run_with(self, results):
        it = iter(results)
        aiops.item_evidence = lambda item, known, a, b: next(it)
        job = {"items": [{"text": str(i)} for i in range(len(results))]}
        return aiops.alert_evidence(job, None, None, None)

    def test_all_noise_skips_but_one_unknown_item_does_not(self):
        noise = {"kept": [], "suppressed": 4, "total": 4}
        self.assertEqual(self.run_with([noise, noise]), {"kept": [], "suppressed": 8, "total": 8})      # every item is noise: skip
        self.assertIsNone(self.run_with([noise, None]))                                                  # an item without evidence: cannot be called noise

    def test_kept_lines_of_all_items_are_combined(self):
        r = self.run_with([{"kept": ["a"], "suppressed": 1, "total": 2}, None, {"kept": ["b"], "suppressed": 0, "total": 1}])
        self.assertEqual((r["kept"], r["suppressed"], r["total"]), (["a", "b"], 1, 3))

    def test_a_job_without_items_behaves_as_before(self):
        aiops.item_evidence = lambda item, known, a, b: {"kept": ["x"], "suppressed": 0, "total": 1} if item.get("alert_text") == "t" else None
        self.assertEqual(aiops.alert_evidence({"alert_text": "t"}, None, None, None)["kept"], ["x"])


class GroundingTests(IsolatedTestCase):
    def test_names_missing_from_the_input_are_removed_but_the_issue_stays(self):
        issues = [{"title": "t", "hosts": ["homesrv3", "ghost-server"], "severity": "high"}, {"title": "u", "hosts": []}]
        out, removed = aiops.ground_issues(issues, "alerts about HOMESRV3 and plex")
        self.assertEqual((out[0]["hosts"], removed, out[0]["title"]), (["homesrv3"], 1, "t"))
        self.assertEqual(out[1]["hosts"], [])


class RunJobInputTests(IsolatedTestCase):
    def test_the_model_sees_the_related_alerts_and_the_hypothesis(self):
        saved = (aiops.TOPOLOGY, aiops.collect, aiops.review_stats, aiops.ollama_chat, aiops.vl_query, aiops.vl_insert, aiops.build_input)
        seen = {}
        aiops.TOPOLOGY = topology.Topology(DOC)
        aiops.collect = lambda a, b: {"a": [], "b": [], "c": [], "e": [], "d": []}
        aiops.review_stats = lambda *a, **k: {}
        aiops.vl_query = lambda q, timeout=None: []
        aiops.vl_insert = lambda ev, timeout=None: None

        def spy(known, a, b, extra_lines=None, raw=None):
            seen["extra"] = list(extra_lines or [])
            return "plan homenas2 homesrv3 router"

        def fake_chat(url, system, user):
            seen["system"] = system
            return {"message": {"content": '{"summary":"s","all_clear":false,"issues":[{"id":"i","title":"NAS down","severity":"high","status":"new",'
                                           '"known_issue":false,"hosts":["homenas2","made-up-host"],"evidence":"e","likely_cause":"c","suggested_action":"a"}]}'},
                    "prompt_eval_count": 1, "eval_count": 1}
        aiops.build_input, aiops.ollama_chat = spy, fake_chat

        class Pool:
            def pick(self):
                return {"url": "http://x"}

            def mark_down(self, ep, why):
                pass
        t = topology.Topology(DOC)
        items = [item("n", "NFS server 192.0.2.172 not responding", ["homenas2"], 0), item("p", "plex errors", ["homesrv3"], 0),
                 item("s", "homesrv nfs stale", ["homesrv"], 0)]
        corr = correlation.analyze(t, items)
        job = {"kind": "incident", "key": "k", "alert_text": "NFS server 192.0.2.172 not responding", "alert_labels": [], "correlation": corr,
               "items": [{"text": i["text"], "alert_labels": [], "detector": None} for i in items],
               "window_from": "2026-11-16T00:00:00Z", "window_to": "2026-11-16T01:00:00Z"}
        try:
            res = aiops.run_job(job, aiops.Known(data={"noise": [], "known_issues": [], "context": []}), Pool())
        finally:
            (aiops.TOPOLOGY, aiops.collect, aiops.review_stats, aiops.ollama_chat, aiops.vl_query, aiops.vl_insert, aiops.build_input) = saved
        self.assertEqual(res, "done")
        text = "\n".join(seen["extra"])
        self.assertIn("Related alerts grouped into this incident (2 more)", text)
        self.assertIn("Root-cause HYPOTHESIS", text)
        self.assertIn("ONE incident", seen["system"])
        self.assertEqual(aiops.STATUS["last_incident"]["issues"][0]["hosts"], ["homenas2"])     # the invented host was removed
        self.assertEqual(aiops.STATUS["last_incident"]["ungrounded_hosts"], 1)
        self.assertEqual(aiops.STATUS["last_incident"]["correlated_alerts"], 3)


if __name__ == "__main__":
    unittest.main()
