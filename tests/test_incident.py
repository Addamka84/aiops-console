"""Incidens-elemzes megalapozasa: a riasztas mogotti tenyleges sorok a bemenetben, zajjal lefedett riasztas kimarad.
Futtatas (a stacks/aiops-console mappabol): python3 -m unittest discover -s tests
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("STATE_FILE", os.path.join(os.environ.get("TEMP", "/tmp"), "aiops-test-state.json"))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import aiops  # noqa: E402

I915 = "i915 <N>:<N>:<N>.<N>: [drm] *ERROR* Atomic update failure on pipe A (start=<N> end=<N>) time <N> us"
ALERTS = json.dumps([{"labels": {"alertname": "JournaldCritical", "host": "homesrv3", "SYSLOG_IDENTIFIER": "kernel", "severity": "warning"}}])
WIN = {"window_from": "2026-11-16T06:54:00Z", "window_to": "2026-11-16T07:14:00Z"}


def known(noise=()):
    return aiops.Known(data={"noise": list(noise), "known_issues": [], "context": []})


class Pool:
    def __init__(self):
        self.picked = 0

    def pick(self):
        self.picked += 1
        return {"url": "http://x"}  # van vegpont; a hamis modell hibaja utan a munka 'retry'


    def mark_down(self, ep, why):
        pass


class Base(unittest.TestCase):
    def setUp(self):
        self.saved = (aiops.vl_query, aiops.vl_insert, aiops.collect, aiops.build_input, aiops.review_stats, aiops.ollama_chat)
        self.queries, self.inserted, self.extra = [], [], []
        self.evidence_rows = [{"_msg": I915, "hits": "1"}]

        def q(query, timeout=None):
            self.queries.append(query)
            return list(self.evidence_rows)

        def bi(kn, a, b, extra_lines=None, raw=None):
            self.extra.append(extra_lines)
            return "input"

        def no_model(*a, **k):
            raise aiops.OllamaError("stop")
        aiops.vl_query = q
        aiops.vl_insert = lambda ev, timeout=None: self.inserted.extend(ev)
        aiops.collect, aiops.build_input, aiops.review_stats, aiops.ollama_chat = lambda a, b: {}, bi, lambda *a, **k: {}, no_model

    def tearDown(self):
        aiops.vl_query, aiops.vl_insert, aiops.collect, aiops.build_input, aiops.review_stats, aiops.ollama_chat = self.saved
        aiops.STATUS.pop("last_skipped_incident", None)

    def job(self, labels=None, kind="incident"):
        return dict(WIN, kind=kind, key="JournaldCritical|", alert_text="[FIRING] JournaldCritical x1 Hiba/kritikus journal-sor: homesrv3 / kernel (1 db)",
                    alert_labels=labels if labels is not None else aiops.alert_labels(ALERTS, "JournaldCritical"))


class AlertLabelTests(unittest.TestCase):
    def test_labels_are_parsed_and_limited(self):
        self.assertEqual(aiops.alert_labels(ALERTS, "JournaldCritical"),
                         [{"alertname": "JournaldCritical", "host": "homesrv3", "SYSLOG_IDENTIFIER": "kernel", "severity": "warning"}])
        many = json.dumps([{"labels": {"alertname": "A", "host": f"h{i}"}} for i in range(9)])
        self.assertEqual(len(aiops.alert_labels(many)), 4)

    def test_bad_input_falls_back_to_the_alert_name(self):
        self.assertEqual(aiops.alert_labels("", "X"), [{"alertname": "X"}])
        self.assertEqual(aiops.alert_labels("not json", "X"), [{"alertname": "X"}])
        self.assertEqual(aiops.alert_labels("", ""), [])


class GroundingTests(Base):
    def test_noise_covered_alert_is_skipped_without_the_model(self):
        pool = Pool()
        res = aiops.run_job(self.job(), known(noise=[r"i915 .*\[drm\] \*ERROR\* Atomic update failure"]), pool)
        self.assertEqual(res, "done")
        self.assertEqual(pool.picked, 0)                    # nincs modellhivas, nincs vegpont-probe
        self.assertEqual(self.extra, [])                    # a bemenetet sem epitettuk
        self.assertEqual([e["kind"] for e in self.inserted], ["incident_skipped"])
        self.assertIn("covered by noise", self.inserted[0]["reason"])
        self.assertIn("last_skipped_incident", aiops.STATUS)

    def test_snooze_and_known_issue_also_count(self):
        k = aiops.Known(data={"noise": [], "context": [], "known_issues": [{"id": "gpu", "note": "i915", "match": "Atomic update failure"}]})
        self.assertEqual(aiops.run_job(self.job(), k, Pool()), "done")
        self.assertEqual(len(self.inserted), 1)

    def test_real_line_reaches_the_model_input(self):
        self.evidence_rows = [{"_msg": "EXT4-fs error (device sda1): ext4_find_entry", "hits": "3"}, {"_msg": I915, "hits": "2"}]
        pool = Pool()
        self.assertEqual(aiops.run_job(self.job(), known(noise=["i915"]), pool), "retry")
        self.assertEqual(pool.picked, 1)
        text = "\n".join(self.extra[0])
        self.assertIn("Log lines behind the alert", text)
        self.assertIn("EXT4-fs error", text)
        self.assertNotIn("i915", text.split("behind the alert")[1].split("removed as known-harmless")[0])  # a zajsor nem kerul be
        self.assertIn("2 more lines", text)
        self.assertEqual(self.inserted, [])

    def test_query_is_scoped_to_the_host_and_source(self):
        aiops.run_job(self.job(), known(), Pool())
        q = self.queries[0]
        self.assertIn('_HOSTNAME:"homesrv3"', q)
        self.assertIn('SYSLOG_IDENTIFIER:"kernel"', q)
        self.assertIn("PRIORITY:in(0,1,2,3)", q)

    def test_unsafe_labels_are_not_queried(self):
        labs = [{"alertname": "JournaldCritical", "host": 'x" or 1', "SYSLOG_IDENTIFIER": "kernel"}]
        self.assertIsNone(aiops.alert_evidence(self.job(labs), known(), aiops.utcnow(), aiops.utcnow()))
        self.assertEqual(self.queries, [])

    def test_unsupported_alerts_keep_the_old_behaviour(self):
        pool = Pool()
        job = self.job([{"alertname": "ContainerLogFlood", "host": "homesrv3", "appname": "plex"}])
        self.assertEqual(aiops.run_job(job, known(noise=["plex"]), pool), "retry")
        self.assertEqual((pool.picked, self.queries), (1, []))
        self.assertEqual(self.extra[0][0], "== ALERT that triggered this analysis:")

    def test_no_lines_found_says_unknown_cause(self):
        self.evidence_rows = []
        self.assertEqual(aiops.run_job(self.job(), known(), Pool()), "retry")  # nem kihagyas: nincs bizonyitek arra, hogy zaj
        self.assertIn("could NOT be retrieved", "\n".join(self.extra[0]))

    def test_vl_error_does_not_block_the_incident(self):
        def boom(q, timeout=None):
            raise OSError("vl down")
        aiops.vl_query = boom
        self.assertEqual(aiops.run_job(self.job(), known(), Pool()), "retry")
        self.assertIn("could NOT be retrieved", "\n".join(self.extra[0]))

    def test_digest_is_not_affected(self):
        pool = Pool()
        self.assertEqual(aiops.run_job(self.job(kind="digest"), known(noise=["i915"]), pool), "retry")
        self.assertEqual((pool.picked, self.queries), (1, []))

    def test_prompt_demands_grounded_severity(self):
        self.assertIn("never the alert's name", aiops.INCIDENT_PROMPT_EXTRA)
        self.assertIn("causal link", aiops.INCIDENT_PROMPT_EXTRA)


class PollTests(Base):
    def test_job_carries_the_alert_labels(self):
        self.evidence_rows = [{"_time": "2026-11-16T07:10:00.5Z", "alertname": "JournaldCritical", "alert_root": "", "alert_count": "1",
                               "alerts": ALERTS, "_msg": "[FIRING] JournaldCritical x1"}]
        state = {"pending": [], "last_alert_ts": "2026-11-16T07:00:00.000000Z", "recent_alert_keys": {}, "incident_times": []}
        aiops.poll_incidents(state, aiops.dt.datetime(2026, 11, 16, 7, 14, tzinfo=aiops.dt.timezone.utc))
        self.assertIn("alerts", self.queries[0])
        job = state["pending"][0]
        self.assertEqual((job["kind"], job["alert_labels"][0]["host"], job["alert_labels"][0]["SYSLOG_IDENTIFIER"]), ("incident", "homesrv3", "kernel"))


if __name__ == "__main__":
    unittest.main()
