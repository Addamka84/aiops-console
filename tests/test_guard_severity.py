"""Az incidens-kimenet determinisztikus vedelme: err-szintu bizonyitekra legfeljebb 'medium', bizonyitatlan szolgaltatasnevre legfeljebb 'low'."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")

import aiops  # noqa: E402


class K:
    context = ["nihil: public server running game servers and the production Immich instance.", "homesrv3: media server (Plex, Sonarr)."]


def issue(sev="critical", title="Network Connectivity Failure on nihil (Production Immich)", evidence="Connection reset by peer", cause="network"):
    return {"id": "i1", "title": title, "severity": sev, "status": "new", "known_issue": False, "hosts": ["nihil"],
            "evidence": evidence, "likely_cause": cause, "suggested_action": "check"}


USER = "nihil | sshd-session | 1x | error: kex_exchange_identification: read: Connection reset by peer"


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.vocab = aiops.vocabulary(K())

    def test_vocabulary_takes_mid_sentence_proper_names_only(self):
        self.assertIn("immich", self.vocab)
        self.assertIn("plex", self.vocab)
        self.assertNotIn("nihil", self.vocab)       # a sor eleji gepnev nem 'tulajdonnev' a szabaly szerint

    def test_generic_words_from_topology_and_context_are_not_service_names(self):
        import topology
        saved = aiops.TOPOLOGY
        aiops.TOPOLOGY = topology.Topology({"assets": [{"id": "smrt-remote-guest", "name": "Remote", "role": "network device (remote access)", "type": "device"},
                                                       {"id": "homesrv3", "name": "homesrv3", "type": "host"}]})
        try:
            v = aiops.vocabulary(type("K2", (), {"context": ["homesrv3: Network storage and Remote access (Plex, Matter bridge)."]})())
        finally:
            aiops.TOPOLOGY = saved
        self.assertIn("homesrv3", v)
        self.assertIn("plex", v)
        for generic in ("network", "remote", "storage", "access", "matter", "guest"):
            self.assertNotIn(generic, v)

    def test_unsupported_service_caps_to_low_and_notes_it(self):
        out, notes = aiops.guard_severity([issue()], USER, {"kept": ["x"], "prio": 0}, self.vocab)
        self.assertEqual(out[0]["severity"], "low")
        self.assertTrue(any("immich" in n for n in notes), notes)

    def test_err_only_evidence_caps_to_medium(self):
        out, notes = aiops.guard_severity([issue(title="SSH reset")], USER, {"kept": ["x"], "prio": 3}, self.vocab)
        self.assertEqual(out[0]["severity"], "medium")
        self.assertIn("error-level only", notes[0])

    def test_crit_priority_evidence_keeps_the_model_severity(self):
        out, notes = aiops.guard_severity([issue(title="SSH reset")], USER, {"kept": ["x"], "prio": 2}, self.vocab)
        self.assertEqual(out[0]["severity"], "critical")
        self.assertEqual(notes, [])

    def test_no_priority_info_means_no_cap(self):      # detektor / ismeretlen bizonyitek: a vedelem nem nyul hozza
        out, _ = aiops.guard_severity([issue(title="SSH reset")], USER, {"kept": ["x"], "prio": None}, self.vocab)
        self.assertEqual(out[0]["severity"], "critical")
        out, _ = aiops.guard_severity([issue(title="SSH reset")], USER, None, self.vocab)
        self.assertEqual(out[0]["severity"], "critical")

    def test_service_present_in_the_input_is_fine(self):
        out, notes = aiops.guard_severity([issue()], USER + " immich-server crashed", {"kept": ["x"], "prio": 0}, self.vocab)
        self.assertEqual(out[0]["severity"], "critical")
        self.assertEqual(notes, [])

    def test_lower_severity_is_never_raised(self):
        out, _ = aiops.guard_severity([issue(sev="info")], USER, {"kept": ["x"], "prio": 3}, self.vocab)
        self.assertEqual(out[0]["severity"], "info")

    def test_alert_evidence_combines_priorities_only_when_all_known(self):
        saved = aiops.item_evidence
        try:
            seq = iter([{"kept": ["a"], "suppressed": 0, "total": 1, "prio": 3}, {"kept": ["b"], "suppressed": 0, "total": 1, "prio": 2}])
            aiops.item_evidence = lambda item, known, a, b: next(seq)
            self.assertEqual(aiops.alert_evidence({"items": [{}, {}]}, None, None, None)["prio"], 2)
            seq = iter([{"kept": ["a"], "suppressed": 0, "total": 1, "prio": 3}, {"kept": ["b"], "suppressed": 0, "total": 1}])
            aiops.item_evidence = lambda item, known, a, b: next(seq)
            self.assertIsNone(aiops.alert_evidence({"items": [{}, {}]}, None, None, None)["prio"])
        finally:
            aiops.item_evidence = saved


if __name__ == "__main__":
    unittest.main()
