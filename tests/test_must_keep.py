"""A must_keep kapu: a known-dokumentum cimkezett mintasorait semmilyen elnyelo szabaly (zaj / snooze) nem takarhatja el;
a Supervisor javaslata, a kezi PUT es a jovahagyas is ugyanazon az ellenorzon megy at (aiops.validate_known)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")

import aiops  # noqa: E402
import runtime  # noqa: E402
import supervisor  # noqa: E402

CRIT = "esx-01 | dynatrace | Problem P-<N>: Host unavailable esx-01"
HB = "esx-01 | dynatrace | OneAgent heartbeat OK, version <N>"


class MustKeepTests(unittest.TestCase):
    def test_validate_shape(self):
        self.assertEqual(aiops.validate_known({"must_keep": [CRIT]}), [])
        for bad in ("x", [1], [""], ["a" * 301], ["x"] * 201):
            self.assertTrue(aiops.validate_known({"must_keep": bad}), bad)

    def test_validate_rejects_noise_and_snooze_that_swallow_a_must_keep_line(self):
        errs = aiops.validate_known({"must_keep": [CRIT], "noise": [r"\| dynatrace \| Problem P-"]})
        self.assertTrue(any("noise[0]" in e and "must_keep" in e for e in errs), errs)
        sn = {"id": "s", "regex": "Host unavailable", "until": "2999-01-01T00:00:00Z"}
        errs = aiops.validate_known({"must_keep": [CRIT], "snoozes": [sn]})
        self.assertTrue(any("snoozes[0]" in e for e in errs), errs)
        self.assertEqual(aiops.validate_known({"must_keep": [CRIT], "noise": [r"\| dynatrace \| OneAgent heartbeat OK"]}), [])

    def test_conflict_handles_number_placeholder_and_bad_input(self):
        self.assertEqual(aiops.must_keep_conflict(r"P-\d+: Host", [CRIT]), CRIT)        # <N> helyett szam is probalva
        self.assertIsNone(aiops.must_keep_conflict(r"heartbeat", [CRIT]))
        self.assertIsNone(aiops.must_keep_conflict("(unclosed", [CRIT]))
        self.assertIsNone(aiops.must_keep_conflict(r"x", []))

    def test_supervisor_rejects_regex_matching_must_keep(self):
        refs = [HB]
        rx = r"esx-01 \| dynatrace \| \S+ "          # a heartbeatre es a kritikus sorra is illeszkedik (alternacio nelkul: alpha.30)
        self.assertIsNone(supervisor.check_noise_regex(rx, refs, []))                    # must_keep nelkul atmenne
        reason = supervisor.check_noise_regex(rx, refs, [], [CRIT])
        self.assertIn("must_keep", reason or "")
        self.assertIsNone(supervisor.check_noise_regex(r"dynatrace \| OneAgent heartbeat OK, version <N>", refs, [], [CRIT]))

    def test_apply_noise_patch_blocked_by_validate_doc(self):
        cur = {"must_keep": [CRIT], "noise": []}
        with self.assertRaises(runtime.DocError):
            runtime.validate_doc("known", runtime.apply_known_patch(cur, {"add_noise": [r"\| dynatrace \| Problem P-"]}))
        ok = runtime.validate_doc("known", runtime.apply_known_patch(cur, {"add_noise": [r"\| dynatrace \| OneAgent heartbeat OK"]}))
        self.assertEqual(ok["must_keep"], [CRIT])                                        # a patch nem bantja a must_keep-et


if __name__ == "__main__":
    unittest.main()
