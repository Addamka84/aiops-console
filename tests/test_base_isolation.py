"""The test base itself: a leaked thread fails the test, and the watched globals are restored after it."""
import os
import sys
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
import _base  # noqa: E402
import aiops  # noqa: E402
import rulesync  # noqa: E402
from _base import IsolatedTestCase  # noqa: E402


def _run_inner(case_cls, name):
    result = unittest.TestResult()
    case_cls(name).run(result)
    return result


class IsolationTests(IsolatedTestCase):
    def test_leaked_thread_fails_the_test(self):
        stop = threading.Event()

        class Inner(IsolatedTestCase):
            def test_leak(self):
                threading.Thread(target=stop.wait, name="leaky-thread", daemon=True).start()

        with mock.patch.object(_base, "THREAD_GRACE_S", 0.2):
            result = _run_inner(Inner, "test_leak")
        stop.set()
        self.assertEqual(len(result.errors) + len(result.failures), 1)
        self.assertIn("leaky-thread", (result.errors + result.failures)[0][1])

    def test_finished_thread_passes(self):
        class Inner(IsolatedTestCase):
            def test_short(self):
                threading.Thread(target=lambda: None, name="short-thread").start()

        self.assertTrue(_run_inner(Inner, "test_short").wasSuccessful())

    def test_globals_are_restored_in_place(self):
        cfg, worker = aiops.CFG, rulesync._worker
        before_timeout, before_store = cfg.get("GEN_TIMEOUT"), worker.get("store")

        class Inner(IsolatedTestCase):
            def test_mutate(self):
                aiops.CFG["GEN_TIMEOUT"] = 12345
                aiops.CFG["ZZ_NEW_KEY"] = 1
                rulesync._worker["store"] = object()
                aiops.TOPOLOGY = object()
                aiops.COMMANDS.put("x")
                aiops.WAKE.set()

        topo = aiops.TOPOLOGY
        wake = aiops.WAKE.is_set()
        self.assertTrue(_run_inner(Inner, "test_mutate").wasSuccessful())
        self.assertIs(aiops.CFG, cfg)  # same object: references held elsewhere stay valid
        self.assertEqual(aiops.CFG.get("GEN_TIMEOUT"), before_timeout)
        self.assertNotIn("ZZ_NEW_KEY", aiops.CFG)
        self.assertIs(rulesync._worker.get("store"), before_store)
        self.assertIs(aiops.TOPOLOGY, topo)
        self.assertTrue(aiops.COMMANDS.empty())
        self.assertEqual(aiops.WAKE.is_set(), wake)


if __name__ == "__main__":
    unittest.main()
