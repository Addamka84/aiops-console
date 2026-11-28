"""Common test base: every test starts from, and leaves behind, the same module-level state, and leaves no thread running.

Why: the services keep state in module globals (aiops.CFG, rulesync._worker, ...) and start background threads. A test that
changed a global or left a thread behind could make a later test fail only sometimes (2026-11-27: a rules-sync worker of an
earlier test wrote into that test's store while the next test was running).

What IsolatedTestCase does around each test (after the test's own tearDown and cleanups):
- waits up to THREAD_GRACE_S for the threads the test started, then FAILS the test if any is still running;
- restores the watched globals (dicts and lists in place, so references held elsewhere stay valid), drains the work queues
  and resets the wake-up events.
Class-level state (setUpClass) is outside this scope: it is snapshotted as part of the first test's starting state.
"""
import copy
import queue
import sys
import threading
import time
import unittest

THREAD_GRACE_S = 5.0

# module -> global names that tests (or the code under test) change. Only modules already imported are handled.
WATCHED = {
    "aiops": ("CFG", "DETECTORS", "DETECTOR_STATUS", "TOPOLOGY", "DIGEST_EXTRAS", "STATUS", "POOL", "_CHECK"),
    "maintenance": ("_ACTIVE",),
    "novelty": ("STATE",),
    "rulesync": ("STATE", "_worker"),
    "supervisor": ("STATE", "GET_KNOWN"),
}
QUEUES = {"aiops": ("COMMANDS", "DETECTOR_HITS")}
EVENTS = {"aiops": ("WAKE",), "supervisor": ("RUN_NOW",)}


def _copy(v):
    try:
        return copy.deepcopy(v)
    except Exception:  # noqa: BLE001 - threads, locks, stores: keep the references, copy only the container
        return copy.copy(v)


def snapshot():
    snap = {}
    for mod_name, names in WATCHED.items():
        mod = sys.modules.get(mod_name)
        if mod is None:
            continue
        for n in names:
            if hasattr(mod, n):
                v = getattr(mod, n)
                snap[(mod_name, n)] = (v, _copy(v) if isinstance(v, (dict, list)) else None)
    for mod_name, names in EVENTS.items():
        mod = sys.modules.get(mod_name)
        for n in names if mod else ():
            snap[(mod_name, n, "event")] = getattr(mod, n).is_set()
    return snap


def restore(snap):
    for key, val in snap.items():
        mod = sys.modules.get(key[0])
        if mod is None:
            continue
        if len(key) == 3:  # event
            ev = getattr(mod, key[1])
            ev.set() if val else ev.clear()
            continue
        obj, saved = val
        if isinstance(obj, dict) and saved is not None:
            obj.clear()
            obj.update(saved)
        elif isinstance(obj, list) and saved is not None:
            obj[:] = saved
        setattr(mod, key[1], obj)
    for mod_name, names in QUEUES.items():
        mod = sys.modules.get(mod_name)
        for n in names if mod else ():
            q = getattr(mod, n)
            while True:
                try:
                    q.get_nowait()
                except queue.Empty:
                    break


def wait_for_threads(before, grace=THREAD_GRACE_S):
    """Joins the threads started since `before` (a set of Thread objects); returns those still alive after `grace` seconds."""
    deadline = time.monotonic() + grace
    for t in threading.enumerate():
        if t in before or t is threading.current_thread():
            continue
        t.join(max(0.0, deadline - time.monotonic()))
    return [t for t in threading.enumerate() if t not in before and t.is_alive()]


class IsolatedTestCase(unittest.TestCase):
    """unittest.TestCase with a state restore and a thread-leak check around every test (see the module docstring)."""

    def _callSetUp(self):
        # Registered before setUp, so it runs last: after tearDown and after every cleanup the test itself registered.
        self.__snap = snapshot()
        self.__threads = set(threading.enumerate())
        self.addCleanup(self.__isolation_check)
        super()._callSetUp()

    def __isolation_check(self):
        left = wait_for_threads(self.__threads)
        restore(self.__snap)
        if left:
            names = ", ".join(sorted(t.name for t in left))
            self.fail(f"thread(s) still running {THREAD_GRACE_S:.0f} s after the test: {names}. "
                      "Stop or join every thread the test starts (see tests/_base.py).")
