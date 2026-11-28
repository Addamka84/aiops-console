"""A javaslatok listaja: lapozas (before + limit) es allapotszuro. Korabban az API csak a legutobbi 50-et adta, a regebbi fuggo
javaslatok a feluleten nem voltak elerhetok."""
import os
import sys
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ["KNOWN_FILE"] = os.path.join(HERE, "fixtures", "known.json")

from fastapi.testclient import TestClient  # noqa: E402

import console  # noqa: E402
import runtime  # noqa: E402
from store import Store  # noqa: E402


class ProposalPagingTests(IsolatedTestCase):
    R = {"Authorization": "Bearer r-token"}

    def setUp(self):
        self.rt = runtime.Runtime(Store())
        self.rt.bootstrap()
        self.c = TestClient(console.create_app(self.rt, tokens={"read": "r-token", "admin": "a-token"}))
        cur = self.rt.store.current("known")["content"]
        for i in range(1, 61):
            self.rt.store.add_proposal("known", cur, "t", f"p{i}", self.rt.store.revision_id("known"))
        for pid in (3, 4):                                        # ket regi javaslat elutasitva, a tobbi fuggo
            self.rt.store.decide(pid, False, "admin")

    def ids(self, **q):
        qs = "&".join(f"{k}={v}" for k, v in q.items())
        return [p["id"] for p in self.c.get("/api/v1/proposals?" + qs, headers=self.R).json()]

    def test_default_page_is_newest_50_and_before_gives_the_older_ones(self):
        first = self.ids()
        self.assertEqual((first[0], first[-1], len(first)), (60, 11, 50))
        self.assertEqual(self.ids(before=first[-1]), list(range(10, 0, -1)))
        self.assertEqual(self.ids(before=1), [])

    def test_status_filter_pages_through_old_pending_ones(self):
        pend = self.ids(status="pending", limit=10, before=12)    # a 12 alatti fuggok: 11, 10, ..., 5, 2, 1
        self.assertEqual(pend, [11, 10, 9, 8, 7, 6, 5, 2, 1])
        self.assertEqual(self.ids(status="rejected"), [4, 3])
        self.assertEqual(len(self.ids(status="pending", limit=200)), 58)

    def test_bad_parameters_are_rejected(self):
        for q in ("status=bogus", "limit=0", "limit=201", "before=0"):
            self.assertEqual(self.c.get("/api/v1/proposals?" + q, headers=self.R).status_code, 422, q)


if __name__ == "__main__":
    unittest.main()
