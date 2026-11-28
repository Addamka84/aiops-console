"""The image tag in the shipped compose files must match aiops.__version__ (a release with a stale tag fails CI)."""
import os
import re
import sys
import unittest
from _base import IsolatedTestCase

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
COMPOSE = ["demo/docker-compose.yml", "docker-compose.example.yml"]
TAG_RX = re.compile(r"aiops-console:v([0-9A-Za-z.\-]+)")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import release_notes  # noqa: E402


def source_version():
    src = open(os.path.join(ROOT, "src", "aiops.py"), encoding="utf-8").read()
    m = re.search(r'^__version__ = "([^"]+)"$', src, re.M)
    return m.group(1) if m else None


class VersionConsistency(IsolatedTestCase):
    def test_version_is_semver(self):
        self.assertRegex(source_version() or "", r"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$")

    def test_compose_tags_match_source(self):
        ver = source_version()
        for rel in COMPOSE:
            with self.subTest(file=rel):
                tags = TAG_RX.findall(open(os.path.join(ROOT, rel), encoding="utf-8").read())
                self.assertTrue(tags, f"{rel}: no aiops-console image tag")
                self.assertEqual(set(tags), {ver}, f"{rel}: image tag {tags} != __version__ {ver}")

    def test_changelog_has_entry_for_source_version(self):
        # the tag build publishes this entry as the GitHub Release notes; no entry = no release
        text = open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
        body = release_notes.entry(source_version(), text)
        self.assertTrue(body, f"CHANGELOG.md: no entry for {source_version()}")
        self.assertNotIn("\n## ", "\n" + body, "the entry must stop at the next version heading")

    def test_release_notes_extract_one_version(self):
        text = "# Changelog\n\n## [1.0.0-alpha.2] - 2026-01-02\n\n### B\n- two\n\n## [1.0.0-alpha.1] - 2026-01-01\n\n- one\n"
        self.assertEqual(release_notes.entry("1.0.0-alpha.2", text), "### B\n- two")
        self.assertEqual(release_notes.entry("1.0.0-alpha.1", text), "- one")
        self.assertIsNone(release_notes.entry("1.0.0-alpha.", text))
        self.assertIsNone(release_notes.entry("1.0.0-alpha.3", text))

    def test_git_tag_matches_source(self):
        # CI on a tag push: the tag (vX) must name the version in the code
        ref = os.environ.get("GITHUB_REF", "")
        if not ref.startswith("refs/tags/v"):
            self.skipTest("not a tag build")
        self.assertEqual(ref[len("refs/tags/v"):], source_version())


if __name__ == "__main__":
    unittest.main()
