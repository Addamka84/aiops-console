"""The image tag in the shipped compose files must match aiops.__version__ (a release with a stale tag fails CI)."""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
COMPOSE = ["demo/docker-compose.yml", "docker-compose.example.yml"]
TAG_RX = re.compile(r"aiops-console:v([0-9A-Za-z.\-]+)")


def source_version():
    src = open(os.path.join(ROOT, "src", "aiops.py"), encoding="utf-8").read()
    m = re.search(r'^__version__ = "([^"]+)"$', src, re.M)
    return m.group(1) if m else None


class VersionConsistency(unittest.TestCase):
    def test_version_is_semver(self):
        self.assertRegex(source_version() or "", r"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$")

    def test_compose_tags_match_source(self):
        ver = source_version()
        for rel in COMPOSE:
            with self.subTest(file=rel):
                tags = TAG_RX.findall(open(os.path.join(ROOT, rel), encoding="utf-8").read())
                self.assertTrue(tags, f"{rel}: no aiops-console image tag")
                self.assertEqual(set(tags), {ver}, f"{rel}: image tag {tags} != __version__ {ver}")

    def test_git_tag_matches_source(self):
        # CI on a tag push: the tag (vX) must name the version in the code
        ref = os.environ.get("GITHUB_REF", "")
        if not ref.startswith("refs/tags/v"):
            self.skipTest("not a tag build")
        self.assertEqual(ref[len("refs/tags/v"):], source_version())


if __name__ == "__main__":
    unittest.main()
