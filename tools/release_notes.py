"""Print the CHANGELOG.md entry of one version (the GitHub Release notes of its tag).

Usage: python tools/release_notes.py 2.0.0-alpha.44 [CHANGELOG.md]   -> exit 1 if the version has no entry or it is empty.
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def entry(version, text):
    """The body under '## [version]' up to the next '## ' heading, stripped; None if there is no such heading."""
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    return m.group(1).strip() if m else None


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    path = argv[2] if len(argv) > 2 else os.path.join(ROOT, "CHANGELOG.md")
    body = entry(argv[1], open(path, encoding="utf-8").read())
    if not body:
        print(f"CHANGELOG.md has no entry for {argv[1]}", file=sys.stderr)
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
