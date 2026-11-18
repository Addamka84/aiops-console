"""Kornyezet: a konzol forrasa (src/) az importutvonalra kerul, az allapotfajl idoleges (az eval semmit nem ir az eles allapotba)."""
import os
import sys
import tempfile

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)
os.environ.setdefault("STATE_FILE", os.path.join(tempfile.gettempdir(), "evalkit-state.json"))
