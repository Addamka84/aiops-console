"""Futasideju osszekotes: a konfig-tar, a hatterszal (aiops) es a konzol kozott.

- bootstrap(): az elso inditaskor a known-dokumentum betoltese (KNOWN_FILE vagy a beepitett alap)
- get_known(): a hatterszal hivja minden kor elejen; a konfig valtozasat (verzio-azonosito) azonnal felveszi
- validate_doc()/apply_known_patch(): a javaslatok es a PUT-ok kozos ellenorzese
"""
import copy
import json
import os
import threading
import time

import aiops
import settings

DEFAULTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "defaults", "known.default.json")
KEYS = ("known", "settings")


class DocError(Exception):
    def __init__(self, errors):
        super().__init__("; ".join(errors))
        self.errors = errors


def validate_doc(key, content):
    """-> tisztitott dokumentum; DocError ha ervenytelen."""
    if key == "known":
        errs = aiops.validate_known(content)
        if errs:
            raise DocError(errs)
        return content
    if key == "settings":
        clean, errs = settings.validate(content)
        if errs:
            raise DocError(errs)
        return clean
    raise DocError([f"unknown config key {key!r} (expected one of {', '.join(KEYS)})"])


PATCH_KEYS = ("add_noise", "remove_noise", "add_known_issues", "remove_known_issue_ids", "set_context")


def apply_known_patch(doc, patch):
    """Kis, kovetheto modositas a known-dokumentumon (a javaslatok diffje kicsi marad). -> uj dokumentum"""
    if not isinstance(patch, dict):
        raise DocError(["patch must be an object"])
    errs = [f"{k}: unknown patch key (expected {', '.join(PATCH_KEYS)})" for k in patch if k not in PATCH_KEYS]
    if errs:
        raise DocError(errs)
    d = copy.deepcopy(doc)
    d.setdefault("noise", [])
    d.setdefault("known_issues", [])
    for rx in patch.get("remove_noise", []):
        if rx not in d["noise"]:
            errs.append(f"remove_noise: no such noise regex: {rx!r}")
        else:
            d["noise"].remove(rx)
    for rx in patch.get("add_noise", []):
        if rx in d["noise"]:
            errs.append(f"add_noise: already present: {rx!r}")
        else:
            d["noise"].append(rx)
    ids = [k.get("id") for k in d["known_issues"] if isinstance(k, dict)]
    for kid in patch.get("remove_known_issue_ids", []):
        if kid not in ids:
            errs.append(f"remove_known_issue_ids: no such id: {kid!r}")
        else:
            d["known_issues"] = [k for k in d["known_issues"] if k.get("id") != kid]
    for k in patch.get("add_known_issues", []):
        d["known_issues"].append(k)
    if "set_context" in patch:
        d["context"] = patch["set_context"]
    if errs:
        raise DocError(errs)
    return d


class Runtime:
    def __init__(self, store):
        self.store = store
        self._lock = threading.Lock()
        self._known = None
        self._known_rev = -1
        self._settings_rev = -1
        self._raw = {}  # hours -> (monotonic, raw)  (a regex-teszt gyorsitotara)

    # ---- inditas
    def bootstrap(self):
        if self.store.revision_id("known") == 0:
            doc, author = None, "seed:default"
            path = aiops.CFG.get("KNOWN_FILE")
            if path and os.path.exists(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        cand = json.load(f)
                    if not aiops.validate_known(cand):
                        doc, author = cand, "seed:file"
                    else:
                        aiops.log(f"a KNOWN_FILE ({path}) ervenytelen, a beepitett alap kerul be")
                except (OSError, ValueError) as e:
                    aiops.log(f"a KNOWN_FILE nem olvashato: {e}")
            if doc is None:
                with open(DEFAULTS_FILE, encoding="utf-8") as f:
                    doc = json.load(f)
            self.store.put("known", doc, author, "initial configuration")
            aiops.log(f"known-konfig betoltve ({author})")
        self.sync()

    # ---- a konfig valtozasanak felvetele
    def sync(self):
        """Idempotens: csak akkor dolgozik, ha a verzio valtozott."""
        with self._lock:
            sid = self.store.revision_id("settings")
            if sid != self._settings_rev:
                cur = self.store.current("settings")
                settings.apply(cur["content"] if cur else {})
                self._settings_rev = sid
            kid = self.store.revision_id("known")
            if kid != self._known_rev:
                cur = self.store.current("known")
                self._known = aiops.Known(data=cur["content"])
                self._known_rev = kid

    def get_known(self):
        self.sync()
        return self._known

    def changed(self):
        """Konfig-iras utan: azonnali felvetel + a hatterszal felebresztese."""
        self.sync()
        aiops.WAKE.set()

    # ---- regex-teszt: a nyers sorok gyorsitotarazva (a VictoriaLogs-lekerdezes lassabb, mint a regexek)
    def raw_rows(self, hours):
        hit = self._raw.get(hours)
        if hit and time.monotonic() - hit[0] < 120:
            return hit[1]
        now = aiops.utcnow()
        raw = aiops.collect(now - aiops.dt.timedelta(hours=hours), now)
        self._raw[hours] = (time.monotonic(), raw)
        return raw
