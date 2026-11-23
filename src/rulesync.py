"""A 'rules' konfig kiadasa a vmalert fele: fajl a kozos mappaba, reload, ellenorzes, hiba eseten az elozo fajl visszaallitasa.

Kikapcsolt alapbol (RULES_SYNC=off) es csak akkor mukodik, ha a VMALERT_URL es a RULES_DIR is be van allitva (kornyezeti valtozok, mint a VL_URL).
Menete egy kiadasnak (minden lepes hibaja megallitja a kiadast, a vmalert a regi szabalyokkal fut tovabb):
  1. rules.render: a dokumentum ervenytelen -> nincs kiadas
  2. szaraz futtatas: minden engedelyezett szabaly kifejezese lefut a VictoriaLogson (a vmalert a LogsQL-t betolteskor nem ellenorzi);
     a VictoriaLogs elutasitasa (HTTP 4xx) = a szabaly hibas -> nincs kiadas; ha a VictoriaLogs nem elerheto, szinten nincs kiadas
  3. a fajl atomi cserevel kerul a mappaba (ideiglenes fajl + os.replace; a '.tmp' veg miatt a vmalert glob-ja nem latja)
  4. POST /-/reload, majd ellenorzes: vmalert_config_last_reload_successful, es a /api/v1/rules-ban pontosan a vart csoportok es szabalyok vannak
  5. sikertelen ellenorzes -> az elozo fajl visszairasa (vagy torlese), ujra reload; az allapot 'error', a konfig-revizio valtozatlan marad
     (a konzol NEM forgat vissza konfig-revizit magatol: az allapot latszik, a javitas vagy a visszaallitas a felhasznalo dontese)
A vmalert futasideju hibai (egy szabaly kiertekelese kozben) a /api/v1/rules/sync elo nezeteben latszanak.
"""
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

import aiops
import rules

_LOCK = threading.Lock()          # egyszerre egy kiadas
_STATE_LOCK = threading.Lock()
STATE = {"state": "off", "message": "", "ts": "", "rev": 0, "applied_rev": 0, "rules": 0}
_kick_lock = threading.Lock()
_worker = {"thread": None, "again": False, "force": False}
FAIL_FAST_S = 6      # ennyi ido utan egy "sikertelen reload" jelzes veglegesnek szamit (a metrika a reload elott meg a regi lehet)
POLL_S = 2
_OK_RX = re.compile(r"^vmalert_config_last_reload_successful\s+(\S+)\s*$", re.M)


def configured():
    return bool(aiops.CFG.get("VMALERT_URL") and aiops.CFG.get("RULES_DIR"))


def enabled():
    return configured() and aiops.CFG.get("RULES_SYNC") == "on"


def _set(state, message, **kw):
    with _STATE_LOCK:
        STATE.update(state=state, message=str(message)[:500], ts=aiops.iso(aiops.utcnow()), **kw)
        snap = dict(STATE)
    aiops.log(f"rules-sync: {state}: {message}", key="rules_sync")
    return snap


def status():
    with _STATE_LOCK:
        out = dict(STATE)
    out.update(configured=configured(), sync=aiops.CFG.get("RULES_SYNC", "off"))
    return out


# ---------------------------------------------------------------- vmalert
def _vm(method, path, timeout=10):
    req = urllib.request.Request(aiops.CFG["VMALERT_URL"].rstrip("/") + path, data=b"" if method == "POST" else None, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def _reload():
    st, _ = _vm("POST", "/-/reload")
    if st >= 300:
        raise OSError(f"reload answered HTTP {st}")


def _reload_ok():
    """True / False a vmalert_config_last_reload_successful metrikabol; None, ha a metrika nincs."""
    _, text = _vm("GET", "/metrics")
    m = _OK_RX.search(text)
    return None if not m else m.group(1) == "1"


def vm_groups():
    """{csoport: {szabaly: {"health", "error", "state"}}} a SAJAT (aiops-console-*) csoportokra, az elo vmalertbol."""
    _, body = _vm("GET", "/api/v1/rules")
    out = {}
    for g in (json.loads(body).get("data") or {}).get("groups") or []:
        if str(g.get("name", "")).startswith(rules.GROUP_PREFIX):
            out[g["name"]] = {r.get("name"): {"health": r.get("health", ""), "error": r.get("lastError", ""), "state": r.get("state", "")}
                              for r in g.get("rules") or []}
    return out


def verify(expected, timeout_s):
    """A reload utan: a vmalert a vart csoportokat tartalmazza (expected = {csoport: [szabaly]}; None = csak a reload sikeressege szamit),
    a reload sikeres volt, es egy szabaly sem 'err' allapotu. -> (ok, uzenet)"""
    t0 = time.monotonic()
    last = "no answer from vmalert"
    while True:
        elapsed = time.monotonic() - t0
        try:
            ok = _reload_ok()
            if ok is False and elapsed >= FAIL_FAST_S:
                return False, "vmalert reported a failed configuration reload (vmalert_config_last_reload_successful=0)"
            if ok is not False:
                if expected is None:
                    if ok:
                        return True, "ok"
                else:
                    have = vm_groups()
                    if {g: set(r) for g, r in have.items()} == {g: set(a) for g, a in expected.items()}:
                        errs = [f"{rn}: {v['error']}" for g in have.values() for rn, v in g.items() if v["health"] == "err"]
                        if errs:
                            return False, "rule evaluation error: " + "; ".join(errs)[:300]
                        return True, "ok" if ok else "ok (reload metric not available)"
                    last = f"vmalert has the groups {sorted(have)}, expected {sorted(expected)}"
        except (OSError, ValueError) as e:
            last = f"vmalert not reachable ({type(e).__name__})"
        if elapsed >= timeout_s:
            return False, last
        time.sleep(POLL_S)


# ---------------------------------------------------------------- fajl
def _write(path, text):
    """text=None: a fajl torlese. Atomi csere: a vmalert sosem lat fel-iras kozepi fajlt."""
    if text is None:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        return
    tmp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


def dry_run(doc):
    """Minden engedelyezett szabaly kifejezese lefut a VictoriaLogson. -> hibauzenet vagy None."""
    for r in (rules.full(x) for x in doc.get("rules", [])):
        if not r["enabled"]:
            continue
        try:
            aiops.vl_query(rules.expr(r), timeout=20)
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", "replace").strip()
            except OSError:
                body = ""
            return f"rule {r['id']}: VictoriaLogs rejected the expression (HTTP {e.code}) {body[:200]}"
        except TimeoutError:
            aiops.log(f"rules-sync: a(z) {r['id']} szabaly szaraz futtatasa idotullepes (nem hiba: lassu kifejezes)", key=("dry", r["id"]))
        except (OSError, ValueError) as e:
            return f"VictoriaLogs not reachable ({type(e).__name__}): the rules were not checked and not applied"
    return None


# ---------------------------------------------------------------- kiadas
def apply(doc, rev, force=False):
    """Egy dokumentum kiadasa. -> az allapot (STATE masolata)."""
    with _LOCK:
        if not enabled():
            why = "RULES_SYNC is off" if configured() else "VMALERT_URL / RULES_DIR are not configured"
            return _set("off", f"{why}: revision {rev} is saved but not applied", rev=rev)
        _set("running", f"applying revision {rev}", rev=rev)
        try:
            out = rules.render(doc, rev)
        except ValueError as e:
            return _set("error", f"revision {rev} is invalid: {e}", rev=rev)
        text = out["files"][rules.FILE_NAME] if out["rules"] else None
        path = os.path.join(aiops.CFG["RULES_DIR"], rules.FILE_NAME)
        try:
            old = _read(path)
        except OSError as e:
            return _set("error", f"cannot read {path}: {e}", rev=rev)
        if text == old and not force:
            return _set("ok", "already in sync", rev=rev, applied_rev=rev, rules=out["rules"])
        err = dry_run(doc)
        if err:
            return _set("error", f"revision {rev} not applied: {err}", rev=rev)
        timeout_s = max(5, int(aiops.CFG.get("RULES_SYNC_TIMEOUT_S", 40)))
        try:
            _write(path, text)
        except OSError as e:
            return _set("error", f"revision {rev} not applied: cannot write {path}: {e}", rev=rev)
        try:
            _reload()
            ok, why = verify(rules.live_groups(doc), timeout_s)
        except (OSError, ValueError) as e:
            ok, why = False, f"vmalert reload failed ({type(e).__name__}: {e})"
        if ok:
            return _set("ok", f"revision {rev} applied ({out['rules']} rule(s))", rev=rev, applied_rev=rev, rules=out["rules"])
        restored = ""
        try:
            _write(path, old)
            _reload()
            r_ok, r_why = verify(None, timeout_s)
            restored = " The previous file was restored and vmalert reloaded." if r_ok else f" The previous file was restored but verification failed: {r_why}"
        except (OSError, ValueError) as e:
            restored = f" Restoring the previous file failed: {e}"
        return _set("error", f"revision {rev} not applied: {why}.{restored}", rev=rev)


def kick(store, force=False):
    """Hatterszalban kiadja a mentett 'rules' dokumentum aktualis revizijat (egyszerre egy szal; kozben erkezo ujabb kerest is kiszolgal)."""
    with _kick_lock:
        _worker["again"] = True
        _worker["force"] = _worker["force"] or force
        t = _worker["thread"]
        if t is not None and t.is_alive():
            return
        t = threading.Thread(target=_run, args=(store,), daemon=True, name="rules-sync")
        _worker["thread"] = t
        t.start()


def _run(store):
    while True:
        with _kick_lock:
            if not _worker["again"]:
                _worker["thread"] = None
                return
            _worker["again"], force, _worker["force"] = False, _worker["force"], False
        cur = store.current("rules")
        doc, rev = (cur["content"], cur["id"]) if cur else ({}, 0)
        try:
            st = apply(doc, rev, force)
        except Exception as e:  # noqa: BLE001 - a szal nem halhat meg csendben
            st = _set("error", f"unexpected: {type(e).__name__}: {e}", rev=rev)
        if st["state"] == "error" or (st["state"] == "ok" and not st["message"].startswith("already")):
            try:
                store.audit("system", "rules-sync", f"{st['state']}: {st['message']}"[:500])
            except Exception:  # noqa: BLE001
                pass
