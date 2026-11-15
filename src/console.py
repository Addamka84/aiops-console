"""A konzol REST API-ja (FastAPI). Az OpenAPI-leiras: /docs.

Szerepkorok (Bearer token, kornyezeti valtozokbol; a tokenek nem kerulnek konfigtarba/repoba):
- read  (CONSOLE_READ_TOKEN):  olvasas, regex-teszt, JAVASLAT letrehozasa (nem modosit eles konfigot)
- admin (CONSOLE_ADMIN_TOKEN): minden, kozvetlen iras, javaslat jovahagyasa, feladatok inditasa, audit
Token nelkul (egyik sincs beallitva) a vedett vegpontok 503-at adnak.
"""
import difflib
import hmac
import json
import os
import re
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from pydantic import BaseModel

import aiops
import runtime
import settings
from store import StoreError

ACTOR_RX = re.compile(r"[^A-Za-z0-9_.-]")
UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")


class Actor:
    def __init__(self, role, label):
        self.role = role
        self.name = f"{role}:{label}" if label else role


class ConfigPut(BaseModel):
    content: dict
    comment: str = ""


class ProposalIn(BaseModel):
    key: str
    comment: str
    content: dict | None = None
    patch: dict | None = None


class TestIn(BaseModel):
    hours: int = 24
    content: dict | None = None
    patch: dict | None = None


class DigestIn(BaseModel):
    hours: int | None = None


def pretty(doc):
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False).splitlines()


def unified(old, new):
    return "\n".join(difflib.unified_diff(pretty(old), pretty(new), "current", "proposed", lineterm="", n=2))


def next_digest():
    now = aiops.utcnow()
    hh, mm = (int(x) for x in aiops.CFG["DIGEST_UTC"].split(":"))
    t = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if t <= now:
        t += aiops.dt.timedelta(days=1)
    return aiops.iso(t)


def create_app(rt, tokens=None):
    if tokens is None:
        tokens = {"read": os.environ.get("CONSOLE_READ_TOKEN", "").strip(), "admin": os.environ.get("CONSOLE_ADMIN_TOKEN", "").strip()}
    store = rt.store
    app = FastAPI(title="aiops-console", version="1.0", description="Configuration and control API of the aiops service.")

    def authed(need):
        def dep(authorization: str | None = Header(None), x_actor: str | None = Header(None)):
            if not (tokens.get("read") or tokens.get("admin")):
                raise HTTPException(503, "no API tokens configured (set CONSOLE_READ_TOKEN / CONSOLE_ADMIN_TOKEN)")
            got = (authorization or "")[7:].strip() if (authorization or "").lower().startswith("bearer ") else ""
            role = None
            if got:
                if tokens.get("admin") and hmac.compare_digest(got, tokens["admin"]):
                    role = "admin"
                elif tokens.get("read") and hmac.compare_digest(got, tokens["read"]):
                    role = "read"
            if role is None:
                time.sleep(0.3)  # tompiti a talalgatast
                raise HTTPException(401, "missing or invalid token", headers={"WWW-Authenticate": "Bearer"})
            if need == "admin" and role != "admin":
                raise HTTPException(403, "admin token required")
            return Actor(role, ACTOR_RX.sub("", x_actor or "")[:32])
        return dep

    read, admin = authed("read"), authed("admin")

    def check_key(key):
        if key not in runtime.KEYS:
            raise HTTPException(404, f"unknown config key {key!r}; expected one of {', '.join(runtime.KEYS)}")

    def fail(e):
        if isinstance(e, runtime.DocError):
            raise HTTPException(422, {"errors": e.errors})
        raise HTTPException(409 if "stale" in str(e) or "already" in str(e) else 404, str(e))

    # ------------------------------------------------------------ nyitott (regi allapot-JSON kompatibilitas, health)
    @app.get("/api/v1/health", include_in_schema=False)
    def health():
        return {"ok": True}

    # A UI statikus fajlok (nem tartalmaznak adatot; az adat az API-bol jon tokennel). Szigoru CSP: csak sajat forras.
    ui_types = {"app.js": "text/javascript; charset=utf-8", "app.css": "text/css; charset=utf-8", "index.html": "text/html; charset=utf-8"}
    ui_headers = {
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; "
                                   "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-cache",
    }

    def ui_file(name):
        with open(os.path.join(UI_DIR, name), "rb") as f:
            return Response(f.read(), media_type=ui_types[name], headers=ui_headers)

    @app.get("/", include_in_schema=False)
    def root():
        return ui_file("index.html")

    @app.get("/ui/{name}", include_in_schema=False)
    def ui_static(name: str):
        if name not in ui_types or name == "index.html":
            raise HTTPException(404, "not found")
        return ui_file(name)

    @app.get("/last", include_in_schema=False)
    def last():
        return {"last_digest": aiops.STATUS.get("last_digest"), "last_incident": aiops.STATUS.get("last_incident")}

    @app.get("/api/v1/whoami")
    def whoami(who: Actor = Depends(read)):
        return {"role": who.role, "actor": who.name}

    # ------------------------------------------------------------ allapot
    @app.get("/api/v1/status")
    def status(_: Actor = Depends(read)):
        s = dict(aiops.STATUS)
        s["config"] = {"known_rev": store.revision_id("known"), "settings_rev": store.revision_id("settings")}
        s["settings"] = settings.effective((store.current("settings") or {"content": {}})["content"])
        s["notify_configured"] = bool(aiops.CFG["HA_WEBHOOK_URL"])
        s["next_digest_utc"] = next_digest()
        return s

    # ------------------------------------------------------------ konfig
    @app.get("/api/v1/config/{key}")
    def get_config(key: str, raw: bool = False, _: Actor = Depends(read)):
        """raw=true: csak maga a dokumentum (szepen formazva), exportalashoz / diffhez."""
        check_key(key)
        cur = store.current(key)
        if raw:
            return Response(json.dumps((cur or {"content": {}})["content"], indent=2, ensure_ascii=False) + "\n", media_type="application/json")
        out = cur or {"id": 0, "key": key, "content": {}}
        if key == "settings":
            out = dict(out, effective=settings.effective(out["content"]), spec=settings.describe())
        return out

    @app.put("/api/v1/config/{key}")
    def put_config(key: str, body: ConfigPut, who: Actor = Depends(admin)):
        check_key(key)
        try:
            doc = runtime.validate_doc(key, body.content)
        except runtime.DocError as e:
            fail(e)
        cur = store.current(key)
        if cur and cur["content"] == doc:
            return {"changed": False, "rev": cur["id"]}
        rid = store.put(key, doc, who.name, body.comment)
        rt.changed()
        return {"changed": True, "rev": rid}

    @app.get("/api/v1/config/{key}/revisions")
    def revisions(key: str, limit: int = Query(50, ge=1, le=200), _: Actor = Depends(read)):
        check_key(key)
        return store.revisions(key, limit)

    @app.get("/api/v1/config/{key}/revisions/{rid}")
    def revision(key: str, rid: int, _: Actor = Depends(read)):
        check_key(key)
        try:
            return store.revision(key, rid)
        except StoreError as e:
            fail(e)

    @app.post("/api/v1/config/{key}/diff")
    def diff_config(key: str, body: ConfigPut, _: Actor = Depends(read)):
        """Mentes elotti elonezet: mi valtozna a jelenlegihez kepest (nem ir semmit, nem validal)."""
        check_key(key)
        cur = (store.current(key) or {"content": {}})["content"]
        return {"changed": cur != body.content, "diff": unified(cur, body.content)}

    @app.get("/api/v1/config/{key}/revisions/{rid}/diff")
    def revision_diff(key: str, rid: int, _: Actor = Depends(read)):
        """Mit valtoztatna a visszaallitas: a jelenlegi -> a kivalasztott verzio."""
        check_key(key)
        try:
            old = store.revision(key, rid)["content"]
        except StoreError as e:
            fail(e)
        cur = (store.current(key) or {"content": {}})["content"]
        return {"changed": cur != old, "diff": unified(cur, old)}

    @app.post("/api/v1/config/{key}/rollback/{rid}")
    def rollback(key: str, rid: int, who: Actor = Depends(admin)):
        check_key(key)
        try:
            new = store.rollback(key, rid, who.name)
        except StoreError as e:
            fail(e)
        rt.changed()
        return {"changed": True, "rev": new}

    # ------------------------------------------------------------ regex-teszt (szaraz futas az elo naplon)
    @app.post("/api/v1/test/known")
    def test_known(body: TestIn, _: Actor = Depends(read)):
        if not 1 <= body.hours <= 168:
            raise HTTPException(422, {"errors": ["hours must be between 1 and 168"]})
        cur = store.current("known")["content"]
        try:
            if body.content is not None and body.patch is not None:
                raise runtime.DocError(["give either content or patch, not both"])
            doc = body.content if body.content is not None else runtime.apply_known_patch(cur, body.patch) if body.patch is not None else cur
            runtime.validate_doc("known", doc)
        except runtime.DocError as e:
            fail(e)
        try:
            raw = rt.raw_rows(body.hours)
        except (OSError, ValueError) as e:
            raise HTTPException(502, f"VictoriaLogs query failed: {e}")
        res = aiops.analyze_known(aiops.Known(data=doc), raw)
        base = aiops.analyze_known(aiops.Known(data=cur), raw)
        res["baseline"] = {"noise_patterns": base["noise_patterns"], "noise_lines": base["noise_lines"],
                           "known_patterns": base["known_patterns"], "kept_patterns": base["kept_patterns"]}
        return res

    # ------------------------------------------------------------ javaslatok (a felhasznalo hagyja jova)
    @app.post("/api/v1/proposals")
    def add_proposal(body: ProposalIn, who: Actor = Depends(read)):
        check_key(body.key)
        if (body.content is None) == (body.patch is None):
            raise HTTPException(422, {"errors": ["give exactly one of content or patch"]})
        cur = (store.current(body.key) or {"content": {}})["content"]
        try:
            if body.content is not None:
                doc = body.content
            elif body.key == "known":
                doc = runtime.apply_known_patch(cur, body.patch)
            else:  # settings: reszleges felulirasok; null torli a kulcsot
                doc = dict(cur)
                for k, v in body.patch.items():
                    if v is None:
                        doc.pop(k, None)
                    else:
                        doc[k] = v
            doc = runtime.validate_doc(body.key, doc)
        except runtime.DocError as e:
            fail(e)
        if doc == cur:
            raise HTTPException(422, {"errors": ["the proposal does not change anything"]})
        pid = store.add_proposal(body.key, doc, who.name, body.comment, store.revision_id(body.key))
        return {"id": pid, "status": "pending", "diff": unified(cur, doc)}

    def prop_view(p, with_diff=True):
        out = {k: p[k] for k in ("id", "ts", "author", "key", "comment", "status", "decided_ts", "decided_by", "base_rev")}
        out["stale"] = p["status"] == "pending" and store.revision_id(p["key"]) != p["base_rev"]
        if with_diff:
            out["diff"] = unified((store.current(p["key"]) or {"content": {}})["content"], p["content"])
        return out

    @app.get("/api/v1/proposals")
    def list_proposals(status_: str | None = Query(None, alias="status"), _: Actor = Depends(read)):
        return [prop_view(p, with_diff=False) for p in store.proposals(status_)]

    @app.get("/api/v1/proposals/{pid}")
    def get_proposal(pid: int, _: Actor = Depends(read)):
        try:
            return prop_view(store.proposal(pid))
        except StoreError as e:
            fail(e)

    @app.post("/api/v1/proposals/{pid}/approve")
    def approve(pid: int, force: bool = False, who: Actor = Depends(admin)):
        try:
            rid = store.decide(pid, True, who.name, force=force)
        except StoreError as e:
            fail(e)
        rt.changed()
        return {"status": "approved", "rev": rid}

    @app.post("/api/v1/proposals/{pid}/reject")
    def reject(pid: int, who: Actor = Depends(admin)):
        try:
            store.decide(pid, False, who.name)
        except StoreError as e:
            fail(e)
        return {"status": "rejected"}

    # ------------------------------------------------------------ feladatok, audit
    @app.post("/api/v1/jobs/digest")
    def job_digest(body: DigestIn | None = None, who: Actor = Depends(admin)):
        hours = (body.hours if body else None) or aiops.CFG["DIGEST_HOURS"]
        if not 1 <= hours <= 168:
            raise HTTPException(422, {"errors": ["hours must be between 1 and 168"]})
        aiops.COMMANDS.put({"cmd": "digest", "hours": hours})
        aiops.WAKE.set()
        store.audit(who.name, "job.digest", f"{hours} h")
        return {"queued": True, "hours": hours}

    @app.post("/api/v1/jobs/notify-test")
    def job_notify_test(who: Actor = Depends(admin)):
        if not aiops.CFG["HA_WEBHOOK_URL"]:
            raise HTTPException(409, "HA_WEBHOOK_URL is not set")
        aiops.COMMANDS.put({"cmd": "notify-test"})
        aiops.WAKE.set()
        store.audit(who.name, "job.notify-test", "")
        return {"queued": True}

    @app.get("/api/v1/audit")
    def audit(limit: int = Query(100, ge=1, le=1000), _: Actor = Depends(admin)):
        return store.audit_list(limit)

    return app
