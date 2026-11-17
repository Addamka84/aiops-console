"""A konzol REST API-ja (FastAPI). Az OpenAPI-leiras: /docs.

Szerepkorok (Bearer token, kornyezeti valtozokbol; a tokenek nem kerulnek konfigtarba/repoba):
- read  (CONSOLE_READ_TOKEN):  olvasas, regex-teszt, JAVASLAT letrehozasa (nem modosit eles konfigot)
- admin (CONSOLE_ADMIN_TOKEN): minden, kozvetlen iras, javaslat jovahagyasa, feladatok inditasa, audit
Token nelkul (egyik sincs beallitva) a vedett vegpontok 503-at adnak.
"""
import collections
import difflib
import hmac
import json
import os
import re
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

import aiops
import detectors
import novelty
import runtime
import settings
import supervisor
import topology
from store import StoreError

ACTOR_RX = re.compile(r"[^A-Za-z0-9_.-]")
MAX_BODY = 262144          # a kerestest legfeljebb ennyi bajt (a legnagyobb dokumentum, a topologia, ennel joval kisebb)
AUTH_FAIL_LIMIT = 10       # hibas tokenes proba / perc / kliens-cim: efelett 429 (a helyes tokenes keres tovabbra is atmegy)
MAX_PENDING_PER_ACTOR = 100  # egy szereplo legfeljebb ennyi fuggo javaslatot hagyhat
UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")


class Actor:
    def __init__(self, role, label):
        self.role = role
        self.name = f"{role}:{label}" if label else role


class ConfigPut(BaseModel):
    content: dict
    comment: str = Field("", max_length=1000)


class ProposalIn(BaseModel):
    key: str = Field(max_length=40)
    comment: str = Field(max_length=1000)
    content: dict | None = None
    patch: dict | None = None


class TestIn(BaseModel):
    hours: int = 24
    content: dict | None = None
    patch: dict | None = None


class TopoTestIn(BaseModel):
    text: str = ""
    content: dict | None = None  # a meg nem mentett szerkesztes (ha nincs: a mentett topologia)


class DetectorTestIn(BaseModel):
    detector: dict
    hours: int = 168


class SnoozeIn(BaseModel):
    regex: str
    hours: float
    note: str = ""


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

    for name_, tok_ in tokens.items():
        if tok_ and len(tok_) < 32:
            aiops.log(f"konzol: a(z) {name_} token rovid ({len(tok_)} jel): legalabb 32 veletlen jelet hasznalj", key=("console_short_token", name_))
    fails = collections.defaultdict(collections.deque)   # kliens-cim -> a hibas probak ideje (monoton, mp)

    def failure(ip):
        now = time.monotonic()
        q = fails[ip]
        while q and now - q[0] > 60:
            q.popleft()
        q.append(now)
        if len(fails) > 1000:   # a tar ne nohessen korlatlanul
            for k in [k for k, v in fails.items() if not v or now - v[-1] > 60]:
                fails.pop(k, None)
        return len(q) > AUTH_FAIL_LIMIT

    def authed(need):
        def dep(request: Request, authorization: str | None = Header(None), x_actor: str | None = Header(None)):
            if not (tokens.get("read") or tokens.get("admin")):
                raise HTTPException(503, "no API tokens configured (set CONSOLE_READ_TOKEN / CONSOLE_ADMIN_TOKEN)")
            got = (authorization or "")[7:].strip() if (authorization or "").lower().startswith("bearer ") else ""
            gb = got.encode("utf-8", "replace")      # a compare_digest nem-ASCII str-re TypeError-t dobna (500)
            role = None
            if got:
                if tokens.get("admin") and hmac.compare_digest(gb, tokens["admin"].encode("utf-8", "replace")):
                    role = "admin"
                elif tokens.get("read") and hmac.compare_digest(gb, tokens["read"].encode("utf-8", "replace")):
                    role = "read"
            if role is None:
                # nincs alvas (a szinkron fuggoseg a szalkészletben futna, igy a hibas probak kimerithetnek): kliensenkenti korlat
                if failure(request.client.host if request.client else "-"):
                    raise HTTPException(429, "too many failed attempts", headers={"Retry-After": "60"})
                raise HTTPException(401, "missing or invalid token", headers={"WWW-Authenticate": "Bearer"})
            if need == "admin" and role != "admin":
                raise HTTPException(403, "admin token required")
            return Actor(role, ACTOR_RX.sub("", x_actor or "")[:32])
        return dep

    read, admin = authed("read"), authed("admin")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            cl = request.headers.get("content-length")
            if cl is None and request.headers.get("transfer-encoding"):
                return Response('{"detail":"chunked bodies are not accepted"}', 411, media_type="application/json")
            try:
                too_big = cl is not None and int(cl) > MAX_BODY
            except ValueError:
                too_big = True
            if too_big:
                return Response('{"detail":"request body too large"}', 413, media_type="application/json")
        resp = await call_next(request)
        if request.url.path.startswith("/api/") or request.url.path == "/last":
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def vl_down(e):
        aiops.log(f"konzol: VictoriaLogs hiba: {type(e).__name__}: {e}", key="console_vl")
        return "VictoriaLogs query failed (details in the service log)"

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
        return {"ok": True, "version": aiops.__version__}

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

    def brief(r):
        """A nyitott /last csak a metaadatot adja (nem a naplotartalmat, a hosztokat, a belso vegpontot): a reszletek a tokenes /api/v1/status-ban vannak."""
        if not isinstance(r, dict):
            return None
        out = {k: r[k] for k in ("kind", "window", "all_clear") if k in r}
        out["issues"] = len(r["issues"]) if isinstance(r.get("issues"), list) else 0
        return out

    @app.get("/last", include_in_schema=False)
    def last():
        return {"last_digest": brief(aiops.STATUS.get("last_digest")), "last_incident": brief(aiops.STATUS.get("last_incident"))}

    @app.get("/api/v1/whoami")
    def whoami(who: Actor = Depends(read)):
        return {"role": who.role, "actor": who.name}

    # ------------------------------------------------------------ allapot
    @app.get("/api/v1/status")
    def status(_: Actor = Depends(read)):
        s = dict(aiops.STATUS)
        s["config"] = {"known_rev": store.revision_id("known"), "settings_rev": store.revision_id("settings"),
                       "topology_rev": store.revision_id("topology"), "detectors_rev": store.revision_id("detectors")}
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
            raise HTTPException(502, vl_down(e))
        res = aiops.analyze_known(aiops.Known(data=doc), raw)
        base = aiops.analyze_known(aiops.Known(data=cur), raw)
        res["baseline"] = {"noise_patterns": base["noise_patterns"], "noise_lines": base["noise_lines"],
                           "known_patterns": base["known_patterns"], "kept_patterns": base["kept_patterns"]}
        return res

    # ------------------------------------------------------------ topologia: proba es lefedettseg
    def topo_of(content):
        doc = content if content is not None else (store.current("topology") or {"content": {}})["content"]
        try:
            runtime.validate_doc("topology", doc)
        except runtime.DocError as e:
            fail(e)
        return topology.Topology(doc)

    @app.post("/api/v1/test/topology")
    def test_topology(body: TopoTestIn, _: Actor = Depends(read)):
        """Mit kapna a modell a topologiabol egy adott szovegre (riasztas / naplosor): a talalt eszkozok es a bemenet szakasza."""
        topo = topo_of(body.content)
        ids = topo.match([body.text], limit=8)
        section = topo.section(ids)
        return {"matched": ids, "section": section, "chars": sum(len(x) + 1 for x in section), "assets": len(topo.assets)}

    cov_cache = {}

    @app.get("/api/v1/topology/coverage")
    def topology_coverage(hours: int = Query(168, ge=1, le=336), _: Actor = Depends(read)):
        """Mi latszik a naplokban, de nincs a topologiaban ('unknown'), es mi van a topologiaban, de nem latszik ('silent'). 2 percig gyorsitotarazva."""
        topo = topo_of(None)
        hit = cov_cache.get(hours)
        if hit and time.monotonic() - hit[0] < 120:
            seen = hit[1]
        else:
            try:
                seen = aiops.log_sources(hours)
            except (OSError, ValueError) as e:
                raise HTTPException(502, vl_down(e))
            cov_cache[hours] = (time.monotonic(), seen)
        return dict(topology.coverage(topo, seen), hours=hours, assets=len(topo.assets), seen=len(seen))

    # ------------------------------------------------------------ detektorok: visszateszt es allapot
    @app.post("/api/v1/test/detector")
    def test_detector(body: DetectorTestIn, _: Actor = Depends(read)):
        """Egy detektor (akar meg nem mentett) hatasa a mult `hours` orajara: mikor es hanyszor tuzelt volna, mintasorok."""
        errs = detectors.validate({"detectors": [body.detector]})
        if errs:
            raise HTTPException(422, {"errors": errs})
        if not 1 <= body.hours <= 336:
            raise HTTPException(422, {"errors": ["hours must be between 1 and 336"]})
        try:
            return detectors.backtest(body.detector, body.hours)
        except ValueError as e:
            raise HTTPException(422, {"errors": [str(e)]})
        except OSError as e:
            raise HTTPException(502, vl_down(e))

    @app.get("/api/v1/detectors/status")
    def detectors_status(_: Actor = Depends(read)):
        """A mentett detektorok eloallapota (utolso kiertekeles, talalatok, hiba) + a legutobbi tuzelesek a tarbol."""
        out = {"mode": aiops.CFG["DETECTOR_MODE"], "interval_s": aiops.CFG["DETECTOR_INTERVAL_S"],
               "detectors": [dict(aiops.DETECTOR_STATUS.get(d["id"], {}), id=d["id"], enabled=d["enabled"]) for d in aiops.DETECTORS], "recent": []}
        try:
            out["recent"] = aiops.vl_query("_time:30d pipeline:ai kind:detector | sort by (_time desc) | limit 25"
                                           " | fields _time, detector, name, action, severity, group, hits", timeout=20)
        except (OSError, ValueError):
            out["recent_error"] = "VictoriaLogs unavailable"
        return out

    # ------------------------------------------------------------ Auto AI Supervisor (csak olvaso attekintes, jelentes)
    @app.get("/api/v1/supervisor")
    def supervisor_status(_: Actor = Depends(read)):
        return supervisor.status(store)

    @app.get("/api/v1/supervisor/runs")
    def supervisor_runs(limit: int = Query(20, ge=1, le=200), _: Actor = Depends(read)):
        return store.sup_runs(limit)

    @app.post("/api/v1/supervisor/run")
    def supervisor_run(who: Actor = Depends(admin)):
        if not supervisor.request_run():
            raise HTTPException(409, "the supervisor is off (SUPERVISOR_MODE)")
        store.audit(who.name, "supervisor-run", "manual run requested")
        return {"requested": True}

    # ------------------------------------------------------------ javaslatok (a felhasznalo hagyja jova)
    @app.post("/api/v1/proposals")
    def add_proposal(body: ProposalIn, who: Actor = Depends(read)):
        check_key(body.key)
        if (body.content is None) == (body.patch is None):
            raise HTTPException(422, {"errors": ["give exactly one of content or patch"]})
        if sum(1 for p in store.proposals("pending", 1000) if p["author"] == who.name) >= MAX_PENDING_PER_ACTOR:
            raise HTTPException(429, f"too many pending proposals from {who.name} (limit {MAX_PENDING_PER_ACTOR})")
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
        proposed = p["content"]
        if out["stale"]:   # a konfig kozben valtozott: az osszefesult eredmeny (vagy a konfliktus) latszik, a jovahagyas ezt hajtja vegre
            mp = store.merge_preview(p)
            out["merge"] = "clean" if mp["merged"] is not None else "conflict"
            out["conflicts"] = mp["conflicts"]
            if mp["merged"] is not None:
                proposed = mp["merged"]
        if with_diff:
            out["diff"] = unified((store.current(p["key"]) or {"content": {}})["content"], proposed)
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
            rid = store.decide(pid, True, who.name, force=force, validate=runtime.validate_doc)
        except (StoreError, runtime.DocError) as e:
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

    # ------------------------------------------------------------ statisztika (VictoriaLogs-bol)
    vol_cache = {}

    @app.get("/api/v1/stats/volume")
    def stats_volume(hours: int = 24, by: str = "pipeline", _: Actor = Depends(read)):
        """Uzenetszam-idosor (stackelt grafikonhoz): by=pipeline|host, hours=6|24|72|168. 60 mp-ig gyorsitotarazva."""
        key = (hours, by)
        hit = vol_cache.get(key)
        if hit and time.monotonic() - hit[0] < 60:
            return hit[1]
        try:
            res = aiops.log_volume(hours, by)
        except ValueError as e:
            raise HTTPException(422, {"errors": [str(e)]})
        except OSError as e:
            raise HTTPException(502, vl_down(e))
        vol_cache[key] = (time.monotonic(), res)
        return res

    @app.get("/api/v1/stats/runs")
    def stats_runs(limit: int = Query(14, ge=1, le=100), kind: str = "digest", _: Actor = Depends(read)):
        """A legutobbi futasok (digest / incident) 'mit neztem at' statisztikaja a VictoriaLogs pipeline:ai esemenyeibol."""
        if kind not in ("digest", "incident", "all"):
            raise HTTPException(422, {"errors": ["kind must be digest, incident or all"]})
        kinds = "in(digest,incident)" if kind == "all" else kind
        try:
            rows = aiops.vl_query(f"_time:90d pipeline:ai kind:{kinds} | sort by (_time desc) | limit {int(limit)}")
        except (OSError, ValueError) as e:
            raise HTTPException(502, vl_down(e))
        out = []
        for r in rows:
            try:
                st = json.loads(r.get("stats") or "{}")
            except ValueError:
                st = {}
            out.append({"time": r.get("_time"), "kind": r.get("kind"), "window": r.get("window"), "model": r.get("model"),
                        "issue_count": int(r.get("issue_count") or 0), "max_severity": r.get("max_severity"),
                        "all_clear": r.get("all_clear") == "true", "dropped_known": int(r.get("dropped_known") or 0),
                        "secs": float(r.get("secs") or 0), "prompt_tokens": r.get("prompt_tokens"), "stats": st})
        return out

    # ------------------------------------------------------------ snooze: ideiglenes nemitas lejarati idovel
    def snooze_views():
        now = aiops.utcnow().replace(tzinfo=None)
        out = []
        for s in (store.current("known") or {"content": {}})["content"].get("snoozes", []):
            until = aiops.parse_until(s.get("until"))
            left = int((until - now).total_seconds()) if until else 0
            out.append({"id": s.get("id"), "regex": s.get("regex"), "until": s.get("until"), "note": s.get("note", ""),
                        "active": left > 0, "remaining_s": max(left, 0)})
        return out

    @app.get("/api/v1/snoozes")
    def list_snoozes(_: Actor = Depends(read)):
        """Az ideiglenes nemitasok (aktiv + lejart, utobbiakat a prune_expired_snoozes patch torli)."""
        return snooze_views()

    @app.post("/api/v1/snoozes")
    def add_snooze(body: SnoozeIn, who: Actor = Depends(admin)):
        """Egy regex ideiglenes nemitasa (hours: 1..2160). Olvaso token: javaslat (POST /proposals, add_snoozes)."""
        cur = (store.current("known") or {"content": {}})["content"]
        item = {"regex": body.regex, "hours": body.hours, "note": body.note}
        try:
            doc = runtime.validate_doc("known", runtime.apply_known_patch(cur, {"add_snoozes": [item]}))
        except runtime.DocError as e:
            fail(e)
        added = doc["snoozes"][-1]
        rid = store.put("known", doc, who.name, f"snooze {added['id']} until {added['until']}" + (f": {body.note}" if body.note else ""))
        rt.changed()
        return {"rev": rid, "snooze": added}

    @app.delete("/api/v1/snoozes/{sid}")
    def delete_snooze(sid: str, who: Actor = Depends(admin)):
        cur = (store.current("known") or {"content": {}})["content"]
        try:
            doc = runtime.validate_doc("known", runtime.apply_known_patch(cur, {"remove_snooze_ids": [sid]}))
        except runtime.DocError as e:
            raise HTTPException(404, {"errors": e.errors})
        rid = store.put("known", doc, who.name, f"remove snooze {sid}")
        rt.changed()
        return {"rev": rid}

    # ------------------------------------------------------------ ujdonsag-eszlelo (jelentes mod)
    @app.get("/api/v1/novelty")
    def novelty_list(status: str = Query("open", pattern="^(open|dismissed|all)$"), limit: int = Query(100, ge=1, le=500),
                     _: Actor = Depends(read)):
        """Uj mintak es gyakorisag-ugrasok a naplokban + a detektor allapota (alapvonal, utolso futas, hiba)."""
        return {"status": novelty.status(store), "findings": store.nov_findings(None if status == "all" else status, limit=limit)}

    @app.post("/api/v1/novelty/dismiss-all")
    def novelty_dismiss_all(who: Actor = Depends(admin)):
        return {"dismissed": store.nov_dismiss(None, who.name)}

    @app.post("/api/v1/novelty/{fid}/dismiss")
    def novelty_dismiss(fid: int, who: Actor = Depends(admin)):
        n = store.nov_dismiss(fid, who.name)
        if not n:
            raise HTTPException(404, f"no open finding {fid}")
        return {"dismissed": n}

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
