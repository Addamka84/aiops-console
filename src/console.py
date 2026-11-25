"""A konzol REST API-ja (FastAPI). Az OpenAPI-leiras: /docs.

Szerepkorok (Bearer token, kornyezeti valtozokbol; a tokenek nem kerulnek konfigtarba/repoba):
- read  (CONSOLE_READ_TOKEN):  olvasas, regex-teszt, JAVASLAT letrehozasa (nem modosit eles konfigot)
- admin (CONSOLE_ADMIN_TOKEN): minden, kozvetlen iras, javaslat jovahagyasa, feladatok inditasa, audit
Token nelkul (egyik sincs beallitva) a vedett vegpontok 503-at adnak.
"""
import collections
import datetime as dt
import difflib
import hmac
import json
import os
import re
import threading
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

import aiops
import detectors
import evidence
import ingest
import maintenance
import noisemodel
import novelty
import rules
import rulesync
import runtime
import settings
import supervisor
import topology
from redact import redact
from store import StoreError

ACTOR_RX = re.compile(r"[^A-Za-z0-9_.-]")
MAX_BODY = 262144          # a kerestest legfeljebb ennyi bajt (a legnagyobb dokumentum, a topologia, ennel joval kisebb)
AUTH_FAIL_LIMIT = 10       # hibas tokenes proba / perc / kliens-cim: efelett 429 (a helyes tokenes keres tovabbra is atmegy)
MAX_PENDING_PER_ACTOR = 100  # egy SZEREPKOR (read / admin) legfeljebb ennyi fuggo javaslatot hagyhat (a cimke szabadon valaszthato: audit M6)
UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")


class Actor:
    def __init__(self, role, label):
        self.role = role
        self.name = f"{role}:{label}" if label else role


class ConfigPut(BaseModel):
    content: dict
    comment: str = Field("", max_length=1000)


class DismissIn(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=500)


class ProposalIn(BaseModel):
    key: str = Field(max_length=40)
    comment: str = Field(max_length=1000)
    content: dict | None = None
    patch: dict | None = None


class TestIn(BaseModel):
    hours: int = 24
    content: dict | None = None
    patch: dict | None = None


class ExplainIn(BaseModel):
    host: str = Field("", max_length=200)
    ident: str = Field("", max_length=200)
    message: str = Field(..., min_length=1, max_length=4000)
    source: str = Field("syslog", max_length=20)
    level: str | None = Field(None, max_length=20)
    hours: int = 24              # 0: csak a szabalyok, elo ablak nelkul
    content: dict | None = None  # a meg nem mentett known-szerkesztes (ha nincs: a mentett dokumentum)


class IncStateIn(BaseModel):
    state: str = Field(..., max_length=20)
    owner: str | None = Field(None, max_length=80)


class IncNoteIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000)


FB_CHOICES = {"root_cause": ("correct", "wrong", "unsure", "n/a"), "severity": ("right", "too_high", "too_low"),
              "grouping": ("right", "should_split", "should_merge", "n/a")}


class IncFeedbackIn(BaseModel):
    root_cause: str = Field(..., max_length=20)
    severity: str = Field(..., max_length=20)
    grouping: str = Field(..., max_length=20)
    comment: str = Field("", max_length=1000)


INC_ID_RX = re.compile(r"^incident-\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
RUN_ID_RX = re.compile(r"^(incident|digest)-\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
MODEL_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$")
REPLAY_MAX_DAYS = int(os.environ.get("REPLAY_MAX_DAYS", "30"))   # a VictoriaLogs megorzesi ideje: regebbi ablak nyers sorai mar nincsenek meg


class ReplayIn(BaseModel):
    source: str = Field(..., max_length=40)          # a tarolt digest / incidens azonositoja (pl. incident-2026-11-25T10:30:57Z)
    model: str | None = Field(None, max_length=100)  # ures: a jelenlegi modell


class MaintIn(BaseModel):
    targets: list[str] = Field(..., min_length=1, max_length=20)
    hours: float = Field(..., gt=0, le=168)
    start: str | None = Field(None, max_length=20)   # UTC "2026-11-25T18:00:00Z"; nincs: most
    include_dependents: bool = True
    note: str = Field("", max_length=300)
    id: str | None = Field(None, max_length=64)


class TopoTestIn(BaseModel):
    text: str = ""
    content: dict | None = None  # a meg nem mentett szerkesztes (ha nincs: a mentett topologia)


class IngestTestIn(BaseModel):
    source: str = Field("", max_length=60)
    value: str = Field("", max_length=100)
    content: dict | None = None  # a meg nem mentett szerkesztes (ha nincs: a mentett dokumentum)


class RulesPreviewIn(BaseModel):
    content: dict | None = None  # a meg nem mentett szerkesztes (ha nincs: a mentett dokumentum)


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
    noisemodel.ADVISOR.attach(store)
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
        s["maintenance_active"] = [{"id": w.get("id"), "targets": w.get("targets", []), "end": w.get("end"), "note": w.get("note", "")}
                                   for w in maintenance.active()]
        s["config"] = {"known_rev": store.revision_id("known"), "settings_rev": store.revision_id("settings"),
                       "topology_rev": store.revision_id("topology"), "detectors_rev": store.revision_id("detectors"),
                       "rules_rev": store.revision_id("rules")}
        s["settings"] = settings.effective((store.current("settings") or {"content": {}})["content"])
        s["notify_configured"] = bool(aiops.CFG["HA_WEBHOOK_URL"])
        s["rules_sync"] = rulesync.status()
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
        if key == "ingest":
            out = dict(out, effective=ingest.effective(out["content"]), levels=list(ingest.LEVELS))
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

    @app.post("/api/v1/explain")
    def explain(body: ExplainIn, _: Actor = Depends(read)):
        """'Miert nem jelent meg?': egy naplosor utja a modell bemenetebe (szint -> zaj -> snooze -> ismert ugy -> mintakorlat).
        Csak olvas; hours > 0 eseten az elo ablak (a modellnek gyujtott sorok) alapjan a mintakorlatot is megnezi."""
        if not 0 <= body.hours <= 168:
            raise HTTPException(422, {"errors": ["hours must be between 0 and 168"]})
        doc = body.content if body.content is not None else store.current("known")["content"]
        try:
            runtime.validate_doc("known", doc)
        except runtime.DocError as e:
            fail(e)
        raw = None
        if body.hours:
            try:
                raw = rt.raw_rows(body.hours)
            except (OSError, ValueError) as e:
                raise HTTPException(502, vl_down(e))
        try:
            res = aiops.explain_line(aiops.Known(data=doc), body.host, body.ident, body.message, body.source, body.level,
                                     raw=raw, must_keep=doc.get("must_keep", []),
                                     lookup=(lambda s, h, i, m: aiops.count_line(s, h, i, m, body.hours)) if body.hours else None)
        except ValueError as e:
            raise HTTPException(422, {"errors": [str(e)]})
        res["hours"] = body.hours
        return res

    @app.post("/api/v1/test/ingest")
    def test_ingest(body: IngestTestIn, _: Actor = Depends(read)):
        """Egy nyers sulyossag-ertek normalizalasa a (meg nem mentett) leképezéssel: -> {level, mapped, default}."""
        doc = body.content if body.content is not None else (store.current("ingest") or {"content": {}})["content"]
        try:
            runtime.validate_doc("ingest", doc)
        except runtime.DocError as e:
            fail(e)
        level, mapped = ingest.Config(doc).level(body.source, body.value if body.value.strip() else None)
        return {"level": level, "mapped": mapped}

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

    # ------------------------------------------------------------ vmalert-szabalyok: elonezet (fajlt nem ir, a vmalertet nem hivja)
    @app.get("/api/v1/rules/preview")
    def rules_preview_saved(_: Actor = Depends(read)):
        """A mentett 'rules' dokumentumbol renderelt vmalert szabaly-fajl (a kovetkezo lepesben ez kerul a kozos mappaba)."""
        cur = store.current("rules")
        return dict(rules.preview((cur or {"content": {}})["content"], cur["id"] if cur else None), rev=cur["id"] if cur else 0)

    @app.post("/api/v1/rules/preview")
    def rules_preview_draft(body: RulesPreviewIn, _: Actor = Depends(read)):
        """Egy meg nem mentett szerkesztes ellenorzese es renderelese (hibak 200-as valaszban, mint a szerkesztoben szokas)."""
        if body.content is None:
            return rules_preview_saved(_)
        return rules.preview(body.content)

    @app.get("/api/v1/rules/sync")
    def rules_sync_state(_: Actor = Depends(read)):
        """A kiadas allapota (utolso kiserlet, a kiadott revizio) + a vmalert elo nezete a sajat (aiops-console-*) csoportokrol."""
        out = rulesync.status()
        out["saved_rev"] = store.revision_id("rules")
        out["vmalert"] = None
        if rulesync.configured():
            try:
                out["vmalert"] = [{"group": g, "rule": r, **v} for g, rs in rulesync.vm_groups().items() for r, v in rs.items()]
            except (OSError, ValueError):
                out["vmalert_error"] = "vmalert unavailable"
        return out

    @app.post("/api/v1/rules/sync")
    def rules_sync_run(who: Actor = Depends(admin)):
        """A mentett revizio ujrakiadasa (fajl ujrairasa + reload + ellenorzes), pl. a RULES_SYNC bekapcsolasa utan vagy hiba javitasa utan."""
        if not rulesync.enabled():
            raise HTTPException(409, "rule sync is off or not configured (RULES_SYNC, VMALERT_URL, RULES_DIR)")
        store.audit(who.name, "rules-sync-run", "re-apply requested")
        rulesync.kick(store, force=True)
        return {"requested": True}

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

    @app.get("/api/v1/detectors/health")
    def detectors_health(_: Actor = Depends(read)):
        """Detektor-attekintes: tuzeles 30 napban, utolso tuzeles, zaszlok (letiltott vazlat, tul zajos, csendes, hibas)."""
        dets = ((store.current("detectors") or {"content": {}})["content"] or {}).get("detectors", [])
        out = {"noisy_30d": detectors.NOISY_30D}
        try:
            fired = detectors.fired_30d()
        except Exception:  # noqa: BLE001 - a tar elerhetetlensege nem akadalyozhatja az attekintest
            fired, out["fired_error"] = {}, "VictoriaLogs unavailable"
        out["detectors"] = detectors.health(dets, fired, aiops.DETECTOR_STATUS)
        out["counts"] = {f: sum(1 for h in out["detectors"] if f in h["flags"]) for f in ("draft-disabled", "disabled", "noisy", "quiet", "error")}
        return out

    @app.post("/api/v1/novelty/{fid}/detector-draft")
    def novelty_detector_draft(fid: int, who: Actor = Depends(read)):
        """'+ detector': determinisztikus detektor-vazlat a leletbol (host + azonosito + a sablon allando szovege), 7 napos visszateszttel;
        javaslatkent kerul be (letiltott detektor), a jovahagyas es a bekapcsolas az admin dolga."""
        f = store.nov_finding(fid)
        if not f:
            raise HTTPException(404, f"no finding {fid}")
        cur = (store.current("detectors") or {"content": {}})["content"] or {}
        dets = list(cur.get("detectors", []))
        try:
            d, query = supervisor.finding_detector_draft(f, dets)
        except ValueError as e:
            raise HTTPException(422, {"errors": [str(e)]})
        err, bt = supervisor.check_coverage_query(query)
        if err:
            raise HTTPException(422, {"errors": [err]})
        try:
            doc = runtime.validate_doc("detectors", dict(cur, detectors=dets + [d]))
        except runtime.DocError as e:
            fail(e)
        if store.count_pending(who.role) >= MAX_PENDING_PER_ACTOR:
            raise HTTPException(429, f"too many pending proposals from the {who.role} role (limit {MAX_PENDING_PER_ACTOR})")
        comment = (f"+ detector from finding #{fid} ({f['host']} / {f['ident']}). Filter: {query}. "
                   f"{bt['hours'] // 24}-day backtest: {bt['firings']} firing(s), {bt['total']} matching line(s).")
        pid = store.add_proposal("detectors", doc, who.name, comment, store.revision_id("detectors"))
        return {"id": pid, "query": query, "backtest": bt, "detector": d["id"]}

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
        if store.count_pending(who.role) >= MAX_PENDING_PER_ACTOR:
            raise HTTPException(429, f"too many pending proposals from the {who.role} role (limit {MAX_PENDING_PER_ACTOR})")
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
        if p["key"] == "known" and p["status"] == "pending":
            # Bizonyitek a zajszabaly-javaslathoz (determinisztikus): figyelem-jelzes mindig, hatasvizsgalat a reszletes nezetben.
            cur_doc = (store.current("known") or {"content": {}})["content"]
            new_rules = [r for r in proposed.get("noise", []) if r not in cur_doc.get("noise", [])]
            if new_rules:
                out["attention"] = evidence.attention(new_rules)
                if with_diff:
                    out["evidence"] = evidence.noise_evidence(new_rules, store.nov_pattern_rows(), store.nov_findings("open", limit=500),
                                                              cur_doc.get("noise", []), redact)
        if with_diff:
            out["diff"] = unified((store.current(p["key"]) or {"content": {}})["content"], proposed)
        return out

    @app.get("/api/v1/proposals")
    def list_proposals(status_: str | None = Query(None, alias="status", pattern="^(pending|approved|rejected)$"),
                       limit: int = Query(50, ge=1, le=200), before: int | None = Query(None, ge=1), _: Actor = Depends(read)):
        """Legujabb elol; lapozas: before=<az elozo oldal utolso azonositoja>."""
        return [prop_view(p, with_diff=False) for p in store.proposals(status_, limit, before)]

    @app.get("/api/v1/proposals/{pid}")
    def get_proposal(pid: int, _: Actor = Depends(read)):
        try:
            return prop_view(store.proposal(pid))
        except StoreError as e:
            fail(e)

    @app.post("/api/v1/proposals/{pid}/approve")
    def approve(pid: int, force: bool = False, enable: bool = False, who: Actor = Depends(admin)):
        """enable=true detektor-javaslatnal: a jovahagyas altal UJONNAN felvett, letiltott detektorokat egy kovetkezo revizioban be is kapcsolja
        (a vazlatok letiltva erkeznek; bekapcsolas nelkul zsakutca). Mas kulcsnal nincs hatasa."""
        before = None
        try:
            prop = store.proposal(pid)
            if enable and prop["key"] == "detectors":
                before = {d.get("id") for d in ((store.current("detectors") or {"content": {}})["content"] or {}).get("detectors", [])}
            rid = store.decide(pid, True, who.name, force=force, validate=runtime.validate_doc)
        except (StoreError, runtime.DocError) as e:
            fail(e)
        out = {"status": "approved", "rev": rid}
        if before is not None:
            cur = store.current("detectors")
            doc = json.loads(json.dumps(cur["content"]))
            ids = []
            for d in doc.get("detectors", []):
                if d.get("id") not in before and d.get("enabled") is False:
                    d["enabled"] = True
                    ids.append(d["id"])
            if ids:
                try:
                    doc = runtime.validate_doc("detectors", doc)
                    out["enable_rev"] = store.put("detectors", doc, who.name, f"enabled with the approval of proposal #{pid}: {', '.join(ids)}")
                    out["enabled"] = ids
                except runtime.DocError as e:
                    out["enable_error"] = str(e)[:200]
        rt.changed()
        return out

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

    # ------------------------------------------------------------ incidensek: lista, reszletek, allapot, jegyzet, visszajelzes
    SEV_ORDER = {s: i for i, s in enumerate(aiops.SEVERITIES)}

    def inc_heads(hours, limit):
        return aiops.vl_query(f"_time:{int(hours)}h pipeline:ai kind:incident | sort by (_time desc) | limit {int(limit)}", timeout=20)

    def inc_issues(hours, parents=None):
        flt = f" parent:in({','.join(json.dumps(p) for p in parents)})" if parents else ""
        rows = aiops.vl_query(f"_time:{int(hours)}h pipeline:ai kind:issue{flt} | sort by (_time desc) | limit 3000", timeout=20)
        by = {}
        for r in rows:
            by.setdefault(str(r.get("parent", "")), []).append({
                "title": r.get("title", ""), "severity": r.get("severity", ""), "status": r.get("status", ""),
                "hosts": [x.strip() for x in str(r.get("hosts", "")).split(",") if x.strip()],
                "evidence": r.get("evidence", ""), "likely_cause": r.get("likely_cause", ""), "suggested_action": r.get("suggested_action", "")})
        for v in by.values():
            v.sort(key=lambda i: -SEV_ORDER.get(i["severity"], -1))
        return by

    def inc_view(hd, issues, meta):
        m = meta or {}
        top = issues[0] if issues else None
        return {"id": hd.get("id"), "time": hd.get("_time"), "alert": hd.get("alert", ""), "summary": str(hd.get("_msg", "")).removeprefix("[AI incident] "),
                "title": (top or {}).get("title") or str(hd.get("alert", ""))[:120], "max_severity": hd.get("max_severity", ""),
                "issue_count": int(hd.get("issue_count") or 0), "correlated_alerts": int(hd.get("correlated_alerts") or 1),
                "root_hypothesis": hd.get("root_hypothesis", ""), "root_confidence": hd.get("root_confidence", ""),
                "state": m.get("state", "open"), "owner": m.get("owner", ""), "state_ts": m.get("ts"), "feedback": m.get("feedback")}

    def inc_check(inc):
        if not INC_ID_RX.match(inc):
            raise HTTPException(404, "unknown incident id")

    def inc_head(inc):
        inc_check(inc)
        try:
            rows = aiops.vl_query(f"_time:400d pipeline:ai kind:incident id:={json.dumps(inc)} | limit 1", timeout=20)
        except (OSError, ValueError) as e:
            raise HTTPException(502, vl_down(e))
        if not rows:
            raise HTTPException(404, "unknown incident id")
        return rows[0]

    @app.get("/api/v1/incidents")
    def incidents(hours: int = Query(168, ge=1, le=2160), state: str = "all", limit: int = Query(100, ge=1, le=500), _: Actor = Depends(read)):
        """Az AI-incidensek (a VictoriaLogs pipeline:ai esemenyeibol) a konzolon tarolt allapottal es visszajelzessel."""
        if state not in ("all", "unresolved") + store.INC_STATES:
            raise HTTPException(422, {"errors": ["state must be all, unresolved, open, acknowledged or resolved"]})
        try:
            heads = inc_heads(hours, limit)
            issues = inc_issues(hours, [str(h.get("id", "")) for h in heads if h.get("id")]) if heads else {}
        except (OSError, ValueError) as e:
            raise HTTPException(502, vl_down(e))
        meta = store.inc_meta(str(h.get("id", "")) for h in heads)
        out = [inc_view(h, issues.get(str(h.get("id", "")), []), meta.get(str(h.get("id", "")))) for h in heads]
        if state == "unresolved":
            out = [x for x in out if x["state"] != "resolved"]
        elif state != "all":
            out = [x for x in out if x["state"] == state]
        return out

    @app.get("/api/v1/incidents/quality")
    def incidents_quality(days: int = Query(30, ge=1, le=365), _: Actor = Depends(read)):
        """Mennyire volt jo a triazs az emberi visszajelzes szerint (a legutobbi visszajelzes incidensenkent)."""
        try:
            heads = inc_heads(days * 24, 2000)
        except (OSError, ValueError) as e:
            raise HTTPException(502, vl_down(e))
        meta = store.inc_meta(str(h.get("id", "")) for h in heads)
        fbs = [m["feedback"] for m in meta.values() if m.get("feedback")]

        def rate(key, good, skip=("n/a", "unsure")):
            vals = [f.get(key) for f in fbs if f.get(key) not in skip]
            return {"good": sum(1 for v in vals if v == good), "rated": len(vals),
                    "rate": round(sum(1 for v in vals if v == good) / len(vals), 3) if vals else None}
        sev = [f.get("severity") for f in fbs]
        return {"days": days, "incidents": len(heads), "with_feedback": len(fbs),
                "states": {s: sum(1 for h in heads if (meta.get(str(h.get("id", ""))) or {}).get("state", "open") == s) for s in store.INC_STATES},
                "root_cause": rate("root_cause", "correct"), "severity": rate("severity", "right"), "grouping": rate("grouping", "right"),
                "severity_too_high": sev.count("too_high"), "severity_too_low": sev.count("too_low")}

    @app.get("/api/v1/incidents/{inc}")
    def incident(inc: str, _: Actor = Depends(read)):
        hd = inc_head(inc)
        try:
            issues = inc_issues(400 * 24, [inc]).get(inc, [])
        except (OSError, ValueError) as e:
            raise HTTPException(502, vl_down(e))
        v = inc_view(hd, issues, store.inc_meta([inc]).get(inc))
        try:
            items = json.loads(hd.get("alert_items") or "[]")
        except ValueError:
            items = []
        try:
            stats = json.loads(hd.get("stats") or "{}")
        except ValueError:
            stats = {}
        try:
            side = json.loads(hd.get("side_issues") or "[]")
        except ValueError:
            side = []
        v.update(issues=issues, alert_items=items if isinstance(items, list) else [],
                 side_issues=[s for s in side if isinstance(s, dict)] if isinstance(side, list) else [], window=hd.get("window", ""), model=hd.get("model", ""),
                 endpoint=hd.get("endpoint", ""), secs=hd.get("secs"), guard_notes=[x for x in str(hd.get("guard_notes", "")).split(" | ") if x],
                 ungrounded_hosts=int(hd.get("ungrounded_hosts") or 0), dropped_known=int(hd.get("dropped_known") or 0), stats=stats,
                 events=store.inc_events(inc))
        return v

    @app.post("/api/v1/incidents/{inc}/state")
    def incident_state(inc: str, body: IncStateIn, who: Actor = Depends(admin)):
        inc_head(inc)
        try:
            store.inc_set_state(inc, body.state, who.name, None if body.owner is None else body.owner.strip())
        except StoreError as e:
            raise HTTPException(422, {"errors": [str(e)]})
        return {"ok": True}

    @app.post("/api/v1/incidents/{inc}/notes")
    def incident_note(inc: str, body: IncNoteIn, who: Actor = Depends(admin)):
        inc_head(inc)
        store.inc_add_note(inc, redact(body.text.strip()), who.name)
        return {"ok": True}

    @app.post("/api/v1/incidents/{inc}/feedback")
    def incident_feedback(inc: str, body: IncFeedbackIn, who: Actor = Depends(admin)):
        errs = [f"{k} must be one of {', '.join(v)}" for k, v in FB_CHOICES.items() if getattr(body, k) not in v]
        if errs:
            raise HTTPException(422, {"errors": errs})
        inc_head(inc)
        store.inc_set_feedback(inc, {"root_cause": body.root_cause, "severity": body.severity, "grouping": body.grouping,
                                     "comment": redact(body.comment.strip())}, who.name)
        return {"ok": True}

    # ------------------------------------------------------------ visszajatszas: egy tarolt futas ujra, masik modellel / a mai konfiguracioval
    def run_head(rid):
        if not RUN_ID_RX.match(rid):
            raise HTTPException(422, {"errors": ["source must be a digest or incident id like incident-2026-11-25T10:30:57Z"]})
        try:
            rows = aiops.vl_query(f"_time:400d pipeline:ai kind:in(digest,incident) id:={json.dumps(rid)} | limit 1", timeout=20)
        except (OSError, ValueError) as e:
            raise HTTPException(502, vl_down(e))
        if not rows:
            raise HTTPException(404, "unknown digest or incident id")
        return rows[0]

    def run_view(hd):
        """Egy tarolt futas osszevetheto alakja (a visszajatszas eredmenyevel azonos mezok)."""
        try:
            issues = inc_issues(400 * 24, [hd["id"]]).get(hd["id"], [])
        except (OSError, ValueError) as e:
            raise HTTPException(502, vl_down(e))
        try:
            side = json.loads(hd.get("side_issues") or "[]")
        except ValueError:
            side = []
        return {"id": hd["id"], "kind": hd.get("kind"), "time": hd.get("_time"), "model": hd.get("model", ""), "window": hd.get("window", ""),
                "alert": hd.get("alert", ""), "summary": re.sub(r"^\[AI \w+\] ", "", str(hd.get("_msg", ""))), "issues": issues,
                "side_issues": side if isinstance(side, list) else [], "root_hypothesis": hd.get("root_hypothesis", ""),
                "guard_notes": [x for x in str(hd.get("guard_notes", "")).split(" | ") if x],
                "secs": hd.get("secs"), "prompt_tokens": hd.get("prompt_tokens"), "out_tokens": hd.get("out_tokens")}

    def replay_worker(rid, job, model):
        try:
            cur = store.current("known")
            known = aiops.Known(data=cur["content"]) if cur else aiops.Known(data={})
            pool = aiops.EndpointPool(aiops.CFG["OLLAMA_URLS"], model)
            res = aiops.run_job(job, known, pool, model=model, replay=True)
            res.pop("job", None)
            store.replay_finish(rid, result=res)
        except aiops.ReplayError as e:
            store.replay_finish(rid, error=str(e))
        except Exception as e:  # noqa: BLE001 - a hatterszal hibaja a futas hibajakent latszik, nem tunik el
            store.replay_finish(rid, error=f"{type(e).__name__}: {e}")

    @app.get("/api/v1/replays/sources")
    def replay_sources(days: int = Query(7, ge=1, le=30), _: Actor = Depends(read)):
        """A visszajatszhato futasok (digest + incidens) az utolso `days` napbol, legujabb elol."""
        days = min(days, REPLAY_MAX_DAYS)
        try:
            rows = aiops.vl_query(f"_time:{days}d pipeline:ai kind:in(digest,incident) | sort by (_time desc) | limit 200", timeout=20)
        except (OSError, ValueError) as e:
            raise HTTPException(502, vl_down(e))
        return [{"id": r.get("id", ""), "kind": r.get("kind", ""), "time": r.get("_time", ""), "model": r.get("model", ""),
                 "max_severity": r.get("max_severity", ""), "issue_count": int(r.get("issue_count") or 0),
                 "title": aiops.cut(str(r.get("alert") or re.sub(r"^\[AI \w+\] ", "", str(r.get("_msg", "")))), 140)}
                for r in rows if RUN_ID_RX.match(str(r.get("id", "")))]

    @app.get("/api/v1/replays")
    def replay_list(limit: int = Query(50, ge=1, le=200), _: Actor = Depends(read)):
        return {"running": store.replay_running(), "default_model": aiops.CFG["MODEL"], "max_days": REPLAY_MAX_DAYS, "replays": store.replay_list(limit)}

    @app.get("/api/v1/replays/{rid}")
    def replay_get(rid: int, _: Actor = Depends(read)):
        r = store.replay_get(rid)
        if r is None:
            raise HTTPException(404, "unknown replay id")
        r["original"] = run_view(run_head(r["source"]))
        return r

    @app.post("/api/v1/replays")
    def replay_start(body: ReplayIn, who: Actor = Depends(admin)):
        """Egy tarolt digest / incidens ujrafuttatasa ugyanarra az ablakra, a mai zajlistaval, topologiaval es vedelmekkel, kerésre masik
        modellel. Nem ir a tarba, nem ertesit; egyszerre egy fut (a modellgep terhelese miatt). Hatterben fut: a GET /replays/{id} mutatja."""
        model = (body.model or "").strip() or aiops.CFG["MODEL"]
        if not MODEL_RX.match(model):
            raise HTTPException(422, {"errors": ["model may contain letters, digits and . _ : / - only"]})
        hd = run_head(body.source)
        try:
            job, notes = aiops.job_from_head(hd)
        except aiops.ReplayError as e:
            raise HTTPException(422, {"errors": [str(e)]})
        t_from = dt.datetime.strptime(job["window_from"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        if aiops.utcnow() - t_from > dt.timedelta(days=REPLAY_MAX_DAYS):
            raise HTTPException(422, {"errors": [f"the window starts more than {REPLAY_MAX_DAYS} days ago: its log lines are no longer kept"]})
        rid = store.replay_add(who.name, body.source, job["kind"], model, notes)
        if rid is None:
            raise HTTPException(409, "a replay is already running; wait for it to finish")
        threading.Thread(target=replay_worker, args=(rid, job, model), name=f"replay-{rid}", daemon=True).start()
        return {"id": rid, "notes": notes}

    # ------------------------------------------------------------ karbantartasi ablakok
    MAINT_KEEP_ENDED = dt.timedelta(days=7)

    def maint_doc():
        return (store.current("maintenance") or {"content": {"windows": []}})["content"]

    def maint_save(doc, who, comment):
        now = aiops.utcnow().replace(tzinfo=None)
        doc = {"windows": [w for w in doc.get("windows", [])   # a 7 napnal regebben lezart ablakok kikerulnek
                           if (maintenance.parse_ts(w.get("end")) or now) > now - MAINT_KEEP_ENDED]}
        try:
            doc = runtime.validate_doc("maintenance", doc)
            store.put("maintenance", doc, who.name, comment)
        except runtime.DocError as e:
            fail(e)
        rt.changed()

    @app.get("/api/v1/maintenance")
    def maintenance_list(_: Actor = Depends(read)):
        """A karbantartasi ablakok allapottal (active / upcoming / ended) es a tenylegesen lefedett eszkozokkel."""
        doc = maint_doc()
        return {"rev": store.revision_id("maintenance"), "windows": maintenance.views(aiops.TOPOLOGY, doc),
                "suppressed": aiops.STATUS.get("maintenance_suppressed", 0)}

    @app.post("/api/v1/maintenance")
    def maintenance_add(body: MaintIn, who: Actor = Depends(admin)):
        """Uj ablak (alapbol most indul). Olvaso token: javaslat (POST /proposals, key 'maintenance', content)."""
        now = aiops.utcnow().replace(tzinfo=None)
        start = maintenance.parse_ts(body.start) if body.start else now.replace(microsecond=0)
        if start is None:
            raise HTTPException(422, {"errors": ["start must be a UTC time like 2026-11-25T18:00:00Z"]})
        doc = maint_doc()
        wid = body.id or f"mw-{start.strftime('%Y%m%d-%H%M%S')}"
        w = {"id": wid, "targets": [t.strip() for t in body.targets], "start": maintenance.fmt_ts(start),
             "end": maintenance.fmt_ts(start + dt.timedelta(hours=body.hours)), "include_dependents": body.include_dependents}
        if body.note.strip():
            w["note"] = redact(body.note.strip())
        maint_save({"windows": doc.get("windows", []) + [w]}, who, f"maintenance window {wid}: {', '.join(w['targets'])} until {w['end']}")
        return {"ok": True, "id": wid, "window": maintenance.views(aiops.TOPOLOGY, {"windows": [w]})[0]}

    @app.post("/api/v1/maintenance/{wid}/end")
    def maintenance_end(wid: str, who: Actor = Depends(admin)):
        """Ablak lezarasa most (aktiv: az 'end' most; meg nem kezdodott: torles)."""
        doc = maint_doc()
        now = aiops.utcnow().replace(tzinfo=None, microsecond=0)
        out, found = [], False
        for w in doc.get("windows", []):
            if w.get("id") != wid:
                out.append(w)
                continue
            found = True
            s = maintenance.parse_ts(w.get("start"))
            if s and s <= now:                                # aktiv: most er veget (ha ugyanabban a masodpercben indult, a kezdet 1 mp-cel korabbra)
                end = min(now, maintenance.parse_ts(w["end"]) or now)
                out.append(dict(w, start=maintenance.fmt_ts(min(s, end - dt.timedelta(seconds=1))), end=maintenance.fmt_ts(end)))
        if not found:
            raise HTTPException(404, "unknown maintenance window")
        maint_save({"windows": out}, who, f"maintenance window {wid} ended")
        return {"ok": True}

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
        rows = store.nov_findings(None if status == "all" else status, limit=limit)
        adv = noisemodel.ADVISOR
        adv.ensure()                      # a hatterben tanul; kesz modell nelkul a leletek pontszam nelkul jonnek
        known = rt.get_known()
        for f in rows:
            sc = adv.score(f, known)
            if sc is not None:
                f["noise_score"], f["likely_noise"] = sc
        return {"status": novelty.status(store), "findings": rows, "advisor": adv.info()}

    @app.post("/api/v1/novelty/dismiss")
    def novelty_dismiss_many(body: DismissIn, who: Actor = Depends(admin)):
        """Tomeges lezaras azonositok szerint (csoport / 'valoszinuleg zaj' gomb); csak a nyitott leleteket erinti."""
        return {"dismissed": store.nov_dismiss_ids(body.ids, who.name, f"{len(body.ids)} finding(s) (bulk)")}

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
