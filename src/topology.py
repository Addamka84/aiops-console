"""Topologia: a labor eszkozei, IP-k, funkciok es fuggosegek (CMDB-szeru, kicsi, kezzel szerkesztheto).

Egy verziozott konfig-dokumentum ('topology', mint a 'known'): {"assets": [...]}. A modell NEM kerdezi le (egy kis modellnel az eszkozhivas
lassu es megbizhatatlan): a kod valogatja ki, mely eszkozok szerepelnek a riasztasban / a megtartott naplosorokban, hozzaadja a
fuggosegeiket (mitol fugg) es a fuggoit (mi romlik el, ha kiesik), es tomor szakaszkent adja a bemenetbe. A prompt kimondja, hogy
hosztok kozott csak itt latszo fuggosegi ut menten lehet ok-okozati allitast tenni.

Eszkoz mezoi: id (kotelezo, egyedi), name, kind (host|container|network|service|device), ip, role, aliases (a naplokban elofordulo nevek:
host / appname / SYSLOG_IDENTIFIER), runs_on (egy masik eszkoz id-je; konteneren a host), depends_on [{id, type, note?}],
criticality (low|normal|high), note.
"""
import ipaddress
import re

KINDS = ("host", "container", "network", "service", "device")
DEP_TYPES = ("network", "storage", "dns", "mqtt", "power", "runtime", "data", "auth", "other")
CRITICALITY = ("low", "normal", "high")
MAX_ASSETS = 400
_ID_RX = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,48}$")
_FIELDS = {"id", "name", "kind", "ip", "role", "aliases", "runs_on", "depends_on", "criticality", "note"}
_CRIT_RANK = {"high": 0, "normal": 1, "low": 2}


def validate(doc):
    """-> hibak listaja (ures = ervenyes)."""
    if not isinstance(doc, dict):
        return ["the topology document must be a JSON object"]
    errs = [f"unknown top-level key {k!r}" for k in doc if k != "assets"]
    assets = doc.get("assets", [])
    if not isinstance(assets, list):
        return errs + ["assets must be a list"]
    if len(assets) > MAX_ASSETS:
        errs.append(f"at most {MAX_ASSETS} assets")
    ids, keys = set(), {}
    for i, a in enumerate(assets):
        where = f"assets[{i}]"
        if not isinstance(a, dict):
            errs.append(f"{where}: must be an object")
            continue
        aid = a.get("id")
        if isinstance(aid, str):
            where = f"asset {aid!r}"
        extra = sorted(set(a) - _FIELDS)
        if extra:
            errs.append(f"{where}: unknown field(s) {', '.join(extra)}")
        if not isinstance(aid, str) or not _ID_RX.match(aid):
            errs.append(f"{where}: id must be lowercase letters, digits, '_', '.', '-' (max 49 chars)")
            continue
        if aid in ids:
            errs.append(f"{where}: duplicate id")
        ids.add(aid)
        if a.get("kind") not in KINDS:
            errs.append(f"{where}: kind must be one of {', '.join(KINDS)}")
        if a.get("criticality", "normal") not in CRITICALITY:
            errs.append(f"{where}: criticality must be one of {', '.join(CRITICALITY)}")
        for f, n in (("name", 80), ("role", 200), ("note", 300)):
            v = a.get(f, "")
            if not isinstance(v, str) or len(v) > n:
                errs.append(f"{where}: {f} must be a string of at most {n} characters")
        ip = a.get("ip", "")
        if ip:
            try:
                ipaddress.ip_address(ip)
            except (ValueError, TypeError):
                errs.append(f"{where}: invalid ip {ip!r}")
        al = a.get("aliases", [])
        if not isinstance(al, list) or len(al) > 10 or any(not isinstance(x, str) or not 1 <= len(x.strip()) <= 80 for x in al):
            errs.append(f"{where}: aliases must be a list of at most 10 non-empty strings")
            al = []
        for k in {aid, str(a.get("name", "")).strip().lower(), str(ip).strip(), *[x.strip().lower() for x in al]} - {""}:
            if keys.setdefault(k, aid) != aid:
                errs.append(f"{where}: name/alias/ip {k!r} is already used by {keys[k]!r}")
    for a in assets:
        if not isinstance(a, dict) or a.get("id") not in ids:
            continue
        aid = a["id"]
        ro = a.get("runs_on")
        if ro:
            if ro not in ids:
                errs.append(f"asset {aid!r}: runs_on {ro!r} does not exist")
            elif ro == aid:
                errs.append(f"asset {aid!r}: runs_on points to itself")
        deps = a.get("depends_on", [])
        if not isinstance(deps, list) or len(deps) > 20:
            errs.append(f"asset {aid!r}: depends_on must be a list of at most 20 items")
            continue
        for d in deps:
            if not isinstance(d, dict) or set(d) - {"id", "type", "note"}:
                errs.append(f"asset {aid!r}: each dependency must be an object with id, type, note")
            elif d.get("id") not in ids:
                errs.append(f"asset {aid!r}: dependency {d.get('id')!r} does not exist")
            elif d["id"] == aid:
                errs.append(f"asset {aid!r}: depends on itself")
            elif d.get("type", "other") not in DEP_TYPES:
                errs.append(f"asset {aid!r}: dependency type must be one of {', '.join(DEP_TYPES)}")
    return errs


class Topology:
    def __init__(self, doc=None):
        self.assets = {}
        for a in (doc or {}).get("assets", []):
            self.assets[a["id"]] = a
        self.keys = {}  # kisbetus nev / alias / ip -> id
        for aid, a in self.assets.items():
            for k in {aid, str(a.get("name", "")).strip().lower(), str(a.get("ip", "")).strip(), *[x.strip().lower() for x in a.get("aliases", [])]} - {""}:
                self.keys.setdefault(k, aid)
        self.up = {aid: [] for aid in self.assets}     # aid -> [(dep_id, type)]: mitol fugg
        self.down = {aid: [] for aid in self.assets}   # aid -> [(user_id, type)]: mi fugg tole
        for aid, a in self.assets.items():
            edges = [(d["id"], d.get("type", "other")) for d in a.get("depends_on", [])]
            if a.get("runs_on"):
                edges.insert(0, (a["runs_on"], "runtime"))
            for dep, typ in edges:
                if dep in self.assets:
                    self.up[aid].append((dep, typ))
                    self.down[dep].append((aid, typ))
        keys = sorted(self.keys, key=len, reverse=True)
        self._rx = re.compile(r"(?<![A-Za-z0-9_.-])(?:%s)(?![A-Za-z0-9_-])" % "|".join(re.escape(k) for k in keys), re.I) if keys else None

    def __bool__(self):
        return bool(self.assets)

    def find(self, name):
        """Egy konkret nev / alias / IP -> eszkoz id (vagy None)."""
        return self.keys.get(str(name).strip().lower()) or self.keys.get(str(name).strip())

    def match(self, texts, limit=8):
        """Szovegekben (elsobbseg szerint rendezve) elofordulo eszkozok id-i, az elso elofordulas sorrendjeben."""
        out = []
        if not self._rx:
            return out
        for t in texts:
            for m in self._rx.finditer(t or ""):
                aid = self.find(m.group(0))
                if aid and aid not in out:
                    out.append(aid)
                    if len(out) >= limit:
                        return out
        return out

    def _nm(self, aid):
        return self.assets[aid].get("name") or aid

    def _line(self, aid):
        a = self.assets[aid]
        head = f"{self._nm(aid)} ({a['kind']}" + (f", {a['ip']}" if a.get("ip") else "") + ")"
        if a.get("role"):
            head += f" - {a['role']}"
        if a.get("criticality") == "high":
            head += " [high criticality]"
        if a.get("note"):
            head += f". {a['note']}"
        up = [f"{self._nm(d)} ({t})" for d, t in self.up[aid]]
        down = sorted(self.down[aid], key=lambda e: (_CRIT_RANK.get(self.assets[e[0]].get("criticality", "normal"), 1), e[0]))
        real = [e for e in down if e[1] != "runtime"]    # igazi fuggok (tarolas, halozat, DNS...)
        runs = [e for e in down if e[1] == "runtime"]    # a rajta futo konteneres / szolgaltatasok: kulon, tomoren
        shown = [f"{self._nm(d)} ({t})" for d, t in real[:6]]
        extra = f" (+{len(real) - 6} more)" if len(real) > 6 else ""
        hosted = [self._nm(d) for d, _t in runs[:5]]
        hextra = f" (+{len(runs) - 5} more)" if len(runs) > 5 else ""
        return (head + (f" | depends on: {', '.join(up)}" if up else "")
                + (f" | needed by: {', '.join(shown)}{extra}" if shown else "")
                + (f" | runs: {', '.join(hosted)}{hextra}" if hosted else ""))

    def section(self, seeds, max_lines=22, max_chars=2600):
        """A bemenet szakasza: a kert eszkozok + mitol fuggnek (2 szint) + mi fugg toluk (1 szint, a sorban). [] ha nincs mit."""
        order = [s for s in seeds if s in self.assets]
        if not order:
            return []
        frontier = list(order)
        for _ in range(2):  # fuggosegek: legfeljebb 2 szintig felfele
            nxt = []
            for aid in frontier:
                for dep, typ in self.up[aid]:
                    if dep not in order:
                        order.append(dep)
                        if typ != "runtime":     # a futtato hostot felvesszuk, de annak sajat fuggosegeire nem terjeszkedunk (zaj lenne)
                            nxt.append(dep)
            frontier = nxt
        lines, size = [], 0
        for n, aid in enumerate(order):
            ln = self._line(aid)
            if len(lines) >= max_lines or size + len(ln) > max_chars:
                lines.append(f"(+{len(order) - n} more related devices not shown)")
                break
            lines.append(ln)
            size += len(ln) + 1
        return ["== Topology (devices involved, IPs, roles and dependencies; 'depends on' = what it needs, 'needed by' = what breaks if it fails):"] + lines


def coverage(topo, seen):
    """seen: [{"name", "kind": host|container, "host", "source", "lines"}] a naplokbol.
    -> {"unknown": a naplokban latott, de a topologiaban nem szereplo nevek, "silent": a topologiaban szereplo host/container eszkozok,
    amelyek a naplokban nem latszanak}."""
    unknown, hit = [], set()
    for s in seen:
        aid = topo.find(s["name"])
        if aid:
            hit.add(aid)
        else:
            unknown.append(s)
    silent = [{"id": aid, "name": a.get("name") or aid, "kind": a["kind"]} for aid, a in topo.assets.items()
              if a["kind"] in ("host", "container") and aid not in hit]
    unknown.sort(key=lambda s: -s.get("lines", 0))
    return {"unknown": unknown, "silent": silent}
