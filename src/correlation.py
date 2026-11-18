"""Riasztas-korrelacio a topologian at: a ugyanazon ok miatt egyszerre megszolalo riasztasok EGY incidensbe vonasa, gyokerok-jelolttel.

Ma egy NAS-kiesesre egyszerre jon az NFS-riasztas, a Plex-hiba, a mentes-hiba... Itt ezek elemekke (items) valnak, es egy rovid
"leulepedesi" ablak utan (CORRELATE_SETTLE_S) egyetlen incidens-munka indul belolük, a tobbi mellett a kodban szamolt gyokerok-jelolttel:
  * a legfelso (a halmazban mas eszkoztol fuggo nelkuli) eszkoz, amelyik a legtobb tobbit "magyarazza" (alatta/rajta fut/tole fugg),
  * a bizonyossag = a magyarazott eszkozok aranya, es a kozos (hub-nak nem szamito) fuggoseg, ha az eredetek fuggetlenek.
Ket riasztas rokon, ha az eszkozeik (topology.py) azonosak (1.0), az egyik a masiktol fugg (0.95 - 0.1/ugras), vagy kozos, nem-hub
felsobb eszkozuk van (0.6, legfeljebb 1+1 ugras). Hub = nagy "fan-out"u eszkoz (pl. a router, a HA host a sok integraciojaval): onmagaban
nem bizonyitek, ezert pl. ket kulonbozo HA-integracio hibaja nem vonodik ossze.
A modell semmit nem dont ebben: csak megfogalmazza az eredmenyt (a bemenetben a gyokerok-jelolt hipotezisnek van jelolve).
"""
from collections import defaultdict

DEPTH = 3
JOIN_TH = 0.55


def _hub(topo, ci, hub_fanout):
    return len(topo_down(topo, ci, 2)) > hub_fanout


# Egy host sajat fuggosegei (pl. az NFS-e) nem terjednek tovabb a rajta futo konteneren / szolgaltatason, hacsak az nem deklaralja:
# a "runtime" el utan felfele csak halozat / aram / runtime elek, lefele a nem-terjedo (tarolas, adat, DNS) el utan nincs "runtime" lepes.
PROPAGATES = {"network", "power", "runtime"}


def _bfs(adj, start, depth, direction):
    seen, frontier = {}, [(start, False)]
    for d in range(1, depth + 1):
        nxt = []
        for x, flag in frontier:
            for y, t in adj.get(x, ()):
                if y == start or y in seen:
                    continue
                if direction == "up":
                    if flag and t not in PROPAGATES:
                        continue
                    nf = flag or t == "runtime"
                else:
                    if flag and t == "runtime":
                        continue
                    nf = flag or t not in PROPAGATES
                seen[y] = d
                nxt.append((y, nf))
        frontier = nxt
    return seen


def topo_up(topo, ci, depth=DEPTH):
    return _bfs(topo.up, ci, depth, "up")


def topo_down(topo, ci, depth=DEPTH):
    return _bfs(topo.down, ci, depth, "down")


def resolve_cis(topo, texts, limit=6):
    """Szovegekbol (riasztas-szoveg, cimkek ertekei) a topologia eszkozei, az elso elofordulas sorrendjeben."""
    if not topo:
        return []
    return topo.match([t for t in texts if t], limit=limit)


def new_cache():
    """A relation() gyorsitotara egy klaszterezesi futashoz: az 'up' bejaras (topo_up) es a hub-szamitas eszkozonkent egyszer."""
    return {"up": {}, "hub": {}}


def relation(topo, a_cis, b_cis, hub_fanout=25, cache=None):
    """Ket elem (eszkozlistak) kozotti kapcsolat erőssege 0..1. A cache (new_cache()) csak gyorsit: az eredmeny ugyanaz."""
    cache = cache if cache is not None else new_cache()

    def up(ci):
        if ci not in cache["up"]:
            cache["up"][ci] = topo_up(topo, ci)
        return cache["up"][ci]

    def hub(ci):
        if ci not in cache["hub"]:
            cache["hub"][ci] = _hub(topo, ci, hub_fanout)
        return cache["hub"][ci]
    best = 0.0
    for a in a_cis:
        up_a = up(a)
        for b in b_cis:
            if a == b:
                return 1.0
            d = up_a.get(b)
            if d is not None:
                best = max(best, 0.95 - 0.1 * d)
            d2 = up(b).get(a)
            if d2 is not None:
                best = max(best, 0.95 - 0.1 * d2)
            if best < 0.6:
                up_b = up(b)
                for anc, da in up_a.items():
                    db = up_b.get(anc)
                    if db is not None and not hub(anc):
                        best = max(best, 0.6 - 0.1 * (da + db - 2))
    return best


def cluster_pairwise(topo, items, window_s=600, hub_fanout=25):
    """REFERENCIA (a regi, paronkenti O(n^2) algoritmus): a tesztek ezzel igazoljak, hogy a gyors cluster() azonos eredmenyt ad."""
    n = len(items)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    cache = new_cache()
    for i in range(n):
        for j in range(i + 1, n):
            if abs(items[i]["ts"] - items[j]["ts"]) > window_s or not items[i]["cis"] or not items[j]["cis"]:
                continue
            if relation(topo, items[i]["cis"], items[j]["cis"], hub_fanout, cache) >= JOIN_TH:
                parent[find(i)] = find(j)
    groups = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(i)
    return sorted(groups.values(), key=lambda g: g[0])


def cluster(topo, items, window_s=600, hub_fanout=25):
    """items: [{"ts", "cis", ...}] -> list of index lists (egy lista = egy incidens). Idoben (window_s) es a topologiaban rokon elemek egyutt.
    Gyors valtozat (az eredmeny azonos a cluster_pairwise()-szel): a kapcsolat csak az eszkozlistak HALMAZAITOL fugg, ezert az azonos halmazu elemeket egyben
    kezeli: a relation() csak a KULONBOZO halmaz-parokra fut (gyorsitotarral), az idoablakos osszevonast pedig rendezett lista + ketmutatos soprés
    vegzi (O(n) egy rokon halmaz-parra). Az eseményvihar (sok elem egy ablakban, kevés kulonbozo eszkozhalmaz) igy nem negyzetes."""
    n = len(items)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        parent[find(i)] = find(j)
    by_set = defaultdict(list)
    for i, it in enumerate(items):
        if it["cis"]:
            by_set[frozenset(it["cis"])].append(i)
    keys = sorted(by_set, key=lambda k: sorted(k))
    for k in keys:
        by_set[k].sort(key=lambda i: items[i]["ts"])
        idx = by_set[k]
        for x, y in zip(idx, idx[1:]):                       # azonos halmaz: relation = 1.0, az ablakon beluli szomszedok lancolodnak
            if items[y]["ts"] - items[x]["ts"] <= window_s:
                union(x, y)
    cache = new_cache()
    for x in range(len(keys)):
        for y in range(x + 1, len(keys)):
            if relation(topo, sorted(keys[x]), sorted(keys[y]), hub_fanout, cache) < JOIN_TH:
                continue
            la, lb = by_set[keys[x]], by_set[keys[y]]
            prev_r = 0
            lo = 0
            hi = 0
            for ia in la:                                    # minden a-hoz a b-lista [lo, hi) tartomanya van az ablakon belul (mindket vege monoton)
                ta = items[ia]["ts"]
                while lo < len(lb) and items[lb[lo]]["ts"] < ta - window_s:
                    lo += 1
                hi = max(hi, lo)
                while hi < len(lb) and items[lb[hi]]["ts"] <= ta + window_s:
                    hi += 1
                if lo < hi:
                    union(ia, lb[lo])
                    for k in range(max(lo, prev_r - 1), hi - 1):
                        union(lb[k], lb[k + 1])
                    prev_r = hi
    groups = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(i)
    return sorted(groups.values(), key=lambda g: g[0])


def analyze(topo, items, hub_fanout=25):
    """Egy csomo gyokerok-jelolt elemzese. -> dict (alerts, cis, root, confidence, alternatives, suspected_dependency, impacted)."""
    cis = []
    for it in items:
        for c in it["cis"]:
            if c not in cis:
                cis.append(c)
    info = {"alerts": len(items), "cis": cis, "root": None, "confidence": 0.0, "alternatives": [], "suspected_dependency": None, "impacted": 0}
    if not cis or not topo:
        return info
    cset = set(cis)
    first = {}
    count = defaultdict(int)
    for it in items:
        for c in it["cis"]:
            first.setdefault(c, it["ts"])
            count[c] += 1
    tops = [c for c in cis if not any(a in cset for a in topo_up(topo, c))]

    def explained(c):
        return 1 + sum(1 for d in topo_down(topo, c) if d in cset)
    ranked = sorted(tops, key=lambda c: (-explained(c), -count[c], first[c], c))
    root = ranked[0]
    info["root"] = root
    info["confidence"] = round(explained(root) / len(cis), 2)
    info["alternatives"] = ranked[1:4]
    if info["confidence"] < 0.8 and len(tops) >= 2:
        counts = defaultdict(int)
        for t in tops:
            for a in topo_up(topo, t):
                if a not in cset and not _hub(topo, a, hub_fanout):
                    counts[a] += 1
        if counts:
            best, cover = max(counts.items(), key=lambda kv: (kv[1], -len(topo_down(topo, kv[0], 2))))
            if cover >= 2:
                info["suspected_dependency"] = {"ci": best, "explains": cover, "of": len(tops)}
    info["impacted"] = len(set(topo_down(topo, root)) | cset)
    return info


def describe(topo, info):
    """A modell bemenetenek sorai a gyokerok-jelolt hipotezisrol (a nevek a topologiabol)."""
    if not info.get("root"):
        return []
    nm = lambda c: topo.assets[c].get("name") or c  # noqa: E731
    L = [f"== Root-cause HYPOTHESIS computed from the topology (not a certainty): {nm(info['root'])} "
         f"(it explains {int(round(info['confidence'] * len(info['cis'])))} of {len(info['cis'])} affected items, confidence {info['confidence']})."]
    if info["alternatives"]:
        L.append("   Other possible origins: " + ", ".join(nm(c) for c in info["alternatives"]) + ".")
    sd = info.get("suspected_dependency")
    if sd:
        L.append(f"   A shared dependency without its own alert may be the cause: {nm(sd['ci'])} (would explain {sd['explains']} of {sd['of']} independent origins).")
    L.append(f"   Potentially impacted items (downstream of the hypothesis): {info['impacted']}.")
    return L
