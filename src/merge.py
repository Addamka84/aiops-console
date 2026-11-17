"""Haromutas osszefesules konfig-dokumentumokra (JSON): alap (a javaslat verzioja), aktualis, javaslat.

A javaslat a teljes dokumentum pillanatkepe a letrehozasakor; ha kozben masik javaslat is lefutott, a pillanatkep elavult. Ahelyett, hogy
felulirna (vagy kenyszeritenek), kiszamoljuk, MIT valtoztatott a javaslat az alaphoz kepest, es azt ratesszuk az aktualis dokumentumra.

Szabalyok:
- szotar: kulcsonkent rekurziv;
- lista: elemhalmaz-szeruen (a hozzaadott elemek bekerulnek, az eltavolitottak kikerulnek, a tobbi marad, a sorrend az aktualisat koveti);
  az 'id' mezos elemek (detektorok, ismert ugyek) azonosito szerint ellenorzottek: ugyanazt az id-t mindket oldal mashogy valtoztatta -> konfliktus;
- skalar: a javaslat erteke ervenyes, ha az aktualis nem tert el az alaptol; ha mindketto mashogy valtozott -> konfliktus.
Konfliktusnal nincs automatikus eredmeny (az ember kenyszerithet: a javaslat sajat tartalma irja felul az aktualisat).
"""

_MISSING = object()


def _eq(a, b):
    return a == b


def _list_merge(base, cur, prop, path, conflicts):
    base, cur, prop = list(base or []), list(cur or []), list(prop or [])
    added = [x for x in prop if x not in base]
    removed = [x for x in base if x not in prop]
    out = [x for x in cur if x not in removed]
    for x in added:
        if x in out:
            continue
        if isinstance(x, dict) and "id" in x:
            clash = next((c for c in out if isinstance(c, dict) and c.get("id") == x["id"]), None)
            if clash is not None:
                conflicts.append(f"{path}[id={x['id']}]")
                continue
        out.append(x)
    return out


def _merge(base, cur, prop, path, conflicts):
    if _eq(prop, base):
        return cur
    if _eq(cur, base) or _eq(cur, prop):
        return prop
    if isinstance(prop, dict) and isinstance(cur, dict):
        b = base if isinstance(base, dict) else {}
        out = {}
        for k in list(cur) + [k for k in prop if k not in cur]:
            kb, kc, kp = b.get(k, _MISSING), cur.get(k, _MISSING), prop.get(k, _MISSING)
            sub = f"{path}.{k}" if path else k
            if kp is _MISSING:
                if kb is _MISSING:
                    out[k] = kc                         # csak az aktualisba kerult be kozben: marad
                elif _eq(kc, kb):
                    continue                            # a javaslat torolte, az aktualis nem valtoztatta: torles
                else:
                    conflicts.append(sub)               # a javaslat torolne, de kozben masvalaki modositotta
                    out[k] = kc
            elif kc is _MISSING:                        # az aktualisbol hianyzik
                if kb is _MISSING:
                    out[k] = kp                         # uj kulcs
                elif _eq(kp, kb):
                    continue                            # masvalaki torolte, a javaslat nem nyult hozza
                else:
                    conflicts.append(sub)
            else:
                out[k] = _merge(kb if kb is not _MISSING else (type(kp)() if isinstance(kp, (dict, list)) else _MISSING), kc, kp, sub, conflicts)
        return out
    if isinstance(prop, list) and isinstance(cur, list):
        return _list_merge(base if isinstance(base, list) else [], cur, prop, path, conflicts)
    conflicts.append(path or "(document)")          # skalar vagy tipus-elteres, mindket oldal mashogy valtozott
    return cur


def merge3(base, cur, prop):
    """-> (osszefesult dokumentum, [konfliktus-utak]). Konfliktusnal az osszefesult dokumentum nem hasznalhato."""
    conflicts = []
    merged = _merge(base, cur, prop, "", conflicts)
    return merged, conflicts
