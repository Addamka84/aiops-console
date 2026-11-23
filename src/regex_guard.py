"""Regex-vedelem (ReDoS): a konfigba es a modelltol erkezo regexek ellenorzese, MIELOTT barhol a folyamaton belul futnanak.

Ket lepcso (alpha.30, a masodik audit H1 lelete utan):
1. Szerkezeti elemzes (a Python sajat regex-elemzojevel, futtatas nelkul): elutasitja a visszalepesre hajlamos alakokat:
   - egymasba agyazott korlatlan ismetles, pl. (x+)+, (a*b?)*  (exponencialis)
   - korlatlanul ismetelt alternacio, pl. (a|aa)+, (?:foo|bar)*  (exponencialis, ha az agak atfednek; az atfedest nem bizonyitjuk, ezert altalaban tiltott)
   - tul sok szeles korlatlan ismetles (.*, \\S+, [^x]* ...): legfeljebb 3, es ket ilyen nem allhat egymas mellett kotelezo karakter nelkul
     (.*.*, \\s*.*: polinomialis, egy 300 jeles sorra percek)
   - a regex hossza legfeljebb 500 jel
2. Idozitett proba KULON ALFOLYAMATBAN, ellenseges szovegeken: az altalanos mintak mellett a regex SAJAT elotagjaval kezdodo, az ismetles
   karaktereivel felfujt szovegek is (a 2026-11-17-es valtozat ezt nem tette, ezert egy 'myapp \\| (x+)+ zz' atment).
   Az alfolyamat hibaja vagy elindithatatlansaga ELUTASITAS (fail-closed); korabban atengedes volt.
Miert alfolyamat: a Python `re` modulja nem szakithato meg es tartja a GIL-t. Csak a Python standard konyvtar.
Korlat: ez heurisztika, nem bizonyitek; a teljes megoldas egy idokorlatos vagy linearis motor (regex / RE2), ami uj fuggoseg.
"""
import json
import subprocess
import sys
import threading

try:                                   # Python 3.11+
    import re._constants as _c
    import re._parser as _p
except ImportError:                    # pragma: no cover - regebbi Python
    import sre_constants as _c
    import sre_parse as _p

TIMEOUT_S = 5
MAX_LEN = 500
MAX_BROAD = 3
_PROBES = ["a" * 40 + "!", "1" * 40 + "!", " " * 40 + "!", "_" * 40 + "!", "ab" * 20 + "!", "a " * 20 + "!", "<N> " * 15 + "!", "x." * 20 + "!",
           "-" * 40 + "!", "a1" * 20 + "!"]
_CHILD = (
    "import sys, json, re\n"
    "todo = json.load(sys.stdin)\n"
    "P = " + repr(_PROBES) + "\n"
    "for i, (x, extra) in enumerate(todo):\n"
    "    print(i, flush=True)\n"
    "    c = re.compile(x)\n"
    "    chars = []\n"
    "    for ch in x:\n"
    "        if (ch.isalnum() or ch in ' _.-') and ch not in chars:\n"
    "            chars.append(ch)\n"
    "    own = [ch * 40 + '!' for ch in chars[:16]] + [a + b + (a + b) * 19 + '!' for a, b in zip(chars[:6], chars[1:7])]\n"
    "    for p in P + own + extra:\n"
    "        c.search(p)\n"
)
_OK = set()          # mar bizonyitottan gyors regexek (nem futtatjuk ujra)
_LOCK = threading.Lock()
_UNBOUNDED = 32      # ennel nagyobb felso hatar 'korlatlannak' szamit
_REPEATS = {_c.MAX_REPEAT, _c.MIN_REPEAT}


def _is_rep(op, av):
    return op in _REPEATS and (av[1] == _c.MAXREPEAT or av[1] > _UNBOUNDED)


def _items(sub):
    return list(sub.data) if hasattr(sub, "data") else list(sub)


def _children(op, av):
    if op in _REPEATS or op == getattr(_c, "POSSESSIVE_REPEAT", None):
        return [_items(av[2])]
    if op == _c.SUBPATTERN:
        return [_items(av[3])]
    if op == _c.BRANCH:
        return [_items(b) for b in av[1]]
    if op in (_c.ASSERT, _c.ASSERT_NOT):
        return [_items(av[1])]
    if op == getattr(_c, "ATOMIC_GROUP", None):
        return [_items(av)]
    if op == _c.GROUPREF_EXISTS:
        return [_items(b) for b in av[1:] if b is not None]
    return []


def _contains(items, pred):
    for op, av in items:
        if pred(op, av):
            return True
        if any(_contains(ch, pred) for ch in _children(op, av)):
            return True
    return False


_ALPH = frozenset([chr(i) for i in range(32, 127)] + ["	"])
_DIG = frozenset("0123456789")
_SPC = frozenset(" 	")
_WRD = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_CATS = {"CATEGORY_DIGIT": _DIG, "CATEGORY_NOT_DIGIT": _ALPH - _DIG, "CATEGORY_SPACE": _SPC, "CATEGORY_NOT_SPACE": _ALPH - _SPC,
         "CATEGORY_WORD": _WRD, "CATEGORY_NOT_WORD": _ALPH - _WRD}
VERY_BROAD = 85      # ennyi jel a 96-bol: '.', '\S', '[^x]' jellegu osztaly


def _cset(op, av):
    """Az egyetlen jelre illeszkedo csomopont jelkeszlete (ASCII-mintan) vagy None."""
    if op == _c.LITERAL:
        return frozenset([chr(av)])
    if op == _c.NOT_LITERAL:
        return _ALPH - {chr(av)}
    if op == _c.ANY:
        return _ALPH
    if op == _c.CATEGORY:
        return _CATS.get(getattr(av, "name", str(av)), _ALPH)
    if op == _c.IN:
        neg, acc = False, set()
        for o, a in av:
            if o == _c.NEGATE:
                neg = True
            elif o == _c.LITERAL:
                acc.add(chr(a))
            elif o == _c.RANGE:
                acc.update(chr(i) for i in range(a[0], a[1] + 1))
            elif o == _c.CATEGORY:
                acc.update(_CATS.get(getattr(a, "name", str(a)), _ALPH))
        return frozenset(_ALPH - acc) if neg else frozenset(acc & _ALPH)
    return None


def _rep_set(op, av):
    """Korlatlan ismetles egyetlen jelosztaly felett -> a jelkeszlet, egyebkent None."""
    if not _is_rep(op, av):
        return None
    body = _items(av[2])
    return _cset(*body[0]) if len(body) == 1 else None


def _min_width(op, av):
    try:
        return _p.SubPattern(_p.State(), [(op, av)]).getwidth()[0]
    except Exception:  # noqa: BLE001
        return 1


def structural_problem(rx):
    """-> None vagy az elutasitas oka (futtatas nelkuli elemzes)."""
    if len(rx) > MAX_LEN:
        return f"regex is longer than {MAX_LEN} characters"
    try:
        tree = _items(_p.parse(rx))
    except Exception:  # noqa: BLE001 - a fordithatatlan regexet mas ellenorzes jelzi
        return None

    def walk(items):
        for op, av in items:
            if _is_rep(op, av):
                body = _items(av[2])
                if _contains(body, _is_rep):
                    return "nested unbounded quantifiers such as (x+)+ are not allowed (catastrophic backtracking)"
                if _contains(body, lambda o, a: o == _c.BRANCH):
                    return "a repeated alternation such as (a|aa)+ is not allowed (catastrophic backtracking)"
            for ch in _children(op, av):
                m = walk(ch)
                if m:
                    return m
        return None

    m = walk(tree)
    if m:
        return m
    def seq(items):
        prev = None
        for op, av in items:
            cs = _rep_set(op, av)
            if cs is not None:
                if prev is not None and prev & cs:
                    return "two overlapping repeats next to each other such as .*.* or \\s*.* are not allowed (polynomial backtracking)"
                prev = cs
            elif _min_width(op, av) > 0:
                prev = None
            for ch in _children(op, av):
                r = seq(ch)
                if r:
                    return r
        return None

    m = seq(tree)
    if m:
        return m
    if _path_broad(tree) > MAX_BROAD:
        return f"more than {MAX_BROAD} very broad repeats such as .* or \\S+ on one path (polynomial backtracking on long lines)"
    return None


def _path_broad(items):
    """A nagyon szeles korlatlan ismetlesek szama egy illeszkedesi uton (alternacional az agak maximuma, nem az osszege)."""
    n = 0
    for op, av in items:
        cs = _rep_set(op, av)
        if cs is not None:
            n += 1 if len(cs) >= VERY_BROAD else 0
        elif op == _c.BRANCH:
            n += max((_path_broad(b) for b in _children(op, av)), default=0)
        else:
            n += sum(_path_broad(ch) for ch in _children(op, av))
    return n


def _rep_char(op, av):
    """Egy jel, amire a csomopont illeszkedik (a felfujt proba-szoveghez)."""
    if op == _c.LITERAL:
        return chr(av)
    if op == _c.ANY:
        return "a"
    if op == _c.CATEGORY:
        return {"CATEGORY_DIGIT": "1", "CATEGORY_SPACE": " ", "CATEGORY_WORD": "a"}.get(getattr(av, "name", str(av)), "!")
    if op == _c.IN:
        for o, a in av:
            if o == _c.LITERAL:
                return chr(a)
            if o == _c.RANGE:
                return chr(a[0])
            if o == _c.CATEGORY:
                return _rep_char(_c.CATEGORY, a)
        return "a"
    for ch in _children(op, av):
        s = "".join(_rep_char(o, a) for o, a in ch[:4])
        if s:
            return s
    return ""


def attack_strings(rx):
    """A regex sajat elotagjaval kezdodo, minden ismetlesnel az ismetelt resszel felfujt, a vegen elbukó szovegek."""
    try:
        tree = _items(_p.parse(rx))
    except Exception:  # noqa: BLE001
        return []
    out, prefix = [], ""
    for op, av in tree:
        if op in _REPEATS or op == getattr(_c, "POSSESSIVE_REPEAT", None):
            unit = "".join(_rep_char(o, a) for o, a in _items(av[2])) or "a"
            for n in (24, 40):
                out.append(prefix + unit * n + "!")
                out.append(prefix + (unit + " ") * (n // 2) + "!")
            prefix += unit * max(1, av[0])
        elif op in (_c.AT,):
            continue
        else:
            prefix += _rep_char(op, av)
        if len(prefix) > 200:
            break
    return out[:24]


def check(regexes, timeout=TIMEOUT_S):
    """-> None (rendben) vagy a hibauzenet (a gyanus regex elejevel). Az ervenytelen (nem fordulo) regexet kihagyja: azt mas ellenorzes jelzi."""
    import re
    todo = []
    for x in dict.fromkeys(r for r in regexes if isinstance(r, str)):
        if x in _OK:
            continue
        try:
            re.compile(x)
        except re.error:
            continue
        m = structural_problem(x)
        if m:
            return f"{m}: {x[:80]}"
        todo.append(x)
    if not todo:
        return None
    payload = [[x, attack_strings(x)] for x in todo]
    try:
        r = subprocess.run([sys.executable, "-I", "-S", "-c", _CHILD], input=json.dumps(payload).encode("utf-8"), capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace").split()
        idx = int(out[-1]) if out and out[-1].isdigit() and int(out[-1]) < len(todo) else 0
        return f"regex may cause catastrophic backtracking (the test took over {timeout} s): {todo[idx][:80]}"
    except OSError as e:
        return f"the regex safety check could not run ({type(e).__name__}); the regex is not accepted"
    if r.returncode != 0:
        return "the regex safety check failed (the test process ended with an error); the regex is not accepted"
    with _LOCK:
        _OK.update(todo)
    return None
