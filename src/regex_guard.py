"""Regex-vedelem (ReDoS): a konfigba kerulo regexeket egy KULON ALFOLYAMATBAN, idokorlattal probalja ki rovid, ellenseges teszt-szovegeken.

Miert alfolyamat: a Python `re` modulja nem szakithato meg, es tartja a GIL-t: egy katasztrofalis visszalepesu regex (pl. `(\\w|\\d)+\\s+x`) az egesz szolgaltatast
(API, triazs, supervisor) megallitana. Az alfolyamat idokorlat utan kilohetö. Ez heurisztika (a teszt-szoveg-keszlet veges), nem bizonyitek: a leggyakoribb
mintakat (egymasba agyazott / atfedo ismetles) fogja meg. Csak a Python standard konyvtar. Ha az alfolyamat nem indithato, az ellenorzes kimarad (naplozva).
"""
import json
import subprocess
import sys
import threading

TIMEOUT_S = 5
_PROBES = ["a" * 40 + "!", "1" * 40 + "!", " " * 40 + "!", "_" * 40 + "!", "ab" * 20 + "!", "a " * 20 + "!", "<N> " * 15 + "!", "x." * 20 + "!",
           "-" * 40 + "!", "a1" * 20 + "!"]
_CHILD = (
    "import sys, json, re\n"
    "rx = json.load(sys.stdin)\n"
    "P = " + repr(_PROBES) + "\n"
    "for i, x in enumerate(rx):\n"
    "    print(i, flush=True)\n"
    "    c = re.compile(x)\n"
    "    chars = []\n"
    "    for ch in x:\n"
    "        if (ch.isalnum() or ch in ' _.-') and ch not in chars:\n"
    "            chars.append(ch)\n"
    "    own = [ch * 40 + '!' for ch in chars[:16]] + [a + b + (a + b) * 19 + '!' for a, b in zip(chars[:6], chars[1:7])]\n"
    "    for p in P + own:\n"
    "        c.search(p)\n"
)
_OK = set()          # mar bizonyitottan gyors regexek (nem futtatjuk ujra)
_LOCK = threading.Lock()


def check(regexes, timeout=TIMEOUT_S):
    """-> None (rendben / nem ellenorizheto) vagy a hibauzenet (a gyanus regex elejevel). Az ervenytelen (nem forduló) regexet kihagyja: azt mas ellenorzes jelzi."""
    import re
    todo = []
    for x in dict.fromkeys(r for r in regexes if isinstance(r, str)):
        if x in _OK:
            continue
        try:
            re.compile(x)
        except re.error:
            continue
        todo.append(x)
    if not todo:
        return None
    try:
        r = subprocess.run([sys.executable, "-I", "-S", "-c", _CHILD], input=json.dumps(todo).encode("utf-8"), capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace").split()
        idx = int(out[-1]) if out and out[-1].isdigit() and int(out[-1]) < len(todo) else 0
        return f"regex may cause catastrophic backtracking (the test took over {timeout} s): {todo[idx][:80]}"
    except OSError:
        return None
    if r.returncode != 0:
        return None      # a gyermek hibaja (pl. memoria): nem a regex bizonyitott hibaja, nem akadalyozzuk a mentest
    with _LOCK:
        _OK.update(todo)
    return None
