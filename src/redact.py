"""Titokszuro: a modell bemenetebol es kimenetebol (es a jelentesekbol, javaslatokbol) kiszuri a titkokat es hozzaferesi azonositokat.

Kozos modul (a triazs-ag aiops.py-ja es a supervisor.py is ezt hasznalja). Csak a Python standard konyvtar. A szures konzervativ, de nem teljes:
ismert alakokra epul (privat kulcs, Bearer/Basic, kulcs=ertek, JSON titokmezo, JWT, AWS kulcsazonosito, URL-ben levo user:jelszo, jatekszerver-
titkok, hosszu veletlen tokenek). Egy ismeretlen alaku titkot nem fog meg: a naplo szovege ettol meg nem megbizhato adat.
"""
import re

_RX_PRIVKEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)
_RX_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_RX_PARAM = re.compile(r"(?i)\b([A-Za-z0-9_.-]*(?:signature|accesskeyid|access_key|accesskey|token|apikey|api_key|secret|passwd|password|authorization|credential)[A-Za-z0-9_.-]*)"
                       r"(\s*[=:]\s*)(?!<redacted>)(\"[^\"]*\"|'[^']*'|[^\s&;,\"'}]+)")
_RX_JSONKEY = re.compile(r"(?i)(\"[A-Za-z0-9_.-]*(?:password|passwd|token|secret|api_?key|signature|credential)[A-Za-z0-9_.-]*\"\s*:\s*)\"[^\"]*\"")
# jatekszerver-parancsok: "rcon_password hunter2", "sv_setsteamaccount <GSLT>" (szokozzel elvalasztva, nem '='-val)
_RX_GAMECMD = re.compile(r"(?i)\b(rcon_password|sv_password|sv_setsteamaccount|sv_steamaccount|gslt)(\s+)(?!<redacted>)(\"[^\"]*\"|[^\s;\"]+)")
_RX_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_RX_AWSKEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_RX_USERINFO = re.compile(r"(://)[^/\s:@]+:[^/\s@]+@")
_RX_LONG = re.compile(r"(?<![A-Za-z0-9_/.-])(?=[A-Za-z0-9_+=-]*\d)(?=[A-Za-z0-9_+=-]*[A-Za-z])[A-Za-z0-9_+=-]{40,}(?![A-Za-z0-9_/.-])")
# 32-39 jegu, tisztan hexa karakterlanc (md5-szeru kulcs, 32 jegyu GSLT): kotojelet/alahuzast nem tartalmaz, igy a gepnevek, egysegnevek nem esnek ide
_RX_HEX = re.compile(r"(?<![A-Za-z0-9_/.-])(?=[0-9a-fA-F]*\d)(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{32,39}(?![A-Za-z0-9_/.-])")


def redact(text):
    """Titkok es hozzaferesi azonositok kiszurese. Nem-szoveget valtozatlanul ad vissza."""
    if not isinstance(text, str):
        return text
    t = _RX_PRIVKEY.sub("<redacted-private-key>", text)
    t = _RX_JWT.sub("<redacted-jwt>", t)
    t = _RX_USERINFO.sub(lambda m: m.group(1) + "<redacted>@", t)
    t = _RX_AWSKEY.sub("<redacted-token>", t)
    t = _RX_BEARER.sub(lambda m: m.group(1) + " <redacted>", t)
    t = _RX_JSONKEY.sub(lambda m: m.group(1) + '"<redacted>"', t)
    t = _RX_PARAM.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", t)
    t = _RX_GAMECMD.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", t)
    t = _RX_LONG.sub("<redacted-token>", t)
    return _RX_HEX.sub("<redacted-token>", t)


def redact_obj(o):
    """redact() rekurzivan szotarra / listara / szovegre (a kulcsokat nem szuri)."""
    if isinstance(o, str):
        return redact(o)
    if isinstance(o, list):
        return [redact_obj(x) for x in o]
    if isinstance(o, dict):
        return {k: redact_obj(v) for k, v in o.items()}
    return o
