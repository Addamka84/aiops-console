"""Demo-modell: Ollama-kompatibilis, DETERMINISZTIKUS ál-végpont (nincs modell, nincs hálózat). Csak a bemutatóhoz, hogy a konzol az AI-triázs
nélkül is végigmenjen az incidens-folyamaton. A válasz a bemenetből SZABÁLLYAL készül (a korrelátor gyökérok-hipotézisét fogalmazza át), nem
következtetés; minden szövegében szerepel, hogy demo-modell. Végpontok: GET /api/tags, POST /api/chat. Csak a standard könyvtár."""
import http.server
import json
import os
import re

MODEL = os.environ.get("MODEL", "qwen3.5:9b")
HYP = re.compile(r"Root-cause HYPOTHESIS[^:]*: (?P<root>.+?) \(it explains (?P<k>\d+) of (?P<n>\d+) affected items, confidence (?P<c>[0-9.]+)\)")
IMPACTED = re.compile(r"Potentially impacted items[^:]*: (?P<n>\d+)")


def answer(user):
    """A felhasználói szövegből (a konzol bemenete) az Ollama-séma szerinti válasz."""
    m = HYP.search(user or "")
    if not m:
        return {"summary": "Demo model: no incident context in this window, nothing to report.", "all_clear": True, "issues": []}
    root, k, n, c = m["root"].strip(), int(m["k"]), int(m["n"]), m["c"]
    imp = IMPACTED.search(user)
    sev = "critical" if float(c) >= 0.5 else "high"
    return {
        "summary": f"Demo model: one incident, likely origin {root}; {k} of {n} affected assets are explained by it.",
        "all_clear": False,
        "issues": [{
            "id": "", "title": f"{root} failure: {n} affected assets grouped into one incident", "severity": sev, "status": "new", "known_issue": False,
            "hosts": [root],
            "evidence": f"Topology correlation: {k} of {n} affected assets are explained by {root} (confidence {c})"
                        + (f"; about {imp['n']} downstream items potentially impacted" if imp else "") + ". [canned demo-model text, not a language-model inference]",
            "likely_cause": f"{root} is unreachable or down; the dependent assets alert because they need it. (Rule-based wording of the correlator's hypothesis.)",
            "cause_quote": "",
            "suggested_action": f"Check {root} first (power, uplink, hypervisor/switch console); the dependent alerts should clear when it recovers.",
        }],
    }


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, obj):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.startswith("/api/tags"):
            return self._send(200, {"models": [{"name": MODEL}]})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        if self.path.startswith("/api/chat"):
            msgs = body.get("messages") or []
            user = next((m.get("content", "") for m in reversed(msgs) if m.get("role") == "user"), "")
            return self._send(200, {"model": MODEL, "done": True, "done_reason": "stop", "prompt_eval_count": len(user) // 4, "eval_count": 120,
                                    "message": {"role": "assistant", "content": json.dumps(answer(user))}})
        self._send(404, {"error": "not found"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "11434"))), Handler).serve_forever()
