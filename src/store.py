"""Konfig-tar (SQLite): verziozott dokumentumok, javaslatok, auditnaplo.

Dokumentumkulcsok: 'known' (zaj + ismert ugyek + labor-tenyek), 'settings' (felulirasok).
Minden iras uj verzio (a regi megmarad, visszaallithato). Titkok SOHA nem kerulnek ide.
"""
import json
import sqlite3
import threading
import time

KEEP_REVISIONS = 200


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class StoreError(Exception):
    pass


class Store:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS config_rev (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, ts TEXT NOT NULL,
                    author TEXT NOT NULL, comment TEXT NOT NULL, content TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS config_rev_key ON config_rev (key, id);
                CREATE TABLE IF NOT EXISTS proposals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, author TEXT NOT NULL, key TEXT NOT NULL,
                    base_rev INTEGER NOT NULL, content TEXT NOT NULL, comment TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending', decided_ts TEXT, decided_by TEXT);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
                    action TEXT NOT NULL, detail TEXT NOT NULL);
            """)
            self.db.commit()

    # ---- konfig-verziok
    @staticmethod
    def _rev(row, with_content=True):
        d = {"id": row["id"], "key": row["key"], "ts": row["ts"], "author": row["author"], "comment": row["comment"]}
        if with_content:
            d["content"] = json.loads(row["content"])
        return d

    def revision_id(self, key):
        """Az aktualis verzio azonositoja (0 = nincs); olcso, a hatterszal ezzel figyeli a valtozast."""
        with self.lock:
            r = self.db.execute("SELECT MAX(id) AS m FROM config_rev WHERE key=?", (key,)).fetchone()
        return r["m"] or 0

    def current(self, key):
        with self.lock:
            r = self.db.execute("SELECT * FROM config_rev WHERE key=? ORDER BY id DESC LIMIT 1", (key,)).fetchone()
        return self._rev(r) if r else None

    def put(self, key, content, author, comment=""):
        with self.lock:
            cur = self.db.execute("INSERT INTO config_rev (key, ts, author, comment, content) VALUES (?,?,?,?,?)",
                                  (key, now_iso(), author, comment[:300], json.dumps(content, ensure_ascii=False, sort_keys=True)))
            rid = cur.lastrowid
            self.db.execute("""DELETE FROM config_rev WHERE key=? AND id NOT IN
                               (SELECT id FROM config_rev WHERE key=? ORDER BY id DESC LIMIT ?)""", (key, key, KEEP_REVISIONS))
            self._audit(author, f"config.put.{key}", f"rev {rid}: {comment[:120]}")
            self.db.commit()
        return rid

    def revisions(self, key, limit=50):
        with self.lock:
            rows = self.db.execute("SELECT * FROM config_rev WHERE key=? ORDER BY id DESC LIMIT ?", (key, limit)).fetchall()
        return [self._rev(r, with_content=False) for r in rows]

    def revision(self, key, rid):
        with self.lock:
            r = self.db.execute("SELECT * FROM config_rev WHERE key=? AND id=?", (key, rid)).fetchone()
        if not r:
            raise StoreError(f"no such revision: {key}/{rid}")
        return self._rev(r)

    def rollback(self, key, rid, author):
        old = self.revision(key, rid)
        return self.put(key, old["content"], author, f"rollback to rev {rid}")

    # ---- javaslatok (a felhasznalo hagyja jova)
    @staticmethod
    def _prop(row):
        d = {k: row[k] for k in ("id", "ts", "author", "key", "base_rev", "comment", "status", "decided_ts", "decided_by")}
        d["content"] = json.loads(row["content"])
        return d

    def add_proposal(self, key, content, author, comment, base_rev):
        with self.lock:
            cur = self.db.execute("INSERT INTO proposals (ts, author, key, base_rev, content, comment) VALUES (?,?,?,?,?,?)",
                                  (now_iso(), author, key, base_rev, json.dumps(content, ensure_ascii=False, sort_keys=True), comment[:300]))
            self._audit(author, f"proposal.add.{key}", f"proposal {cur.lastrowid}: {comment[:120]}")
            self.db.commit()
            return cur.lastrowid

    def proposals(self, status=None, limit=50):
        with self.lock:
            if status:
                rows = self.db.execute("SELECT * FROM proposals WHERE status=? ORDER BY id DESC LIMIT ?", (status, limit)).fetchall()
            else:
                rows = self.db.execute("SELECT * FROM proposals ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._prop(r) for r in rows]

    def proposal(self, pid):
        with self.lock:
            r = self.db.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone()
        if not r:
            raise StoreError(f"no such proposal: {pid}")
        return self._prop(r)

    def decide(self, pid, approve, actor, force=False):
        """Elfogad (-> uj konfig-verzio) vagy elutasit. Elavult javaslat (kozben valtozott a konfig) csak force-szal fogadhato el."""
        with self.lock:
            p = self.proposal(pid)
            if p["status"] != "pending":
                raise StoreError(f"proposal {pid} is already {p['status']}")
            rid = None
            if approve:
                if self.revision_id(p["key"]) != p["base_rev"] and not force:
                    raise StoreError("stale: the configuration changed since this proposal was made (use force to apply anyway)")
                rid = self.put(p["key"], p["content"], f"{p['author']} (approved by {actor})", f"proposal {pid}: {p['comment']}")
            self.db.execute("UPDATE proposals SET status=?, decided_ts=?, decided_by=? WHERE id=?",
                            ("approved" if approve else "rejected", now_iso(), actor, pid))
            self._audit(actor, f"proposal.{'approve' if approve else 'reject'}", f"proposal {pid}")
            self.db.commit()
        return rid

    # ---- audit
    def _audit(self, actor, action, detail):
        self.db.execute("INSERT INTO audit (ts, actor, action, detail) VALUES (?,?,?,?)", (now_iso(), actor, action, detail))
        self.db.execute("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 2000)")

    def audit(self, actor, action, detail=""):
        with self.lock:
            self._audit(actor, action, detail)
            self.db.commit()

    def audit_list(self, limit=100):
        with self.lock:
            rows = self.db.execute("SELECT ts, actor, action, detail FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
