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
                CREATE TABLE IF NOT EXISTS nov_patterns (
                    key TEXT PRIMARY KEY, source TEXT NOT NULL, host TEXT NOT NULL, ident TEXT NOT NULL, level TEXT NOT NULL,
                    tmpl TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, total INTEGER NOT NULL,
                    since TEXT NOT NULL, last_spike TEXT NOT NULL DEFAULT '');
                CREATE INDEX IF NOT EXISTS nov_patterns_seen ON nov_patterns (last_seen);
                CREATE TABLE IF NOT EXISTS nov_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,
                    source TEXT NOT NULL, host TEXT NOT NULL, ident TEXT NOT NULL, level TEXT NOT NULL, tmpl TEXT NOT NULL,
                    hits INTEGER NOT NULL, baseline REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'open');
                CREATE INDEX IF NOT EXISTS nov_findings_ts ON nov_findings (ts);
                CREATE TABLE IF NOT EXISTS nov_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
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

    # ---- ujdonsag-eszleles (novelty.py): minta-alapvonal, leletek, allapot. A konfig-verziozashoz nem tartozik.
    def nov_meta(self, k, default=""):
        with self.lock:
            r = self.db.execute("SELECT v FROM nov_meta WHERE k=?", (k,)).fetchone()
        return r["v"] if r else default

    def nov_set_meta(self, k, v):
        with self.lock:
            self.db.execute("INSERT INTO nov_meta (k, v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))
            self.db.commit()

    def nov_patterns(self, keys):
        """kulcs -> sor (dict); egy lekerdezesben (a kulcsok szama nagy lehet, ezert darabolva)."""
        out = {}
        keys = list(keys)
        with self.lock:
            for i in range(0, len(keys), 500):
                part = keys[i:i + 500]
                q = "SELECT * FROM nov_patterns WHERE key IN (%s)" % ",".join("?" * len(part))
                for r in self.db.execute(q, part).fetchall():
                    out[r["key"]] = dict(r)
        return out

    def nov_upsert(self, rows):
        """rows: dict-ek (key, source, host, ident, level, tmpl, first_seen, last_seen, total, since, last_spike).
        Letezo kulcsnal: az elso latas a kisebb, az utolso a nagyobb, az osszeg novekszik, a tobbi mezo marad."""
        with self.lock:
            self.db.executemany("""
                INSERT INTO nov_patterns (key, source, host, ident, level, tmpl, first_seen, last_seen, total, since, last_spike)
                VALUES (:key,:source,:host,:ident,:level,:tmpl,:first_seen,:last_seen,:total,:since,:last_spike)
                ON CONFLICT(key) DO UPDATE SET
                    first_seen = MIN(first_seen, excluded.first_seen), last_seen = MAX(last_seen, excluded.last_seen),
                    total = total + excluded.total, host = excluded.host, level = excluded.level,
                    since = MIN(since, excluded.since),
                    last_spike = CASE WHEN excluded.last_spike > last_spike THEN excluded.last_spike ELSE last_spike END
            """, rows)
            self.db.commit()

    def nov_rekey(self, fn):
        """Az osszes minta ujrakulcsolasa: fn(sor) -> (uj_kulcs, uj_sablon). Az azonos uj kulcsra eso sorok osszevonodnak
        (osszeg, legkorabbi/legkesobbi latas). Egy tranzakcio: hiba eseten semmi sem valtozik. -> (elotte, utana)"""
        with self.lock:
            rows = [dict(r) for r in self.db.execute("SELECT * FROM nov_patterns").fetchall()]
            merged = {}
            for r in rows:
                key, tmpl = fn(r)
                m = merged.get(key)
                if m is None:
                    merged[key] = dict(r, key=key, tmpl=tmpl)
                    continue
                newer = r["last_seen"] > m["last_seen"]
                m.update(total=m["total"] + r["total"], first_seen=min(m["first_seen"], r["first_seen"]),
                         last_seen=max(m["last_seen"], r["last_seen"]), since=min(m["since"], r["since"]),
                         last_spike=max(m["last_spike"], r["last_spike"]))
                if newer:
                    m.update(host=r["host"], level=r["level"])
            try:
                self.db.execute("BEGIN")
                self.db.execute("DELETE FROM nov_patterns")
                self.db.executemany("""INSERT INTO nov_patterns (key, source, host, ident, level, tmpl, first_seen, last_seen, total, since, last_spike)
                                       VALUES (:key,:source,:host,:ident,:level,:tmpl,:first_seen,:last_seen,:total,:since,:last_spike)""",
                                    list(merged.values()))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
        return len(rows), len(merged)

    def nov_add_findings(self, items):
        with self.lock:
            self.db.executemany("""INSERT INTO nov_findings (ts, kind, key, source, host, ident, level, tmpl, hits, baseline)
                                   VALUES (:ts,:kind,:key,:source,:host,:ident,:level,:tmpl,:hits,:baseline)""", items)
            self.db.commit()

    def nov_findings(self, status="open", since=None, limit=100):
        q, args = "SELECT * FROM nov_findings WHERE 1=1", []
        if status:
            q += " AND status=?"
            args.append(status)
        if since:
            q += " AND ts>=?"
            args.append(since)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self.lock:
            return [dict(r) for r in self.db.execute(q, args).fetchall()]

    def nov_dismiss(self, fid=None, actor="system"):
        """Egy lelet (vagy mind) elintezettre allitasa. -> az erintett sorok szama"""
        with self.lock:
            if fid is None:
                cur = self.db.execute("UPDATE nov_findings SET status='dismissed' WHERE status='open'")
            else:
                cur = self.db.execute("UPDATE nov_findings SET status='dismissed' WHERE id=? AND status='open'", (fid,))
            self._audit(actor, "novelty.dismiss", "all" if fid is None else f"finding {fid}")
            self.db.commit()
            return cur.rowcount

    def nov_counts(self):
        with self.lock:
            p = self.db.execute("SELECT COUNT(*) AS n FROM nov_patterns").fetchone()["n"]
            o = self.db.execute("SELECT COUNT(*) AS n FROM nov_findings WHERE status='open'").fetchone()["n"]
        return {"patterns": p, "open_findings": o}

    def nov_prune(self, keep_since_iso, max_patterns=100000, findings_keep_iso=None, max_findings=500):
        with self.lock:
            self.db.execute("DELETE FROM nov_patterns WHERE last_seen < ?", (keep_since_iso,))
            self.db.execute("""DELETE FROM nov_patterns WHERE key IN
                               (SELECT key FROM nov_patterns ORDER BY last_seen DESC LIMIT -1 OFFSET ?)""", (max_patterns,))
            if findings_keep_iso:
                self.db.execute("DELETE FROM nov_findings WHERE ts < ?", (findings_keep_iso,))
            self.db.execute("""DELETE FROM nov_findings WHERE id NOT IN
                               (SELECT id FROM nov_findings ORDER BY id DESC LIMIT ?)""", (max_findings,))
            self.db.commit()

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
