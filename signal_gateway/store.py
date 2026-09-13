import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def init(self):
        with self.connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS rules (
              id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
              priority INTEGER NOT NULL DEFAULT 100, match_mode TEXT NOT NULL DEFAULT 'all',
              conditions TEXT NOT NULL DEFAULT '[]', title_template TEXT NOT NULL,
              message_template TEXT NOT NULL, html INTEGER NOT NULL DEFAULT 1,
              pushover_priority INTEGER NOT NULL DEFAULT 0, sound TEXT NOT NULL DEFAULT 'pushover',
              stop_processing INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL, payload TEXT NOT NULL,
              variables TEXT NOT NULL, matched_rules TEXT NOT NULL, status TEXT NOT NULL);
            """)

    def settings(self):
        with self.connect() as db:
            return {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM settings")}

    def set_settings(self, values):
        with self.connect() as db:
            db.executemany("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", values.items())

    def rules(self):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM rules ORDER BY priority,id").fetchall()
        result=[]
        for row in rows:
            item=dict(row); item["conditions"]=json.loads(item["conditions"]); item["enabled"]=bool(item["enabled"]); item["html"]=bool(item["html"]); item["stop_processing"]=bool(item["stop_processing"]); result.append(item)
        return result

    def save_rule(self, item):
        fields=(item["name"],int(item.get("enabled",0)),int(item.get("priority",100)),item.get("match_mode","all"),json.dumps(item.get("conditions",[])),item.get("title_template",""),item.get("message_template",""),int(item.get("html",0)),int(item.get("pushover_priority",0)),item.get("sound","pushover"),int(item.get("stop_processing",0)))
        with self.connect() as db:
            if item.get("id"):
                db.execute("UPDATE rules SET name=?,enabled=?,priority=?,match_mode=?,conditions=?,title_template=?,message_template=?,html=?,pushover_priority=?,sound=?,stop_processing=? WHERE id=?",fields+(int(item["id"]),))
            else:
                db.execute("INSERT INTO rules(name,enabled,priority,match_mode,conditions,title_template,message_template,html,pushover_priority,sound,stop_processing) VALUES(?,?,?,?,?,?,?,?,?,?,?)",fields)

    def delete_rule(self, rule_id):
        with self.connect() as db: db.execute("DELETE FROM rules WHERE id=?",(rule_id,))

    def record(self,payload,variables,matches,status):
        with self.connect() as db:
            db.execute("INSERT INTO events(received_at,payload,variables,matched_rules,status) VALUES(?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),json.dumps(payload),json.dumps(variables),json.dumps(matches),status))

    def recent(self,limit=20):
        with self.connect() as db: return [dict(r) for r in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?",(limit,))]

