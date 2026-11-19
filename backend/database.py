"""SQLite layer: schema + small helpers."""
import sqlite3, json, os
DB_PATH = os.path.join(os.path.dirname(__file__), "soc.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, src_ip TEXT, dst_ip TEXT, src_port INTEGER,
 dst_port INTEGER, protocol TEXT, packets INTEGER, duration REAL, bytes REAL,
 prediction TEXT, confidence REAL, anomaly INTEGER, anomaly_score REAL, rule_hits TEXT,
 explanation TEXT, status TEXT, source TEXT, simulated INTEGER, ip_simulated INTEGER);
CREATE TABLE IF NOT EXISTS alerts(
 id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, ts TEXT, src_ip TEXT, dst_ip TEXT,
 category TEXT, confidence REAL, severity TEXT, explanation TEXT, rule_hits TEXT, incident_id INTEGER);
CREATE TABLE IF NOT EXISTS incidents(
 id INTEGER PRIMARY KEY AUTOINCREMENT, threat_name TEXT, src_ip TEXT, dst_ip TEXT, detected_at TEXT,
 severity TEXT, category TEXT, ml_prediction TEXT, confidence REAL, status TEXT DEFAULT 'Open',
 event_count INTEGER, evidence TEXT, response TEXT, mitre TEXT, intel TEXT, summary TEXT,
 risk_score REAL, blocked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS notes(
 id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER, author TEXT, text TEXT, created_at TEXT);
CREATE INDEX IF NOT EXISTS ix_ev_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS ix_al_inc ON alerts(incident_id);
"""

def conn():
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row; return c

def init_db():
    with conn() as c: c.executescript(SCHEMA)

def reset_db():
    with conn() as c:
        for t in ("events", "alerts", "incidents", "notes"): c.execute(f"DELETE FROM {t}")

def q(sql, args=()):
    with conn() as c: return [dict(r) for r in c.execute(sql, args).fetchall()]

def q1(sql, args=()):
    r = q(sql, args); return r[0] if r else None

def ex(sql, args=()):
    with conn() as c:
        cur = c.execute(sql, args); return cur.lastrowid

def jl(s, default=None):
    try: return json.loads(s) if s else default
    except Exception: return default

if __name__ == "__main__":
    init_db(); print("Database initialised at", DB_PATH)
