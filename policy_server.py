from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import sqlite3
import json
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "edr_database.db"

# ── Database setup ──────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Firewall rules table
    c.execute('''CREATE TABLE IF NOT EXISTS firewall_rules (
        id TEXT PRIMARY KEY,
        direction TEXT,
        protocol TEXT,
        port INTEGER,
        src_ip TEXT,
        dst_ip TEXT,
        action TEXT,
        priority INTEGER
    )''')

    # Events table
    c.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id TEXT,
        hostname TEXT,
        os TEXT,
        timestamp TEXT,
        event_type TEXT,
        feature_id INTEGER,
        severity TEXT,
        mitre_id TEXT,
        mitre_technique TEXT,
        data TEXT
    )''')

    # Blocked domains table
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_domains (
        domain TEXT PRIMARY KEY,
        added_at TEXT
    )''')

    conn.commit()
    conn.close()
    print("[+] Database initialized!")

init_db()

# ── Models ───────────────────────────────────────────────────
class FirewallRule(BaseModel):
    id: str
    direction: str
    protocol: str
    port: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    action: str
    priority: int

class SecurityEvent(BaseModel):
    host_id: str
    hostname: str
    os: str
    timestamp: str
    event_type: str
    feature_id: int
    severity: str
    mitre_id: Optional[str] = "T0000"
    mitre_technique: Optional[str] = "Unknown"
    data: dict

class BlockedDomain(BaseModel):
    domain: str

# ── Firewall Rules ───────────────────────────────────────────
@app.get("/rules")
def get_rules():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM firewall_rules ORDER BY priority")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "direction": r[1], "protocol": r[2],
             "port": r[3], "src_ip": r[4], "dst_ip": r[5],
             "action": r[6], "priority": r[7]} for r in rows]

@app.post("/rules")
def add_rule(rule: FirewallRule):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO firewall_rules VALUES (?,?,?,?,?,?,?,?)",
              (rule.id, rule.direction, rule.protocol, rule.port,
               rule.src_ip, rule.dst_ip, rule.action, rule.priority))
    conn.commit()
    conn.close()
    return {"status": "added", "rule_id": rule.id}

@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM firewall_rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()
    return {"status": "deleted"}

# ── Events ───────────────────────────────────────────────────
@app.post("/events")
def receive_event(event: SecurityEvent):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""INSERT INTO events
        (host_id, hostname, os, timestamp, event_type, feature_id,
         severity, mitre_id, mitre_technique, data)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (event.host_id, event.hostname, event.os, event.timestamp,
         event.event_type, event.feature_id, event.severity,
         event.mitre_id, event.mitre_technique, json.dumps(event.data)))
    conn.commit()
    conn.close()
    print(f"[EVENT] {event.event_type} | {event.hostname} | severity={event.severity}")
    return {"status": "received"}

@app.get("/events")
def get_events():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "host_id": r[1], "hostname": r[2], "os": r[3],
             "timestamp": r[4], "event_type": r[5], "feature_id": r[6],
             "severity": r[7], "mitre_id": r[8], "mitre_technique": r[9],
             "data": json.loads(r[10])} for r in rows]

# ── Blocked Domains ──────────────────────────────────────────
@app.get("/blocked-domains")
def get_blocked_domains():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT domain FROM blocked_domains")
    rows = c.fetchall()
    conn.close()
    return [r[0] for r in rows]

@app.post("/blocked-domains")
def add_blocked_domain(item: BlockedDomain):
    from datetime import datetime
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO blocked_domains VALUES (?,?)",
              (item.domain, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"status": "added", "domain": item.domain}

@app.delete("/blocked-domains/{domain}")
def delete_blocked_domain(domain: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM blocked_domains WHERE domain=?", (domain,))
    conn.commit()
    conn.close()
    return {"status": "deleted", "domain": domain}

# ── Heartbeat ────────────────────────────────────────────────
@app.post("/heartbeat")
def heartbeat(data: dict):
    print(f"[♥] Heartbeat: {data.get('hostname')} | {data.get('timestamp')}")
    return {"status": "alive"}

@app.get("/health")
def health():
    return {"status": "ok", "database": DB_FILE}
    
@app.post("/alert")
def receive_alert(data: dict):
    print(f"[ALERT] {data.get('event_type')} | severity={data.get('severity')}")
    return {"status": "alert received"}
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "policy_server:app",
        host="127.0.0.1",
        port=8000,
        reload=False
    )
