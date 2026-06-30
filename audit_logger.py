# ~/firewall-agent/audit_logger.py
from email_alert import send_alert
import sqlite3
import json
import requests
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "edr.db"
POLICY_SERVER = "http://localhost:8000"
AI_ENGINE_URL = "http://localhost:8001/analyze"

MITRE_TAGS = {
    "dns_blocked": {"tactic": "Command and Control", "technique": "T1071.004"},
    "ip_blocked": {"tactic": "Command and Control", "technique": "T1095"},
    "script_exec": {"tactic": "Execution", "technique": "T1059"},
    "canary_triggered": {"tactic": "Impact", "technique": "T1486"},
    "firewall_block": {"tactic": "Defense Evasion", "technique": "T1562.004"},
    "unknown": {"tactic": "Unknown", "technique": "T0000"},
}

def get_mitre_tag(event_type: str) -> dict:
    return MITRE_TAGS.get(event_type, MITRE_TAGS["unknown"])

def log_event(event_type: str, source_ip: str = "", details: dict = None, feature_id: int = None, severity: str = None, data: dict = None):
    """Log security event to SQLite + trigger AI if high severity."""
    if details is None:
        details = {}

    mitre = get_mitre_tag(event_type)
    severity = calculate_severity(event_type, details)
    timestamp = datetime.now(timezone.utc).isoformat()

    record = {
        "timestamp": timestamp,
        "event_type": event_type,
        "source_ip": source_ip,
        "mitre_tactic": mitre["tactic"],
        "mitre_technique": mitre["technique"],
        "severity": severity,
        "details": json.dumps(details),
    }

    _write_to_db(record)
    _send_alert_if_needed(severity, record)

    if severity >= 8:
        _trigger_ai_engine(event_type, source_ip, details)

def calculate_severity(event_type: str, details: dict) -> int:
    base_scores = {
        "canary_triggered": 10,
        "script_exec": 7,
        "dns_blocked": 5,
        "ip_blocked": 6,
        "firewall_block": 4,
    }
    score = base_scores.get(event_type, 3)

    # Boost score based on details
    if details.get("repeated"):
        score = min(10, score + 2)
    if details.get("known_malicious"):
        score = min(10, score + 3)

    return score

def _write_to_db(record: dict):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                source_ip TEXT,
                mitre_tactic TEXT,
                mitre_technique TEXT,
                severity INTEGER,
                details TEXT
            )
        """)
        cursor.execute("""
            INSERT INTO audit_log
            (timestamp, event_type, source_ip, mitre_tactic, mitre_technique, severity, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            record["timestamp"], record["event_type"], record["source_ip"],
            record["mitre_tactic"], record["mitre_technique"],
            record["severity"], record["details"]
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[AuditLogger] DB Error: {e}")

def _send_alert_if_needed(severity: int, record: dict):
    if severity >= 7:
        try:
            requests.post(
                f"{POLICY_SERVER}/alert",
                json=record,
                timeout=3
            )
        except Exception as e:
            print(f"[AuditLogger] Alert send failed: {e}")
        
        # Email alert
        send_alert(
            event_type=record["event_type"],
            severity=severity,
            source_ip=record["source_ip"],
            details=record["details"]
        )

def _trigger_ai_engine(event_type: str, source_ip: str, details: dict):
    try:
        payload = {
            "event_type": event_type,
            "source_ip": source_ip,
            "details": details,
        }
        resp = requests.post(AI_ENGINE_URL, json=payload, timeout=10)
        if resp.status_code == 200:
            print(f"[AuditLogger] AI Engine triggered successfully.")
        else:
            print(f"[AuditLogger] AI Engine returned: {resp.status_code}")
    except Exception as e:
        print(f"[AuditLogger] AI trigger failed: {e}")

# --- Test ---
if __name__ == "__main__":
    log_event("canary_triggered", source_ip="192.168.1.50", details={"file": "canary_doc.txt"})
    log_event("script_exec", source_ip="10.0.0.5", details={"script": "evil.ps1", "repeated": True})
    print("Events logged.")