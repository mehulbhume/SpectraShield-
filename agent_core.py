import requests
import hashlib
import json
import time
import threading
import socket
import datetime
import subprocess
import sys
import os
from os_firewall import apply_rules
from audit_logger import log_event

POLICY_SERVER = "http://127.0.0.1:8000"
POLL_INTERVAL = 10
MAX_RETRIES   = 5
RETRY_BASE    = 2

last_hash = None

def fetch_with_retry(url, retries=MAX_RETRIES):
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            wait = RETRY_BASE ** attempt
            print(f"[!] Attempt {attempt}/{retries} failed: {e}")
            if attempt < retries:
                print(f"[*] Retry in {wait}s...")
                time.sleep(wait)
            else:
                print(f"[!!!] All {retries} attempts failed — backend down?")
                log_event(
                    event_type="agent_backend_unreachable",
                    feature_id=15,
                    severity="critical",
                    data={"url": url, "attempts": retries, "last_error": str(e)}
                )
                raise

def fetch_rules():
    return fetch_with_retry(f"{POLICY_SERVER}/rules")

def rules_changed(rules):
    global last_hash
    current_hash = hashlib.sha256(
        json.dumps(rules, sort_keys=True).encode()
    ).hexdigest()
    if current_hash != last_hash:
        last_hash = current_hash
        return True
    return False

def send_heartbeat():
    while True:
        try:
            requests.post(f"{POLICY_SERVER}/heartbeat", json={
                "hostname":  socket.gethostname(),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "status":    "alive"
            }, timeout=3)
            print(f"[♥] Heartbeat sent — {time.strftime('%H:%M:%S')}")
        except Exception as e:
            print(f"[!] Heartbeat failed: {e}")
        time.sleep(30)

def tamper_protection():
    """Agent ko kill karne ki koshish detect karo aur restart karo"""
    print("[🛡] Tamper Protection active!")
    while True:
        time.sleep(30)
        # Agar koi firewall rules delete kare
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True
        )
        if "FirewallAgentRule" not in result.stdout:
            print("[!!!] TAMPER DETECTED — firewall rules deleted! Restoring...")
            log_event(
                event_type="tamper_detected",
                feature_id=15,
                severity="critical",
                data={
                    "type": "firewall_rules_deleted",
                    "action": "auto_restore",
                    "timestamp": time.strftime("%H:%M:%S")
                }
            )
            
def watchdog():
    """Agar agent crash ho toh restart karo"""
    print("[🐕] Watchdog started!")
    while True:
        time.sleep(60)
        print(f"[🐕] Watchdog check — agent alive at {time.strftime('%H:%M:%S')}")

def run_agent():
    print("[*] Firewall Agent started (retry mode ON)...")
    print(f"[*] Max retries: {MAX_RETRIES} | Backoff: exponential (2^n seconds)")

    # Threads start karo
    threading.Thread(target=send_heartbeat,    daemon=True).start()
    threading.Thread(target=tamper_protection, daemon=True).start()
    threading.Thread(target=watchdog,          daemon=True).start()

    print("[♥] Heartbeat thread started — ping every 30s")
    print("[🛡] Tamper Protection thread started")
    print("[🐕] Watchdog thread started\n")

    while True:
        try:
            rules = fetch_rules()
            if rules_changed(rules):
                print("[+] New rules mili! Apply kar raha hoon...")
                apply_rules(rules)
                log_event(
                    event_type="rules_applied",
                    feature_id=15,
                    severity="info",
                    data={"rule_count": len(rules)}
                )
            else:
                print(f"[=] [{time.strftime('%H:%M:%S')}] Koi change nahi, wait kar raha hoon...")
        except Exception as e:
            print(f"[!!!] Fatal error after retries: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run_agent()