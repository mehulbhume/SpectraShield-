import time
import os
import requests
from audit_logger import log_event

SUSPICIOUS_KEYWORDS = [
    "base64", "wget", "curl", "Invoke-WebRequest",
    "DownloadFile", "DownloadString", "IEX", "Invoke-Expression",
    "nc.exe", "ncat", "python -c", "perl -e",
    "powershell -enc", "-ExecutionPolicy Bypass",
    "rm -rf", "format c:", "del /f /s",
    "net user", "net localgroup administrators",
]

HISTORY_FILE = os.path.expandvars(
    r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
)
BACKEND_URL = "http://127.0.0.1:8000/events"
MAX_RETRIES = 5
RETRY_BASE  = 2

def get_recent_commands(n=20):
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [l.strip() for l in lines[-n:] if l.strip()]
    except FileNotFoundError:
        print(f"[!] History file not found: {HISTORY_FILE}")
        return []
    except Exception as e:
        print(f"[!] Error reading history: {e}")
        return []

def check_suspicious(commands):
    flagged = []
    for cmd in commands:
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in cmd.lower():
                flagged.append({
                    "command": cmd,
                    "matched_keyword": keyword
                })
                break
    return flagged

def send_with_retry(entry: dict):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.post(BACKEND_URL, json=entry, timeout=5)
            r.raise_for_status()
            return True
        except Exception as e:
            wait = RETRY_BASE ** attempt
            print(f"[!] Attempt {attempt}/{MAX_RETRIES} failed: {e}")
            if attempt < MAX_RETRIES:
                print(f"[*] Retry in {wait}s...")
                time.sleep(wait)
    print(f"[!!!] All {MAX_RETRIES} attempts failed!")
    return False

def monitor_scripts(interval=10):
    print("[*] Script Execution Monitor started (Windows mode)...")
    print(f"[*] Watching: {HISTORY_FILE}")
    last_seen = set()

    while True:
        commands = get_recent_commands(20)
        new_commands = [c for c in commands if c not in last_seen]

        if new_commands:
            flagged = check_suspicious(new_commands)

            if flagged:
                print(f"[!!!] SUSPICIOUS COMMANDS DETECTED: {len(flagged)}")
                for f in flagged:
                    print(f"    → {f['command']} (keyword: {f['matched_keyword']})")
                log_event(
                    event_type="suspicious_script_detected",
                    feature_id=24,
                    severity="critical",
                    data={"flagged_commands": flagged, "count": len(flagged)}
                )
            else:
                print(f"[=] {len(new_commands)} new commands — clean")

            last_seen.update(new_commands)

        time.sleep(interval)

if __name__ == "__main__":
    monitor_scripts()