import os
import time
import hashlib
import requests
from audit_logger import log_event

CANARY_DIR   = os.path.expanduser("~/firewall-agent/canary_files")
BACKEND_URL  = "http://127.0.0.1:8000/events"
MAX_RETRIES  = 5
RETRY_BASE   = 2

CANARY_FILES = [
    "important_document.docx",
    "passwords.txt",
    "financial_report.xlsx",
    "backup_keys.pem",
    "secret_data.csv"
]

def get_file_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None

def create_canary_files():
    os.makedirs(CANARY_DIR, exist_ok=True)
    for filename in CANARY_FILES:
        filepath = os.path.join(CANARY_DIR, filename)
        if not os.path.exists(filepath):
            with open(filepath, "w") as f:
                f.write(f"CANARY FILE - {filename} - DO NOT MODIFY")
    print(f"[+] {len(CANARY_FILES)} canary files created in {CANARY_DIR}")

def get_all_hashes():
    hashes = {}
    for filename in CANARY_FILES:
        filepath = os.path.join(CANARY_DIR, filename)
        hashes[filename] = get_file_hash(filepath)
    return hashes

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
    print(f"[!!!] All {MAX_RETRIES} attempts failed — backend down?")
    return False

def monitor_canary(interval=5):
    print("[*] Ransomware Canary Monitor started (retry mode ON)...")
    create_canary_files()

    baseline = get_all_hashes()
    print(f"[+] Baseline hashes recorded for {len(baseline)} files")
    check_num = 0

    while True:
        time.sleep(interval)
        check_num += 1
        current  = get_all_hashes()
        all_safe = True

        for filename in CANARY_FILES:
            filepath = os.path.join(CANARY_DIR, filename)

            if current[filename] is None and baseline[filename] is not None:
                all_safe = False
                print(f"[!!!] RANSOMWARE ALERT — File DELETED: {filename}")
                log_event(
                    event_type="ransomware_canary_triggered",
                    feature_id=32,
                    severity="critical",
                    data={
                        "file":      filename,
                        "trigger":   "file_deleted",
                        "path":      filepath,
                        "timestamp": time.strftime("%H:%M:%S")
                    }
                )

            elif current[filename] != baseline[filename]:
                all_safe = False
                print(f"[!!!] RANSOMWARE ALERT — File MODIFIED: {filename}")
                log_event(
                    event_type="ransomware_canary_triggered",
                    feature_id=32,
                    severity="critical",
                    data={
                        "file":      filename,
                        "trigger":   "file_modified",
                        "old_hash":  baseline[filename],
                        "new_hash":  current[filename],
                        "path":      filepath,
                        "timestamp": time.strftime("%H:%M:%S")
                    }
                )

        if all_safe:
            print(f"[✓] [{time.strftime('%H:%M:%S')}] Check #{check_num} — all {len(CANARY_FILES)} files safe")

        baseline = current

if __name__ == "__main__":
    monitor_canary()