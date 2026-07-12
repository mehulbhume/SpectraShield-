import hashlib
import json
import os
import time
from datetime import datetime

PROTECTED_FILES = [
    "protected_file.txt",
    "config.json"
]

BASELINE_FILE = "baseline_hashes.json"
LOG_FILE = "tamper_log.txt"

# Track files already reported as deleted
deleted_files = set()


def get_file_hash(filepath):
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def create_baseline():
    hashes = {}

    for file in PROTECTED_FILES:
        if os.path.exists(file):
            hashes[file] = get_file_hash(file)

    with open(BASELINE_FILE, "w") as f:
        json.dump(hashes, f, indent=4)

    print("Baseline Created")


def load_baseline():
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)


def save_baseline(baseline):
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)


def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log = f"[{timestamp}] {message}"

    print(log)

    with open(LOG_FILE, "a") as f:
        f.write(log + "\n")


# Create baseline if it doesn't exist
if not os.path.exists(BASELINE_FILE):
    create_baseline()

baseline = load_baseline()

print("Tamper Protection Started...")
print("----------------------------------------")

while True:

    for file in PROTECTED_FILES:

        # File deleted
        if not os.path.exists(file):

            if file not in deleted_files:
                log_event(f"TAMPER ALERT: {file} deleted!")
                deleted_files.add(file)

            continue

        # File restored
        if file in deleted_files:
            deleted_files.remove(file)

            current_hash = get_file_hash(file)
            baseline[file] = current_hash
            save_baseline(baseline)

            log_event(f"INFO: {file} restored and monitoring resumed.")

            continue

        current_hash = get_file_hash(file)

        # New file added to baseline
        if file not in baseline:
            baseline[file] = current_hash
            save_baseline(baseline)
            continue

        # File modified
        if current_hash != baseline[file]:

            log_event(f"TAMPER ALERT: {file} modified!")

            baseline[file] = current_hash
            save_baseline(baseline)

    time.sleep(5)
