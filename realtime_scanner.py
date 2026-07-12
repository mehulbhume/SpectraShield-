import hashlib
import json
import os
import shutil
import time
import yara

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

DATABASE_FILE = "malware_hashes.json"
QUARANTINE_FOLDER = "quarantine"
YARA_RULE_FILE = "yara_rules/malware_rule.yar"
WATCH_FOLDER = "sample_files"


def calculate_sha256(filepath):

    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:

        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


with open(DATABASE_FILE, "r") as f:
    database = json.load(f)

rules = yara.compile(filepath=YARA_RULE_FILE)

os.makedirs(QUARANTINE_FOLDER, exist_ok=True)


class AVHandler(FileSystemEventHandler):

    def on_created(self, event):

        if event.is_directory:
            return

        filepath = event.src_path

        print(f"\n[NEW FILE] {filepath}")

        try:

            file_hash = calculate_sha256(filepath)

            malware_detected = False
            detection_reason = ""

            # Hash Detection
            if file_hash in database:

                malware_detected = True
                detection_reason = database[file_hash]

            # YARA Detection
            matches = rules.match(filepath)

            if matches:

                malware_detected = True
                detection_reason = f"YARA Rule: {matches[0]}"

            if malware_detected:

                quarantine_path = os.path.join(
                    QUARANTINE_FOLDER,
                    os.path.basename(filepath)
                )

                shutil.move(filepath, quarantine_path)

                print(
                    f"[MALWARE DETECTED] "
                    f"{filepath} -> {detection_reason}"
                )

                print(
                    f"[QUARANTINED] "
                    f"{quarantine_path}"
                )

            else:

                print(f"[CLEAN] {filepath}")

        except Exception as e:

            print(f"[ERROR] {e}")


event_handler = AVHandler()

observer = Observer()

observer.schedule(
    event_handler,
    WATCH_FOLDER,
    recursive=True
)

observer.start()

print("===================================")
print("Next-Gen AV Real-Time Protection")
print(f"Monitoring: {WATCH_FOLDER}")
print("===================================")

try:

    while True:
        time.sleep(1)

except KeyboardInterrupt:

    observer.stop()

observer.join()