# ==========================================================
# FEATURE NAME : Pre-Execution Prevention
# FEATURE ID : 12
# INTERN ID : 2128
# ==========================================================

import hashlib
import time
import platform

if platform.system() == "Windows":
    import wmi

BLOCKED_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb924"
}


def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except Exception:
        return None


def run(send_event):

    try:

        if platform.system() == "Windows":

            c = wmi.WMI()

            process_watcher = c.Win32_Process.watch_for("creation")

            while True:

                try:

                    new_process = process_watcher()

                    process_name = new_process.Caption
                    process_path = new_process.ExecutablePath

                    if not process_path:
                        continue

                    if not process_path.lower().endswith(".exe"):
                        continue

                    file_hash = calculate_sha256(process_path)

                    if not file_hash:
                        continue

                    blocked = file_hash in BLOCKED_HASHES

                    data = {
                        "file": process_name,
                        "path": process_path,
                        "hash": file_hash,
                        "blocked": blocked,
                        "reason": "known malware hash" if blocked else "clean"
                    }

                    if send_event:

                        send_event(
                            event_type="pre_execution_prevention",
                            feature_id=12,
                            data=data,
                            severity="critical" if blocked else "info"
                        )

                    print(f"[F12] Checked: {process_name}")

                except Exception as e:
                    print(f"[F12 ERROR] {e}")

                time.sleep(1)

        else:
            print("[F12] Windows only feature")

    except Exception as e:
        print(f"[F12 FATAL ERROR] {e}")