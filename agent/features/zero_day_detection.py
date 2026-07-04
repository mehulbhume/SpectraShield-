import platform
import os
import hashlib
import time

KNOWN_SAFE_HASHES = {
    "dummy_safe_hash"
}

def get_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def run(send_event):
    """
    F30: Zero-Day Detection (heuristic-based)
    """

    os_type = platform.system().lower()

    scan_path = "C:\\" if os_type == "windows" else "/tmp"

    try:
        while True:
            suspicious = []

            for root, dirs, files in os.walk(scan_path):
                for file in files:

                    if file.endswith((".exe", ".sh", ".bat")):
                        path = os.path.join(root, file)
                        file_hash = get_hash(path)

                        unknown = file_hash not in KNOWN_SAFE_HASHES
                        risky_path = any(x in path.lower() for x in ["temp", "downloads", "tmp"])

                        if unknown or risky_path:
                            suspicious.append({
                                "file": file,
                                "path": path,
                                "unknown_hash": unknown,
                                "risky_location": risky_path
                            })

            if suspicious:
                send_event(
                    "zero_day_detection",
                    30,
                    {
                        "count": len(suspicious),
                        "samples": suspicious[:3],
                        "os": os_type
                    },
                    "high"
                )

            time.sleep(15)

    except Exception:
        pass