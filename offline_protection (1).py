import os
import hashlib
import json
from datetime import datetime

# Simple local threat signature DB (offline)
KNOWN_MALICIOUS_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": "EmptyFile_Suspicious",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR_Test_Malware",
}

def hash_file(filepath):
    md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
        return md5.hexdigest()
    except (IOError, PermissionError):
        return None

def scan_directory(directory="."):
    print(f"[*] Offline scan started: {directory} at {datetime.now()}\n")
    threats = []
    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            fhash = hash_file(fpath)
            if fhash and fhash in KNOWN_MALICIOUS_HASHES:
                threat_name = KNOWN_MALICIOUS_HASHES[fhash]
                threats.append({"file": fpath, "hash": fhash, "threat": threat_name})
                print(f"  [!] THREAT DETECTED: {fpath} -> {threat_name}")
            else:
                print(f"  [OK] {fpath}")
    print(f"\n[*] Scan complete. Threats found: {len(threats)}")
    return threats

if __name__ == "__main__":
    scan_directory(".")
