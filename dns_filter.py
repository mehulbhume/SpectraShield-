import time
import subprocess
import requests

from audit_logger import log_event

# ===========================
# Configuration
# ===========================

HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"

MARKER_START = "# EDR-DNS-BLOCK-START"
MARKER_END = "# EDR-DNS-BLOCK-END"

BACKEND_URL = "http://127.0.0.1:8000"

MAX_RETRIES = 5
RETRY_BASE = 2


# ===========================
# Backend Communication
# ===========================

def fetch_domains_with_retry():
    """
    Fetch blocked domains from policy server.
    Retries automatically if backend is temporarily unavailable.
    """

    for attempt in range(1, MAX_RETRIES + 1):

        try:

            response = requests.get(
                f"{BACKEND_URL}/blocked-domains",
                timeout=5
            )

            response.raise_for_status()

            domains = response.json()

            if not isinstance(domains, list):
                print("[!] Backend returned invalid response.")
                return []

            return domains

        except Exception as e:

            wait = RETRY_BASE ** attempt

            print(
                f"[!] Backend connection failed "
                f"({attempt}/{MAX_RETRIES})"
            )

            print(e)

            if attempt < MAX_RETRIES:

                print(f"[*] Retrying in {wait} seconds...\n")

                time.sleep(wait)

    print("[!!!] Backend unavailable.\n")

    return []


# ===========================
# Hosts File Cleanup
# ===========================

def remove_old_entries():

    try:

        with open(HOSTS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        cleaned = []

        inside_block = False

        for line in lines:

            if MARKER_START in line:
                inside_block = True
                continue

            if MARKER_END in line:
                inside_block = False
                continue

            if not inside_block:
                cleaned.append(line)

        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            f.writelines(cleaned)

        print("[+] Old EDR entries removed.")

    except FileNotFoundError:

        print("[!] Hosts file not found.")

    except PermissionError:

        print("[!] Run VS Code as Administrator.")

    except Exception as e:

        print(f"[!] Cleanup failed: {e}")

# ===========================
# Apply DNS Block
# ===========================

def apply_dns_block(domains):

    remove_old_entries()

    if not domains:
        print("[*] No domains to block.")
        return

    entries = "\n" + MARKER_START + "\n"

    unique_domains = sorted(set(domains))

    for domain in unique_domains:

        clean = (
            domain.replace("https://", "")
                  .replace("http://", "")
                  .split("/")[0]
                  .split("?")[0]
                  .strip()
                  .lower()
        )

        if not clean:
            continue

        entries += f"127.0.0.1 {clean}\n"
        entries += f"127.0.0.1 www.{clean}\n"

    entries += MARKER_END + "\n"

    print("\n========== HOSTS UPDATE ==========")
    print(entries)
    print("==================================\n")

    try:

        with open(HOSTS_FILE, "a", encoding="utf-8") as f:
            f.write(entries)

        print(f"[+] {len(unique_domains)} domain(s) blocked.")

        subprocess.run(
            ["ipconfig", "/flushdns"],
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        print("[+] DNS cache flushed.")

        try:
            log_event(
                event_type="dns_blocked",
                feature_id=16,
                severity="high",
                data={
                    "blocked_domains": unique_domains,
                    "count": len(unique_domains),
                    "method": "hosts_file_windows"
                }
            )
        except Exception as e:
            print(f"[!] Audit log failed: {e}")

    except PermissionError:
        print("[!!!] Permission denied. Run VS Code as Administrator.")

    except Exception as e:
        print(f"[!!!] DNS block failed: {e}")


# ===========================
# Monitor Backend
# ===========================

def monitor_dns(interval=5):

    print("=" * 50)
    print("EDR DNS FILTER STARTED")
    print("=" * 50)

    print(f"Hosts File : {HOSTS_FILE}")
    print(f"Backend    : {BACKEND_URL}")
    print(f"Interval   : {interval} sec")
    print()

    last_domains = []

    while True:

        try:

            domains = fetch_domains_with_retry()

            if sorted(domains) != sorted(last_domains):

                print(
                    f"[{time.strftime('%H:%M:%S')}] "
                    "Domain list changed."
                )

                apply_dns_block(domains)

                last_domains = list(domains)

            else:

                print(
                    f"[{time.strftime('%H:%M:%S')}] "
                    f"No changes ({len(domains)} active)"
                )

        except KeyboardInterrupt:

            print("\n[!] DNS Filter stopped.")
            break

        except Exception as e:

            print(f"[!] Monitor Error: {e}")

        time.sleep(interval)


# ===========================
# Main
# ===========================

if __name__ == "__main__":
    monitor_dns()