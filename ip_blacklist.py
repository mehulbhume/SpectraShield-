import subprocess
from audit_logger import log_event

MALICIOUS_IPS = [
    "185.220.101.1",
    "192.42.116.16",
    "198.96.155.3",
    "171.25.193.9",
]

def apply_ip_blacklist(ips: list):
    for ip in ips:
        # Inbound block
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=EDR_BLOCK_IN_{ip}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "protocol=any"
        ], capture_output=True, text=True)

        # Outbound block
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=EDR_BLOCK_OUT_{ip}",
            "dir=out",
            "action=block",
            f"remoteip={ip}",
            "protocol=any"
        ], capture_output=True, text=True)

        print(f"[+] IP Blocked: {ip}")

    log_event(
        event_type="ip_blacklist_applied",
        feature_id=16,
        severity="high",
        data={
            "blocked_ips": ips,
            "count": len(ips),
            "method": "netsh_advfirewall"
        }
    )
    print(f"\n[+] Total {len(ips)} IPs blocked!")

if __name__ == "__main__":
    print("[*] IP Blacklist starting...")
    apply_ip_blacklist(MALICIOUS_IPS)