import subprocess
from audit_logger import log_event

def apply_rules(rules):
    # Pehle purane rules saaf karo
    subprocess.run(["sudo", "iptables", "-F", "INPUT"], capture_output=True)
    subprocess.run(["sudo", "iptables", "-F", "OUTPUT"], capture_output=True)
    print("[*] Old rules cleared")

    applied = []
    failed = []

    for rule in sorted(rules, key=lambda r: r["priority"]):
        success = apply_single_rule(rule)
        if success:
            applied.append(rule["id"])
        else:
            failed.append(rule["id"])

    # Summary event — kitne rules apply hue
    log_event(
        event_type="firewall_rules_applied",
        feature_id=15,
        severity="info",
        data={
            "total": len(rules),
            "applied": len(applied),
            "failed": len(failed),
            "applied_ids": applied,
            "failed_ids": failed
        }
    )

def apply_single_rule(rule):
    chain = "INPUT" if rule["direction"] == "inbound" else "OUTPUT"
    action = rule["action"].upper()  # ACCEPT ya DROP

    cmd = ["sudo", "iptables", "-A", chain, "-p", rule["protocol"]]

    if rule.get("port"):
        cmd += ["--dport", str(rule["port"])]

    if rule.get("src_ip"):
        cmd += ["-s", rule["src_ip"]]

    if rule.get("dst_ip"):
        cmd += ["-d", rule["dst_ip"]]

    cmd += ["-j", action]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"[+] Rule applied: {rule['id']} → {action} on port {rule.get('port', 'any')}")

        # Har rule ka individual event bhi log karo
        log_event(
            event_type="firewall_rule_applied",
            feature_id=15,
            severity="info",
            data={
                "rule_id": rule["id"],
                "action": action,
                "direction": rule["direction"],
                "protocol": rule["protocol"],
                "port": rule.get("port", "any"),
                "src_ip": rule.get("src_ip", "any"),
                "dst_ip": rule.get("dst_ip", "any"),
            }
        )
        return True
    else:
        print(f"[!] Rule failed: {rule['id']} — {result.stderr.strip()}")

        log_event(
            event_type="firewall_rule_failed",
            feature_id=15,
            severity="high",
            data={
                "rule_id": rule["id"],
                "error": result.stderr.strip(),
                "cmd": " ".join(cmd)
            }
        )
        return False