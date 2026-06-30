import subprocess
from audit_logger import log_event

def apply_rules(rules):
    # Pehle purane rules saaf karo (sirf hamare banaye hue rules)
    subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", "name=FirewallAgentRule"],
        capture_output=True, text=True
    )
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
    direction = "in" if rule["direction"] == "inbound" else "out"
    action = "allow" if rule["action"].upper() == "ACCEPT" else "block"
    protocol = rule["protocol"].upper()

    rule_name = f"FirewallAgentRule_{rule['id']}"

    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        f"dir={direction}",
        f"action={action}",
        f"protocol={protocol}",
    ]

    if rule.get("port"):
        cmd.append(f"localport={rule['port']}")
    if rule.get("src_ip"):
        cmd.append(f"remoteip={rule['src_ip']}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"[+] Rule applied: {rule['id']} → {rule['action'].upper()} on port {rule.get('port', 'any')}")
        log_event(
            event_type="firewall_rule_applied",
            feature_id=15,
            severity="info",
            data={
                "rule_id": rule["id"],
                "action": rule["action"].upper(),
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