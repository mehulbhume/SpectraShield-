import os, time, platform, subprocess, socket, json, logging, argparse, sys
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from collections import defaultdict

# ============================================================
# CONSTANTS
# ============================================================

LATERAL_MOVEMENT_PORTS = {
    22: "SSH",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    389: "LDAP",
    636: "LDAPS",
    88: "Kerberos",
    464: "Kerberos-Change-PW",
}

REMOTE_ADMIN_PORTS = {22, 135, 445, 3389, 5985, 5986}

SMB_PORTS = {139, 445}
RDP_PORTS = {3389}
WINRM_PORTS = {5985, 5986}
RPC_PORTS = {135}

HIGH_VALUE_PORTS = {22, 3389, 5985, 5986, 445}

SENSITIVE_PROCESSES = [
    "psexec", "psexesvc", "smbexec", "wmiexec", "wmic",
    "schtasks", "sc.exe", "winrs", "mstsc", "remote",
    "net.exe", "net1.exe", "powershell", "pwsh",
]

SUSPICIOUS_TEMP_PATHS = ["\\temp\\", "\\tmp\\", "\\windows\\temp\\"]

# ============================================================
# EVENT EMITTER
# ============================================================

class EventEmitter:
    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "lateral_movement_events.log")
        self.logger = logging.getLogger("lateral_movement")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
            self.logger.addHandler(handler)
        self._listeners: Dict[str, List[Callable]] = {}

    def on(self, event: str, callback: Callable):
        self._listeners.setdefault(event, []).append(callback)

    def _emit(self, event: str, **data):
        payload = {"event": event, "timestamp": datetime.now().isoformat(), "data": data}
        level = logging.ERROR if event == "scan.error" else logging.INFO
        self.logger.log(level, "%s | %s", event, json.dumps(data))
        print(f"[EVENT] {payload['timestamp']} | {event} | {json.dumps(data)}")
        for cb in self._listeners.get(event, []):
            try:
                cb(payload)
            except Exception:
                pass

    def scan_started(self, feature: str, target: str = None):
        self._emit("scan.started", feature=feature, target=target)

    def scan_completed(self, feature: str, findings_count: int, duration_ms: float):
        self._emit("scan.completed", feature=feature, findings_count=findings_count, duration_ms=duration_ms)

    def finding_detected(self, feature: str, finding: dict):
        self._emit("finding.detected", feature=feature, finding=finding)

    def error(self, feature: str, message: str):
        self._emit("scan.error", feature=feature, message=message)

    def progress(self, feature: str, current: int, total: int):
        self._emit("scan.progress", feature=feature, current=current, total=total)

# ============================================================
# REPORT
# ============================================================

class Report:
    def __init__(self):
        self.report = {
            "scan_timestamp": datetime.now().isoformat(),
            "tool": "Lateral Movement Alert Tool",
            "version": "1.0.0",
            "findings": [],
        }

    def add_findings(self, findings: List[Dict[str, Any]]):
        self.report["findings"] = findings
        self.report["total_count"] = len(findings)
        self.report["risk_level"] = self._assess_risk(findings)

    def _assess_risk(self, findings: List[Dict]) -> str:
        risks = [f.get("risk", "Low") for f in findings]
        if "CRITICAL" in risks:
            return "CRITICAL"
        if "HIGH" in risks:
            return "HIGH"
        if "MEDIUM" in risks:
            return "MEDIUM"
        if findings:
            return "LOW"
        return "NONE"

    def to_json(self, pretty: bool = True) -> str:
        return json.dumps(self.report, indent=2 if pretty else None, default=str)

    def to_text(self) -> str:
        lines = ["=" * 60, "LATERAL MOVEMENT ALERT REPORT",
                 f"Timestamp: {self.report['scan_timestamp']}",
                 f"Risk Level: {self.report.get('risk_level', 'N/A')}",
                 f"Total Items: {self.report.get('total_count', 0)}", "=" * 60]
        for f in self.report.get("findings", []):
            lines.append(f"\n  - {f.get('name', 'Unknown')}")
            for k, v in f.items():
                if k not in ("name", "timestamp"):
                    v_str = json.dumps(v) if isinstance(v, (list, dict)) else str(v)
                    lines.append(f"      {k}: {v_str}")
        lines.extend(["-" * 60, "END OF REPORT", "=" * 60])
        return "\n".join(lines)

    def save(self, path: str, fmt: str = "json"):
        with open(path, "w") as f:
            f.write(self.to_json() if fmt == "json" else self.to_text())

# ============================================================
# NETWORK HELPERS
# ============================================================

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def parse_ip_port(addr: str) -> tuple:
    if addr.startswith("[") and "]" in addr:
        ip_part, port_part = addr.rsplit("]", 1)
        ip = ip_part[1:]
        port = port_part.lstrip(":")
    elif addr == "*:*":
        return ("*", "*")
    elif "[" in addr:
        ip, port = addr.rsplit(":", 1)
        ip = ip.strip("[]")
    elif addr.count(":") > 1 and "." not in addr:
        return (addr, "0")
    else:
        parts = addr.rsplit(":", 1)
        ip = parts[0] if len(parts) > 1 else addr
        port = parts[1] if len(parts) > 1 else "0"
    return (ip, port)

def get_service_name(port: int) -> str:
    if port in LATERAL_MOVEMENT_PORTS:
        return LATERAL_MOVEMENT_PORTS[port]
    try:
        return socket.getservbyport(port)
    except (OSError, OverflowError):
        return "unknown"

def get_connections() -> List[Dict[str, Any]]:
    system = platform.system().lower()
    conns = []
    try:
        if system == "windows":
            r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=15)
            for line in r.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                if parts[0].upper() not in ("TCP", "UDP", "TCP6", "UDP6"):
                    continue
                proto = parts[0].upper().replace("6", "")
                local = parts[1]
                foreign = parts[2]
                state = parts[3] if len(parts) > 3 and parts[0].upper().startswith("TCP") else ""
                pid = parts[-1] if parts[-1].isdigit() else "0"
                l_ip, l_port = parse_ip_port(local)
                f_ip, f_port = parse_ip_port(foreign)
                if l_port and l_port.isdigit() and (not f_port or f_port.isdigit()):
                    conns.append({
                        "proto": proto, "local_ip": l_ip, "local_port": int(l_port),
                        "foreign_ip": f_ip, "foreign_port": int(f_port) if f_port and f_port.isdigit() else 0,
                        "state": state.upper() if state else "",
                        "pid": int(pid) if pid.isdigit() else 0,
                    })
        else:
            try:
                r = subprocess.run(["ss", "-anptu"], capture_output=True, text=True, timeout=15)
            except FileNotFoundError:
                r = subprocess.run(["netstat", "-anptu"], capture_output=True, text=True, timeout=15)
            for line in r.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                proto = "TCP" if "tcp" in parts[0].lower() else "UDP" if "udp" in parts[0].lower() else ""
                if not proto:
                    continue
                local = parts[3] if proto == "TCP" else parts[3] if len(parts) > 4 else ""
                foreign = parts[4] if proto == "TCP" else "*:*"
                state = parts[1] if proto == "TCP" and len(parts) > 1 else ""
                l_ip, l_port = parse_ip_port(local)
                f_ip, f_port = parse_ip_port(foreign)
                if l_port and l_port.isdigit() and (not f_port or f_port.isdigit()):
                    conns.append({
                        "proto": proto, "local_ip": l_ip, "local_port": int(l_port),
                        "foreign_ip": f_ip, "foreign_port": int(f_port) if f_port and f_port.isdigit() else 0,
                        "state": state.upper() if state else "",
                        "pid": 0,
                    })
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass
    return conns

def get_process_list() -> List[Dict[str, Any]]:
    system = platform.system().lower()
    procs = []
    try:
        if system == "windows":
            r = subprocess.run(["wmic", "process", "get", "ProcessId,ParentProcessId,Name,CommandLine", "/format:csv"],
                               capture_output=True, text=True, timeout=15)
            for line in r.stdout.splitlines():
                if not line.strip() or line.startswith("Node"):
                    continue
                parts = line.split(",")
                if len(parts) < 4:
                    continue
                _n = parts[0].strip()
                cmd = parts[1].strip() if len(parts) > 1 else ""
                name = parts[2].strip() if len(parts) > 2 else ""
                ppid = parts[3].strip() if len(parts) > 3 else "0"
                pid = parts[4].strip() if len(parts) > 4 else "0"
                procs.append({"name": name.lower(), "pid": pid, "cmdline": cmd.lower()})
        else:
            r = subprocess.run(["ps", "-eo", "pid,comm,args", "--no-headers"],
                               capture_output=True, text=True, timeout=15)
            for line in r.stdout.splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) < 2:
                    continue
                procs.append({"name": parts[1].lower(), "pid": parts[0], "cmdline": (parts[2] if len(parts) > 2 else "").lower()})
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return procs

# ============================================================
# LATERAL MOVEMENT DETECTOR
# ============================================================

class LateralMovementDetector:
    def __init__(self, emitter: EventEmitter = None):
        self.findings: List[Dict[str, Any]] = []
        self.connections: List[Dict[str, Any]] = []
        self.processes: List[Dict[str, Any]] = []
        self.emitter = emitter or EventEmitter()

    def _add(self, finding: dict):
        finding["timestamp"] = time.time()
        self.findings.append(finding)
        self.emitter.finding_detected("lateral_movement", finding)

    def _is_local_ip(self, ip: str) -> bool:
        local_ips = {"127.0.0.1", "::1", "0.0.0.0", "::", "*", "localhost"}
        if ip in local_ips:
            return True
        try:
            if ip == get_local_ip():
                return True
        except Exception:
            pass
        return False

    def collect(self):
        self.connections = get_connections()
        self.processes = get_process_list()

    def _find_process_by_pid(self, pid: int) -> Optional[str]:
        for p in self.processes:
            if p.get("pid") == str(pid):
                return p.get("name", "")
        return None

    def detect_rdp_movement(self) -> List[Dict[str, Any]]:
        findings = []
        inbound_rdp = []
        outbound_rdp = []
        for c in self.connections:
            if c.get("state") in ("LISTEN", "LISTENING") or not c.get("state"):
                continue
            if c.get("local_port") in RDP_PORTS and not self._is_local_ip(c.get("foreign_ip", "")):
                inbound_rdp.append(c)
            if c.get("foreign_port") in RDP_PORTS and not self._is_local_ip(c.get("foreign_ip", "")):
                outbound_rdp.append(c)
        if inbound_rdp:
            src_ips = defaultdict(int)
            for c in inbound_rdp:
                src_ips[c["foreign_ip"]] += 1
            for ip, count in sorted(src_ips.items(), key=lambda x: -x[1]):
                f = {
                    "type": "rdp_inbound",
                    "name": f"Inbound RDP from {ip}",
                    "source_ip": ip,
                    "connection_count": count,
                    "risk": "HIGH" if count > 3 else "MEDIUM",
                    "description": f"Remote RDP session from {ip} ({count} connection(s)) -- possible lateral movement",
                }
                findings.append(f)
                self._add(f)
        if outbound_rdp:
            dst_ips = defaultdict(int)
            for c in outbound_rdp:
                dst_ips[c["foreign_ip"]] += 1
            for ip, count in sorted(dst_ips.items(), key=lambda x: -x[1]):
                f = {
                    "type": "rdp_outbound",
                    "name": f"Outbound RDP to {ip}",
                    "destination_ip": ip,
                    "connection_count": count,
                    "risk": "MEDIUM",
                    "description": f"Outbound RDP connection to {ip} ({count} connection(s))",
                }
                findings.append(f)
                self._add(f)
        return findings

    def detect_smb_movement(self) -> List[Dict[str, Any]]:
        findings = []
        inbound_smb = []
        outbound_smb = []
        for c in self.connections:
            if c.get("state") in ("LISTEN", "LISTENING") or not c.get("state"):
                continue
            if c.get("local_port") in SMB_PORTS and not self._is_local_ip(c.get("foreign_ip", "")):
                inbound_smb.append(c)
            if c.get("foreign_port") in SMB_PORTS and not self._is_local_ip(c.get("foreign_ip", "")):
                outbound_smb.append(c)
        if inbound_smb:
            src_ips = defaultdict(int)
            for c in inbound_smb:
                src_ips[c["foreign_ip"]] += 1
            for ip, count in sorted(src_ips.items(), key=lambda x: -x[1]):
                f = {
                    "type": "smb_inbound",
                    "name": f"Inbound SMB from {ip}",
                    "source_ip": ip,
                    "connection_count": count,
                    "risk": "HIGH",
                    "description": f"Remote SMB connection from {ip} -- possible lateral movement via file sharing",
                }
                findings.append(f)
                self._add(f)
        if outbound_smb:
            dst_count = defaultdict(int)
            for c in outbound_smb:
                dst_count[c["foreign_ip"]] += 1
            for ip, count in sorted(dst_count.items(), key=lambda x: -x[1]):
                f = {
                    "type": "smb_outbound",
                    "name": f"Outbound SMB to {ip}",
                    "destination_ip": ip,
                    "connection_count": count,
                    "risk": "MEDIUM",
                    "description": f"Outbound SMB connection to {ip} ({count} connection(s))",
                }
                findings.append(f)
                self._add(f)
        return findings

    def detect_winrm_movement(self) -> List[Dict[str, Any]]:
        findings = []
        winrm_conns = []
        for c in self.connections:
            if c.get("state") in ("LISTEN", "LISTENING") or not c.get("state"):
                continue
            if c.get("foreign_port") in WINRM_PORTS and not self._is_local_ip(c.get("foreign_ip", "")):
                winrm_conns.append(c)
            if c.get("local_port") in WINRM_PORTS and not self._is_local_ip(c.get("foreign_ip", "")):
                winrm_conns.append(c)
        if winrm_conns:
            peers = defaultdict(int)
            for c in winrm_conns:
                peer = c.get("foreign_ip", "")
                if peer and not self._is_local_ip(peer):
                    peers[peer] += 1
            for ip, count in sorted(peers.items(), key=lambda x: -x[1]):
                f = {
                    "type": "winrm_remoting",
                    "name": f"WinRM/PowerShell remoting with {ip}",
                    "peer_ip": ip,
                    "connection_count": count,
                    "risk": "HIGH",
                    "description": f"WinRM remoting detected with {ip} -- possible PowerShell lateral movement",
                }
                findings.append(f)
                self._add(f)
        return findings

    def detect_multi_host_admin(self) -> List[Dict[str, Any]]:
        findings = []
        ip_port_map = defaultdict(lambda: defaultdict(int))
        for c in self.connections:
            if c.get("state") in ("LISTEN", "LISTENING") or not c.get("state"):
                continue
            f_ip = c.get("foreign_ip", "")
            f_port = c.get("foreign_port", 0)
            if f_ip and not self._is_local_ip(f_ip) and f_port in REMOTE_ADMIN_PORTS:
                ip_port_map[f_ip][f_port] += 1
        single_ip_multi_port = {ip: ports for ip, ports in ip_port_map.items() if len(ports) >= 2}
        for ip, ports in sorted(single_ip_multi_port.items(), key=lambda x: -sum(x[1].values())):
            port_list = [{"port": p, "service": get_service_name(p), "count": c} for p, c in sorted(ports.items())]
            total = sum(ports.values())
            f = {
                "type": "multi_admin_ports",
                "name": f"Multiple admin protocols from {ip}",
                "source_ip": ip,
                "admin_ports": port_list,
                "total_connections": total,
                "risk": "HIGH",
                "description": f"Host {ip} connected on {len(ports)} different admin ports ({total} total connections) -- possible lateral movement tool",
            }
            findings.append(f)
            self._add(f)

        local_multi_host = defaultdict(lambda: defaultdict(int))
        for c in self.connections:
            if c.get("state") in ("LISTEN", "LISTENING") or not c.get("state"):
                continue
            f_ip = c.get("foreign_ip", "")
            f_port = c.get("foreign_port", 0)
            if f_ip and not self._is_local_ip(f_ip) and f_port in HIGH_VALUE_PORTS:
                local_multi_host[f_port][f_ip] += 1
        for port, hosts in sorted(local_multi_host.items(), key=lambda x: -len(x[1])):
            if len(hosts) >= 3:
                host_list = [{"ip": ip, "count": c} for ip, c in sorted(hosts.items(), key=lambda x: -x[1])]
                f = {
                    "type": "multi_host_admin_access",
                    "name": f"Connecting to multiple hosts on port {port}",
                    "port": port,
                    "service": get_service_name(port),
                    "target_count": len(hosts),
                    "targets": host_list[:10],
                    "risk": "HIGH",
                    "description": f"Connections to {len(hosts)} different hosts on {get_service_name(port)} (port {port}) -- possible lateral movement scanning",
                }
                findings.append(f)
                self._add(f)
        return findings

    def detect_suspicious_processes(self) -> List[Dict[str, Any]]:
        findings = []
        for p in self.processes:
            name = p.get("name", "")
            cmd = p.get("cmdline", "")
            matched = [s for s in SENSITIVE_PROCESSES if s in name or s in cmd]
            if not matched:
                continue
            temp_match = any(t in cmd for t in SUSPICIOUS_TEMP_PATHS)
            risk = "CRITICAL" if temp_match else "MEDIUM"
            f = {
                "type": "suspicious_lateral_movement_process",
                "name": f"Suspicious process: {name}",
                "process_name": name,
                "pid": p.get("pid"),
                "matched_keywords": matched,
                "running_from_temp": temp_match,
                "cmdline": cmd,
                "risk": risk,
                "description": f"Process '{name}' matches lateral movement tool patterns: {', '.join(matched)}",
            }
            findings.append(f)
            self._add(f)
        return findings

    def get_connection_summary(self) -> Dict[str, Any]:
        total = len(self.connections)
        by_state = defaultdict(int)
        admin_conns = 0
        for c in self.connections:
            by_state[c.get("state", "NONE")] += 1
            if c.get("local_port") in REMOTE_ADMIN_PORTS or c.get("foreign_port") in REMOTE_ADMIN_PORTS:
                admin_conns += 1
        listening = by_state.get("LISTEN", 0) + by_state.get("LISTENING", 0)
        established = by_state.get("ESTABLISHED", 0)
        return {
            "total_connections": total,
            "listening": listening,
            "established": established,
            "admin_port_connections": admin_conns,
        }

    def run_all(self) -> List[Dict[str, Any]]:
        self.emitter.scan_started("lateral_movement")
        start = time.time()
        self.findings = []
        self.collect()
        self.detect_rdp_movement()
        self.detect_smb_movement()
        self.detect_winrm_movement()
        self.detect_multi_host_admin()
        self.detect_suspicious_processes()
        self.emitter.scan_completed("lateral_movement", len(self.findings), (time.time() - start) * 1000)
        return self.findings

# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Lateral Movement Alert Tool")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    parser.add_argument("--rdp", action="store_true", help="Detect RDP lateral movement")
    parser.add_argument("--smb", action="store_true", help="Detect SMB lateral movement")
    parser.add_argument("--winrm", action="store_true", help="Detect WinRM/PowerShell remoting")
    parser.add_argument("--admin", action="store_true", help="Detect multi-host admin connections")
    parser.add_argument("--processes", action="store_true", help="Detect suspicious lateral movement processes")
    parser.add_argument("--connections", action="store_true", help="Show connection summary")
    parser.add_argument("--output", "-o", help="Save report to file")
    parser.add_argument("--format", "-f", choices=["json", "text"], default="text", help="Output format")
    args = parser.parse_args()

    if not any([args.all, args.rdp, args.smb, args.winrm, args.admin, args.processes, args.connections]):
        parser.print_help()
        sys.exit(1)

    emitter = EventEmitter()
    detector = LateralMovementDetector(emitter=emitter)
    detector.collect()

    if args.all:
        results = detector.run_all()
    else:
        results = []
        if args.rdp:
            results.extend(detector.detect_rdp_movement())
        if args.smb:
            results.extend(detector.detect_smb_movement())
        if args.winrm:
            results.extend(detector.detect_winrm_movement())
        if args.admin:
            results.extend(detector.detect_multi_host_admin())
        if args.processes:
            results.extend(detector.detect_suspicious_processes())

    if args.connections or args.all:
        summary = detector.get_connection_summary()
        print(f"\nConnection Summary:")
        print(f"  Total: {summary['total_connections']}")
        print(f"  Listening: {summary['listening']}")
        print(f"  Established: {summary['established']}")
        print(f"  Admin Port Connections: {summary['admin_port_connections']}")

    report = Report()
    report.add_findings(results)

    if args.format == "json":
        print(report.to_json())
    else:
        print(report.to_text())

    if args.output:
        report.save(args.output, fmt=args.format)
        print(f"\nReport saved to {args.output}")

if __name__ == "__main__":
    main()
