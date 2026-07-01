import os, time, platform, subprocess, socket, json, logging, argparse, sys
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from collections import defaultdict

# ============================================================
# CONSTANTS
# ============================================================

WELL_KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

SENSITIVE_PORTS = {21, 22, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}

DEFAULT_PORT_THRESHOLD = 30
DEFAULT_TIME_WINDOW = 60

# ============================================================
# EVENT EMITTER
# ============================================================

class EventEmitter:
    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "port_scan_events.log")
        self.logger = logging.getLogger("port_scan")
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
            "tool": "Port Scan Detection Tool",
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
        lines = ["=" * 60, "PORT SCAN DETECTION REPORT",
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
    elif addr.count(":") >= 2 and addr[0].isdigit() or "[" in addr:
        ip, port = addr.rsplit(":", 1)
    else:
        ip, port = addr.rsplit(":", 1) if ":" in addr else (addr, "0")
    return (ip, port)

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
                foreign = parts[2] if proto != "UDP" else parts[2]
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

def get_service_name(port: int) -> str:
    if port in WELL_KNOWN_SERVICES:
        return WELL_KNOWN_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except (OSError, OverflowError):
        return "unknown"

# ============================================================
# PORT SCAN DETECTOR
# ============================================================

class PortScanDetector:
    def __init__(self, emitter: EventEmitter = None, threshold: int = DEFAULT_PORT_THRESHOLD):
        self.findings: List[Dict[str, Any]] = []
        self.connections: List[Dict[str, Any]] = []
        self.emitter = emitter or EventEmitter()
        self.threshold = threshold

    def _add(self, finding: dict):
        finding["timestamp"] = time.time()
        self.findings.append(finding)
        self.emitter.finding_detected("port_scan", finding)

    def _is_local_ip(self, ip: str) -> bool:
        local_ips = {"127.0.0.1", "::1", "0.0.0.0", "::", "*", "localhost"}
        if ip in local_ips:
            return True
        try:
            local_ip = get_local_ip()
            if ip == local_ip:
                return True
        except Exception:
            pass
        return False

    def _classify_scan_risk(self, port_count: int, sensitive_hit: bool) -> str:
        if port_count >= 100 or (port_count >= self.threshold and sensitive_hit):
            return "HIGH"
        if port_count >= self.threshold:
            return "MEDIUM"
        if port_count >= 10:
            return "LOW"
        return "INFO"

    def collect_connections(self) -> List[Dict[str, Any]]:
        self.connections = get_connections()
        return self.connections

    def detect_incoming_scan(self) -> List[Dict[str, Any]]:
        findings = []
        foreign_to_local_ports = defaultdict(set)
        foreign_port_details = defaultdict(list)

        for c in self.connections:
            if self._is_local_ip(c.get("foreign_ip", "")):
                continue
            if c.get("state") in ("LISTEN", "LISTENING"):
                continue
            f_ip = c.get("foreign_ip", "")
            local_port = c.get("local_port", 0)
            if f_ip and local_port and not self._is_local_ip(f_ip):
                foreign_to_local_ports[f_ip].add(local_port)
                foreign_port_details[f_ip].append(c)

        for f_ip, ports in sorted(foreign_to_local_ports.items(), key=lambda x: -len(x[1])):
            port_count = len(ports)
            if port_count < 10:
                continue
            port_list = sorted(ports)
            sensitive_hit = any(p in SENSITIVE_PORTS for p in port_list)
            risk = self._classify_scan_risk(port_count, sensitive_hit)
            target_ports = [{"port": p, "service": get_service_name(p)} for p in port_list[:20]]
            syn_recv = sum(1 for c in foreign_port_details[f_ip] if c.get("state") in ("SYN_RECEIVED", "SYN_RECV"))
            states = defaultdict(int)
            for c in foreign_port_details[f_ip]:
                states[c.get("state", "")] += 1

            f = {
                "type": "incoming_port_scan",
                "name": f"Incoming scan from {f_ip}",
                "scanner_ip": f_ip,
                "unique_ports_hit": port_count,
                "target_ports": target_ports,
                "sensitive_ports_hit": sensitive_hit,
                "syn_recv_count": syn_recv,
                "connection_states": dict(states),
                "risk": risk,
                "description": f"Remote host {f_ip} connected to {port_count} local ports (threshold: {self.threshold}) -- possible port scan",
            }
            findings.append(f)
            self._add(f)

        return findings

    def detect_outgoing_scan(self) -> List[Dict[str, Any]]:
        findings = []
        local_to_foreign_ports = defaultdict(set)
        local_port_details = defaultdict(list)

        for c in self.connections:
            local_ip = c.get("local_ip", "")
            if not self._is_local_ip(local_ip):
                continue
            f_ip = c.get("foreign_ip", "")
            f_port = c.get("foreign_port", 0)
            if f_ip and f_port and not self._is_local_ip(f_ip) and c.get("state") != "LISTEN":
                local_to_foreign_ports[f_ip].add(f_port)
                local_port_details[f_ip].append(c)

        for f_ip, ports in sorted(local_to_foreign_ports.items(), key=lambda x: -len(x[1])):
            port_count = len(ports)
            if port_count < 10:
                continue
            port_list = sorted(ports)
            sensitive_hit = any(p in SENSITIVE_PORTS for p in port_list)
            risk = self._classify_scan_risk(port_count, sensitive_hit)
            target_ports = [{"port": p, "service": get_service_name(p)} for p in port_list[:20]]
            syn_sent = sum(1 for c in local_port_details[f_ip] if c.get("state") == "SYN_SENT")
            states = defaultdict(int)
            for c in local_port_details[f_ip]:
                states[c.get("state", "")] += 1

            f = {
                "type": "outgoing_port_scan",
                "name": f"Outgoing scan to {f_ip}",
                "target_ip": f_ip,
                "unique_ports_contacted": port_count,
                "target_ports": target_ports,
                "sensitive_ports_hit": sensitive_hit,
                "syn_sent_count": syn_sent,
                "connection_states": dict(states),
                "risk": risk,
                "description": f"Local machine contacted {port_count} ports on {f_ip} (threshold: {self.threshold}) -- possible outgoing port scan",
            }
            findings.append(f)
            self._add(f)

        return findings

    def get_connection_summary(self) -> Dict[str, Any]:
        total = len(self.connections)
        by_state = defaultdict(int)
        by_proto = defaultdict(int)
        listening = 0
        established = 0
        for c in self.connections:
            by_state[c.get("state", "NONE")] += 1
            by_proto[c.get("proto", "?")] += 1
            if c.get("state") in ("LISTEN", "LISTENING"):
                listening += 1
            if c.get("state") == "ESTABLISHED":
                established += 1
        return {
            "total_connections": total,
            "by_protocol": dict(by_proto),
            "by_state": dict(by_state),
            "listening": listening,
            "established": established,
        }

    def run_all(self) -> List[Dict[str, Any]]:
        self.emitter.scan_started("port_scan")
        start = time.time()
        self.findings = []
        self.collect_connections()
        self.detect_incoming_scan()
        self.detect_outgoing_scan()
        self.emitter.scan_completed("port_scan", len(self.findings), (time.time() - start) * 1000)
        return self.findings

# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Port Scan Detection Tool")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    parser.add_argument("--incoming", action="store_true", help="Detect incoming port scans")
    parser.add_argument("--outgoing", action="store_true", help="Detect outgoing port scans")
    parser.add_argument("--connections", action="store_true", help="Show current connections overview")
    parser.add_argument("--threshold", "-t", type=int, default=DEFAULT_PORT_THRESHOLD,
                        help=f"Port count threshold for scan detection (default: {DEFAULT_PORT_THRESHOLD})")
    parser.add_argument("--output", "-o", help="Save report to file")
    parser.add_argument("--format", "-f", choices=["json", "text"], default="text", help="Output format")
    args = parser.parse_args()

    if not any([args.all, args.incoming, args.outgoing, args.connections]):
        parser.print_help()
        sys.exit(1)

    emitter = EventEmitter()
    detector = PortScanDetector(emitter=emitter, threshold=args.threshold)
    detector.collect_connections()

    if args.all:
        results = detector.run_all()
    else:
        results = []
        if args.incoming:
            results.extend(detector.detect_incoming_scan())
        if args.outgoing:
            results.extend(detector.detect_outgoing_scan())

    if args.connections or args.all:
        summary = detector.get_connection_summary()
        print(f"\nConnection Summary:")
        print(f"  Total: {summary['total_connections']}")
        print(f"  Listening: {summary['listening']}")
        print(f"  Established: {summary['established']}")
        print(f"  By Protocol: {json.dumps(summary['by_protocol'])}")
        print(f"  By State: {json.dumps(summary['by_state'])}")

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
