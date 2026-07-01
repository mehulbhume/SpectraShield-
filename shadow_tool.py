import os, time, platform, subprocess, socket, json, logging, argparse, sys
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable

SHADOW_IT_SERVICES = [
    {"name": "Dropbox", "domain": "dropbox.com", "category": "Cloud Storage"},
    {"name": "Google Drive", "domain": "drive.google.com", "category": "Cloud Storage"},
    {"name": "Slack", "domain": "slack.com", "category": "Communication"},
    {"name": "Discord", "domain": "discord.com", "category": "Communication"},
    {"name": "Telegram", "domain": "telegram.org", "category": "Communication"},
    {"name": "WhatsApp Web", "domain": "web.whatsapp.com", "category": "Communication"},
    {"name": "Trello", "domain": "trello.com", "category": "Project Management"},
    {"name": "Asana", "domain": "asana.com", "category": "Project Management"},
    {"name": "Notion", "domain": "notion.so", "category": "Productivity"},
    {"name": "Miro", "domain": "miro.com", "category": "Collaboration"},
    {"name": "Figma", "domain": "figma.com", "category": "Design"},
    {"name": "Canva", "domain": "canva.com", "category": "Design"},
    {"name": "Zoom", "domain": "zoom.us", "category": "Video Conferencing"},
    {"name": "Microsoft Teams (Personal)", "domain": "teams.microsoft.com", "category": "Communication"},
    {"name": "Airtable", "domain": "airtable.com", "category": "Database"},
    {"name": "Notion", "domain": "notion.site", "category": "Productivity"},
    {"name": "LastPass", "domain": "lastpass.com", "category": "Password Manager"},
    {"name": "1Password", "domain": "1password.com", "category": "Password Manager"},
    {"name": "WeTransfer", "domain": "wetransfer.com", "category": "File Sharing"},
    {"name": "Jira Cloud", "domain": "atlassian.net", "category": "Project Management"},
]

KNOWN_UNAUTHORIZED_SOFTWARE = [
    "TeamViewer", "AnyDesk", "LogMeIn", "VNC Server",
    "BitTorrent", "uTorrent", "LimeWire",
    "Tor Browser", "Psiphon", "Hotspot Shield",
    "Kali Linux", "Metasploit", "Nmap (non-admin)",
    "Wireshark (unauthorized)", "Burp Suite (unauthorized)",
    "Crypto Miner", "EthMiner", "CcMiner",
]

def is_known_shadow_it_service(domain: str) -> dict:
    for service in SHADOW_IT_SERVICES:
        if service["domain"] in domain or domain in service["domain"]:
            return service
    return {}

class EventEmitter:
    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "shadow_it_events.log")
        self.logger = logging.getLogger("shadow_it")
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

class Report:
    def __init__(self):
        self.report = {
            "scan_timestamp": datetime.now().isoformat(),
            "tool": "Shadow IT Detection Tool",
            "version": "1.0.0",
            "findings": [],
        }

    def add_findings(self, findings: List[Dict[str, Any]]):
        self.report["findings"] = findings
        self.report["total_count"] = len(findings)
        self.report["risk_level"] = self._assess_risk(findings)

    def _assess_risk(self, findings: List[Dict]) -> str:
        categories = {r.get("category", "") for r in findings}
        if any(c in ("File Sharing", "VPN", "Remote Access") for c in categories):
            return "HIGH"
        if len(findings) >= 5:
            return "MEDIUM"
        if findings:
            return "LOW"
        return "NONE"

    def to_json(self, pretty: bool = True) -> str:
        return json.dumps(self.report, indent=2 if pretty else None, default=str)

    def to_text(self) -> str:
        lines = ["=" * 60, "SHADOW IT DETECTION REPORT",
                 f"Timestamp: {self.report['scan_timestamp']}",
                 f"Risk Level: {self.report.get('risk_level', 'N/A')}",
                 f"Total Items: {self.report.get('total_count', 0)}", "=" * 60]
        for f in self.report.get("findings", []):
            lines.append(f"\n  - {f.get('name', 'Unknown')}")
            for k, v in f.items():
                if k not in ("name", "timestamp"):
                    lines.append(f"      {k}: {v}")
        lines.extend(["-" * 60, "END OF REPORT", "=" * 60])
        return "\n".join(lines)

    def save(self, path: str, fmt: str = "json"):
        with open(path, "w") as f:
            f.write(self.to_json() if fmt == "json" else self.to_text())

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

def arp_scan() -> List[dict]:
    devices = []
    system = platform.system().lower()
    try:
        if system == "windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=30)
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and ":" in parts[1]:
                    devices.append({"ip": parts[0], "mac": parts[1], "type": parts[2] if len(parts) > 2 else "dynamic"})
        else:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=30)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and ":" in parts[2]:
                    devices.append({"ip": parts[0], "mac": parts[2], "type": parts[3] if len(parts) > 3 else "unknown"})
    except (subprocess.TimeoutExpired, FileNotFoundError):
        devices.append({"ip": "127.0.0.1", "mac": "00:00:00:00:00:00", "type": "localhost"})
    return devices

def resolve_domain(domain: str, timeout: float = 3.0) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)

def check_connectivity(host: str = "8.8.8.8", port: int = 53, timeout: float = 2.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

class ShadowITDetector:
    def __init__(self, emitter: EventEmitter = None):
        self.findings: List[Dict[str, Any]] = []
        self.emitter = emitter or EventEmitter()

    def _add(self, finding: dict):
        finding["timestamp"] = time.time()
        self.findings.append(finding)
        self.emitter.finding_detected("shadow_it", finding)

    def detect_network_devices(self) -> List[Dict[str, Any]]:
        findings = []
        for d in arp_scan():
            ip, mac = d.get("ip", ""), d.get("mac", "")
            if ip == "127.0.0.1":
                continue
            f = {"type": "unauthorized_device", "name": f"Unknown Device at {ip}",
                 "ip": ip, "mac": mac, "risk": "MEDIUM" if mac != "00:00:00:00:00:00" else "LOW",
                 "description": f"Unrecognized network device detected at {ip}"}
            findings.append(f)
            self._add(f)
        return findings

    def detect_cloud_services(self, domains: List[str] = None) -> List[Dict[str, Any]]:
        if domains is None:
            domains = [s["domain"] for s in SHADOW_IT_SERVICES]
        if not check_connectivity():
            return []
        findings = []
        for i, domain in enumerate(domains):
            self.emitter.progress("cloud_services", i + 1, len(domains))
            ip = resolve_domain(domain, timeout=2.0)
            if ip:
                svc = is_known_shadow_it_service(domain)
                if svc:
                    f = {"type": "unauthorized_cloud_service", "name": svc["name"],
                         "domain": domain, "ip": ip, "category": svc["category"],
                         "risk": "MEDIUM",
                         "description": f"Unauthorized {svc['category']} service: {svc['name']}"}
                    findings.append(f)
                    self._add(f)
        return findings

    def detect_unauthorized_software(self) -> List[Dict[str, Any]]:
        findings = []
        system = platform.system().lower()

        def check(running: str):
            running = running.lower()
            for sw in KNOWN_UNAUTHORIZED_SOFTWARE:
                name = sw.lower().replace("(non-admin)", "").replace("(unauthorized)", "").strip()
                parts = name.replace("(", "").replace(")", "").split()
                for p in parts:
                    if p and p in running:
                        f = {"type": "unauthorized_software", "name": sw, "risk": "HIGH",
                             "description": f"Unauthorized software detected: {sw}"}
                        findings.append(f)
                        self._add(f)
                        break

        try:
            if system == "windows":
                r = subprocess.run(["wmic", "process", "get", "name"], capture_output=True, text=True, timeout=10)
                check(r.stdout)
            elif system in ("linux", "darwin"):
                r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
                check(r.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return findings

    def detect_browser_extensions(self) -> List[Dict[str, Any]]:
        findings = []
        system = platform.system().lower()
        home = os.path.expanduser("~")
        paths = []
        if system == "windows":
            paths.append(os.path.join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Extensions"))
            paths.append(os.path.join(home, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Extensions"))
        elif system == "linux":
            paths.append(os.path.join(home, ".config", "google-chrome", "Default", "Extensions"))
        elif system == "darwin":
            paths.append(os.path.join(home, "Library", "Application Support", "Google", "Chrome", "Default", "Extensions"))
        keywords = ["proxy", "vpn", "torrent", "crypto", "miner", "password", "remote", "screen", "recording"]
        for p in paths:
            if p and os.path.isdir(p):
                for eid in os.listdir(p):
                    matched = [k for k in keywords if k in eid.lower()]
                    if matched:
                        f = {"type": "browser_extension", "name": eid, "risk": "MEDIUM",
                             "matched_keywords": matched,
                             "description": f"Risky browser extension: {eid}"}
                        findings.append(f)
                        self._add(f)
        return findings

    def run_all(self) -> List[Dict[str, Any]]:
        self.emitter.scan_started("shadow_it")
        start = time.time()
        self.findings = []
        self.detect_network_devices()
        self.detect_cloud_services()
        self.detect_unauthorized_software()
        self.detect_browser_extensions()
        self.emitter.scan_completed("shadow_it", len(self.findings), (time.time() - start) * 1000)
        return self.findings

def main():
    parser = argparse.ArgumentParser(description="Shadow IT Detection Tool")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    parser.add_argument("--devices", action="store_true", help="Detect unauthorized network devices")
    parser.add_argument("--cloud", action="store_true", help="Detect unauthorized cloud services")
    parser.add_argument("--software", action="store_true", help="Detect unauthorized software")
    parser.add_argument("--browser", action="store_true", help="Detect risky browser extensions")
    parser.add_argument("--output", "-o", help="Save report to file")
    parser.add_argument("--format", "-f", choices=["json", "text"], default="text", help="Output format")
    args = parser.parse_args()

    if not any([args.all, args.devices, args.cloud, args.software, args.browser]):
        parser.print_help()
        sys.exit(1)

    emitter = EventEmitter()
    detector = ShadowITDetector(emitter=emitter)

    if args.all:
        results = detector.run_all()
    else:
        results = []
        if args.devices:
            results.extend(detector.detect_network_devices())
        if args.cloud:
            results.extend(detector.detect_cloud_services())
        if args.software:
            results.extend(detector.detect_unauthorized_software())
        if args.browser:
            results.extend(detector.detect_browser_extensions())

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
