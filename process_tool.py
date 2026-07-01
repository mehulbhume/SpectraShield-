import os, re, time, platform, subprocess, json, logging, argparse, sys
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable

# ============================================================
# DATA: Suspicious process patterns
# ============================================================

SUSPICIOUS_PARENT_CHILD = [
    {"parent_keywords": ["winword", "excel", "powerpnt", "outlook"],
     "child_keywords": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
     "risk": "HIGH", "description": "Office application spawning a shell -- possible macro infection"},
    {"parent_keywords": ["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "opera.exe"],
     "child_keywords": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"],
     "risk": "HIGH", "description": "Browser spawning a shell -- possible drive-by download"},
    {"parent_keywords": ["svchost.exe", "services.exe", "lsass.exe", "wininit.exe"],
     "child_keywords": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe"],
     "risk": "HIGH", "description": "System process spawning a shell -- possible privilege escalation"},
    {"parent_keywords": ["cmd.exe", "powershell.exe", "pwsh.exe"],
     "child_keywords": ["rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe"],
     "risk": "MEDIUM", "description": "Shell spawning lolbin -- possible code execution bypass"},
    {"parent_keywords": ["winword", "excel", "powerpnt", "outlook"],
     "child_keywords": ["rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe"],
     "risk": "MEDIUM", "description": "Office app spawning lolbin -- possible scriptlet execution"},
    {"parent_keywords": ["taskmgr.exe", "procexp.exe", "procmon.exe"],
     "child_keywords": ["cmd.exe", "powershell.exe"],
     "risk": "LOW", "description": "Process explorer spawning shell -- user initiated"},
    {"parent_keywords": ["explorer.exe"],
     "child_keywords": ["wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"],
     "risk": "MEDIUM", "description": "Explorer spawning script host -- possible click-based infection"},
    {"parent_keywords": ["python.exe", "python3.exe", "node.exe", "java.exe", "ruby.exe"],
     "child_keywords": ["cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe"],
     "risk": "MEDIUM", "description": "Interpreter spawning a shell -- possible reverse shell"},
    {"parent_keywords": ["cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe"],
     "child_keywords": ["nc.exe", "ncat", "socat", "plink", "netcat"],
     "risk": "HIGH", "description": "Shell spawning network connection tool -- possible backdoor"},
]

SUSPICIOUS_PROCESS_NAMES = [
    {"name": "mimikatz", "risk": "CRITICAL", "description": "Credential dumping tool"},
    {"name": "procdump", "risk": "HIGH", "description": "Process memory dumper"},
    {"name": "pwdump", "risk": "HIGH", "description": "Password hash dumper"},
    {"name": "gsecdump", "risk": "HIGH", "description": "Credential dumper"},
    {"name": "cain", "risk": "HIGH", "description": "Password cracking tool"},
    {"name": "wce", "risk": "HIGH", "description": "Windows credential editor"},
    {"name": "meterpreter", "risk": "CRITICAL", "description": "Metasploit payload"},
    {"name": "beacon", "risk": "CRITICAL", "description": "Cobalt Strike beacon"},
    {"name": "nc.exe", "risk": "HIGH", "description": "Netcat backdoor"},
    {"name": "ncat", "risk": "HIGH", "description": "Nmap netcat"},
    {"name": "plink", "risk": "MEDIUM", "description": "PuTTY link -- possible tunneling"},
    {"name": "socat", "risk": "HIGH", "description": "Bidirectional data relay"},
    {"name": "stunnel", "risk": "MEDIUM", "description": "SSL tunnel"},
    {"name": "tsocks", "risk": "MEDIUM", "description": "SOCKS proxy wrapper"},
    {"name": "proxychains", "risk": "MEDIUM", "description": "Proxy chain tool"},
    {"name": "fscan", "risk": "HIGH", "description": "Network scanner"},
    {"name": "masscan", "risk": "HIGH", "description": "High-speed port scanner"},
]

LEAF_PROCESSES = ["lsass.exe", "winlogon.exe", "csrss.exe", "smss.exe",
                   "services.exe", "svchost.exe", "spoolsv.exe"]

# ============================================================
# EVENT EMITTER
# ============================================================

class EventEmitter:
    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(log_dir, exist_ok=True)
        self.logger = logging.getLogger("process_tree")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            h = logging.FileHandler(os.path.join(log_dir, "process_tree_events.log"))
            h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
            self.logger.addHandler(h)
        self._listeners: Dict[str, List[Callable]] = {}

    def on(self, event: str, cb: Callable):
        self._listeners.setdefault(event, []).append(cb)

    def _emit(self, event: str, **data):
        p = {"event": event, "timestamp": datetime.now().isoformat(), "data": data}
        lvl = logging.ERROR if event == "scan.error" else logging.INFO
        self.logger.log(lvl, "%s | %s", event, json.dumps(data))
        print(f"[EVENT] {p['timestamp']} | {event} | {json.dumps(data)}")
        for cb in self._listeners.get(event, []):
            try: cb(p)
            except Exception: pass

    def scan_started(self, feature: str, target: str = None):
        self._emit("scan.started", feature=feature, target=target)
    def scan_completed(self, feature: str, count: int, dur: float):
        self._emit("scan.completed", feature=feature, findings_count=count, duration_ms=dur)
    def finding_detected(self, feature: str, finding: dict):
        self._emit("finding.detected", feature=feature, finding=finding)
    def error(self, feature: str, msg: str):
        self._emit("scan.error", feature=feature, message=msg)
    def progress(self, feature: str, cur: int, total: int):
        self._emit("scan.progress", feature=feature, current=cur, total=total)

# ============================================================
# REPORT
# ============================================================

class Report:
    def __init__(self):
        self.report = {"scan_timestamp": datetime.now().isoformat(),
                       "tool": "Process Tree Tracker", "version": "1.0.0",
                       "findings": [], "process_tree": []}

    def add_findings(self, findings: List[Dict]):
        self.report["findings"] = findings
        self.report["total_count"] = len(findings)
        risks = [f.get("risk", "Low") for f in findings]
        if "CRITICAL" in risks: self.report["risk_level"] = "CRITICAL"
        elif "HIGH" in risks: self.report["risk_level"] = "HIGH"
        elif "MEDIUM" in risks: self.report["risk_level"] = "MEDIUM"
        elif findings: self.report["risk_level"] = "LOW"
        else: self.report["risk_level"] = "NONE"

    def set_process_tree(self, tree: List[Dict]):
        self.report["process_tree"] = tree

    def to_json(self, pretty: bool = True) -> str:
        return json.dumps(self.report, indent=2 if pretty else None, default=str)

    def to_text(self) -> str:
        lines = ["=" * 60, "PROCESS TREE TRACKER REPORT",
                 f"Timestamp: {self.report['scan_timestamp']}",
                 f"Risk Level: {self.report.get('risk_level', 'N/A')}",
                 f"Suspicious Items: {self.report.get('total_count', 0)}", "=" * 60,
                 "", "--- PROCESS TREE ---"]
        for node in self.report.get("process_tree", []):
            ind = "  " * node.get("depth", 0)
            lines.append(f"{ind}|-  {node.get('name', '?')} (PID: {node.get('pid', '?')})")
            if node.get("cmdline"):
                lines.append(f"{ind}  cmd: {node['cmdline']}")
        lines.extend(["", "--- SUSPICIOUS FINDINGS ---"])
        for f in self.report.get("findings", []):
            lines.append(f"\n  [{f.get('risk', '?')}] {f.get('name', 'Unknown')}")
            for k, v in f.items():
                if k not in ("name", "risk", "timestamp"):
                    lines.append(f"      {k}: {v}")
        lines.extend(["-" * 60, "END OF REPORT", "=" * 60])
        return "\n".join(lines)

    def save(self, path: str, fmt: str = "json"):
        with open(path, "w") as f:
            f.write(self.to_json() if fmt == "json" else self.to_text())

# ============================================================
# PROCESS TREE TRACKER
# ============================================================

class ProcessTreeTracker:
    def __init__(self, emitter: EventEmitter = None):
        self.all_processes: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.tree: List[Dict[str, Any]] = []
        self.emitter = emitter or EventEmitter()

    def _add(self, f: dict):
        f["timestamp"] = time.time()
        self.findings.append(f)
        self.emitter.finding_detected("process_tree", f)

    def enumerate_processes(self) -> List[Dict[str, Any]]:
        system = platform.system().lower()
        procs, seen = [], set()
        if system == "windows":
            try:
                r = subprocess.run(["wmic", "process", "get",
                    "ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath", "/format:csv"],
                    capture_output=True, text=True, timeout=30)
                for line in r.stdout.splitlines():
                    if not line.strip() or line.startswith("Node"): continue
                    parts = line.split(",")
                    if len(parts) < 4: continue
                    _n, cmd, path = parts[0].strip(), parts[1].strip() if parts[1] else "", parts[2].strip() if parts[2] else ""
                    name = parts[3].strip() if len(parts) > 3 and parts[3] else ""
                    try: ppid = int(parts[4].strip()) if parts[4].strip().isdigit() else 0
                    except: ppid = 0
                    try: pid = int(parts[5].strip()) if parts[5].strip().isdigit() else 0
                    except: pid = 0
                    if pid and pid not in seen:
                        seen.add(pid)
                        procs.append({"pid": pid, "ppid": ppid, "name": name, "cmdline": cmd, "path": path})
            except (subprocess.TimeoutExpired, FileNotFoundError): pass
        else:
            try:
                r = subprocess.run(["ps", "-eo", "pid,ppid,comm,args", "--no-headers"],
                    capture_output=True, text=True, timeout=30)
                for line in r.stdout.splitlines():
                    parts = line.strip().split(None, 3)
                    if len(parts) < 3: continue
                    try: pid, ppid = int(parts[0]), int(parts[1])
                    except ValueError: continue
                    name, cmd = parts[2], parts[3] if len(parts) > 3 else ""
                    if pid not in seen:
                        seen.add(pid)
                        procs.append({"pid": pid, "ppid": ppid, "name": name, "cmdline": cmd, "path": ""})
            except (subprocess.TimeoutExpired, FileNotFoundError): pass
        self.all_processes = procs
        return procs

    def build_tree(self) -> List[Dict[str, Any]]:
        pmap = {p["pid"]: p for p in self.all_processes}
        tree, visited = [], set()
        def walk(pid: int, depth: int = 0):
            if pid in visited or pid not in pmap: return
            visited.add(pid)
            p = pmap[pid]
            tree.append({"pid": pid, "ppid": p["ppid"], "name": p["name"],
                         "cmdline": p["cmdline"], "depth": depth, "children": []})
            for cp in sorted([c["pid"] for c in self.all_processes if c["ppid"] == pid]):
                walk(cp, depth + 1)
        roots = sorted([p["pid"] for p in self.all_processes if p["ppid"] not in pmap or p["ppid"] == p["pid"]])
        for r in roots: walk(r)
        self.tree = tree
        return tree

    def get_process_by_name(self, name: str) -> List[Dict]:
        return [p for p in self.all_processes if name.lower() in p["name"].lower()]

    def detect_suspicious_parent_child(self) -> List[Dict[str, Any]]:
        findings, pmap = [], {p["pid"]: p for p in self.all_processes}
        for p in self.all_processes:
            parent = pmap.get(p["ppid"])
            if not parent: continue
            pn, cn = parent["name"].lower(), p["name"].lower()
            for pat in SUSPICIOUS_PARENT_CHILD:
                pm = any(k in pn for k in pat["parent_keywords"])
                cm = any(k in cn for k in pat["child_keywords"])
                if pm and cm:
                    f = {"type": "suspicious_parent_child",
                         "name": f"{parent['name']} (PID:{p['ppid']}) -> {p['name']} (PID:{p['pid']})",
                         "parent_pid": p["ppid"], "parent_name": parent["name"],
                         "child_pid": p["pid"], "child_name": p["name"],
                         "parent_cmdline": parent.get("cmdline", ""),
                         "child_cmdline": p.get("cmdline", ""),
                         "risk": pat["risk"], "description": pat["description"]}
                    findings.append(f); self._add(f); break
        return findings

    def detect_suspicious_process_names(self) -> List[Dict[str, Any]]:
        findings = []
        for p in self.all_processes:
            n, nx = p["name"].lower(), p["name"].lower().replace(".exe", "")
            for pat in SUSPICIOUS_PROCESS_NAMES:
                if pat["name"] in n or pat["name"] in nx:
                    f = {"type": "suspicious_process_name",
                         "name": f"{p['name']} (PID:{p['pid']})", "pid": p["pid"],
                         "cmdline": p.get("cmdline", ""),
                         "risk": pat["risk"], "description": pat["description"]}
                    findings.append(f); self._add(f); break
        return findings

    def detect_temp_directory_processes(self) -> List[Dict[str, Any]]:
        findings = []
        t = [os.environ.get("TEMP", "").lower(), os.environ.get("TMP", "").lower(),
             "/tmp", "/var/tmp", "\\temp\\", "\\tmp\\"]
        for p in self.all_processes:
            path = p.get("path", p.get("cmdline", "")).lower()
            if any(d in path for d in t if d) and p["name"].lower() not in (
                "setup.exe", "installer.exe", "msiexec.exe", "unins000.exe"):
                f = {"type": "temp_directory_process",
                     "name": f"{p['name']} (PID:{p['pid']})", "pid": p["pid"],
                     "path": path, "cmdline": p.get("cmdline", ""),
                     "risk": "MEDIUM", "description": f"Process running from temp: {p['name']}"}
                findings.append(f); self._add(f)
        return findings

    def run_all(self) -> List[Dict[str, Any]]:
        self.emitter.scan_started("process_tree")
        start = time.time()
        self.findings = []
        if not self.all_processes: self.enumerate_processes()
        self.build_tree()
        self.detect_suspicious_parent_child()
        self.detect_suspicious_process_names()
        self.detect_temp_directory_processes()
        self.emitter.scan_completed("process_tree", len(self.findings), (time.time() - start) * 1000)
        return self.findings

    def get_process_count(self) -> int:
        return len(self.all_processes)

    def get_tree_depth(self) -> int:
        if not self.tree: return 0
        return max(n.get("depth", 0) for n in self.tree)

# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Process Tree Tracking Tool")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    parser.add_argument("--tree", action="store_true", help="Show process hierarchy")
    parser.add_argument("--parent-child", action="store_true", help="Detect suspicious parent-child pairs")
    parser.add_argument("--names", action="store_true", help="Detect suspicious process names")
    parser.add_argument("--temp", action="store_true", help="Detect processes in temp directories")
    parser.add_argument("--output", "-o", help="Save report to file")
    parser.add_argument("--format", "-f", choices=["json", "text"], default="text")
    args = parser.parse_args()

    if not any([args.all, args.tree, args.parent_child, args.names, args.temp]):
        parser.print_help(); sys.exit(1)

    emitter = EventEmitter()
    tracker = ProcessTreeTracker(emitter=emitter)
    tracker.enumerate_processes()
    tracker.build_tree()

    if args.all:
        results = tracker.run_all()
    else:
        results = []
        if args.parent_child: results.extend(tracker.detect_suspicious_parent_child())
        if args.names: results.extend(tracker.detect_suspicious_process_names())
        if args.temp: results.extend(tracker.detect_temp_directory_processes())

    report = Report()
    report.add_findings(results)
    report.set_process_tree(tracker.tree)

    if args.tree or args.all:
        print(f"\nTotal processes: {tracker.get_process_count()}")
        print(f"Tree depth: {tracker.get_tree_depth()}")
        print("\nProcess hierarchy (showing up to 50 nodes):")
        for node in tracker.tree[:50]:
            print(f"{'  ' * node.get('depth', 0)}|-  {node['name']} (PID: {node['pid']})")

    if args.format == "json":
        print(report.to_json())
    else:
        print(report.to_text())

    if args.output:
        report.save(args.output, fmt=args.format)
        print(f"\nReport saved to {args.output}")

if __name__ == "__main__":
    main()
