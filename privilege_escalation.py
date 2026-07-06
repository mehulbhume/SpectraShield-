"""
Privilege Escalation Detection Feature for Agentic Security Tool

This module monitors both Windows and Linux systems for privilege escalation attempts
in real-time, detecting suspicious privilege assignments, token elevation, setuid binaries,
unexpected root processes, and sudoers file modifications.
"""

import platform
import subprocess
import os
import time
import xml.etree.ElementTree as ET
import ctypes
from datetime import datetime, timezone
from pathlib import Path
import json
import sys


# Windows-specific imports (only loaded on Windows)
try:
    import ctypes.wintypes as wintypes
except ImportError:
    pass


# Known safe setuid binaries for Linux
KNOWN_SAFE_SETUID = {
    '/usr/bin/sudo',
    '/usr/bin/su',
    '/bin/mount',
    '/bin/umount',
    '/usr/bin/passwd',
    '/usr/bin/newgrp',
    '/usr/bin/chsh',
    '/usr/bin/chfn'
}

# Known safe system processes that should run as root
KNOWN_SAFE_ROOT_PROCESSES = {
    'systemd',
    'kthreadd',
    'init',
    'rcu_sched',
    'migration',
    'watchdog',
    'sshd',
    'cron'
}

# High-risk privileges that indicate privilege escalation
HIGH_RISK_PRIVILEGES = {
    'SeDebugPrivilege',
    'SeTcbPrivilege',
    'SeImpersonatePrivilege',
    'SeAssignPrimaryTokenPrivilege'
}

SUDOERS_MODIFICATION_THRESHOLD = 300  # 5 minutes in seconds

# Global list to store all findings
FINDINGS = []


def log_output(message, level="INFO"):
    """Write output to console and file"""
    timestamp = datetime.now(timezone.utc).isoformat()
    output = f"[{timestamp}] [{level}] {message}"
    print(output)
    sys.stdout.flush()
    
    # Also append to file for persistence
    try:
        with open('/tmp/privilege_escalation.log', 'a') as f:
            f.write(output + '\n')
    except Exception:
        pass


def get_iso_timestamp():
    """Return current time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def check_windows_event_log(send_event):
    """
    Monitor Windows Event Log for privilege escalation indicators.
    
    Checks Event IDs:
    - 4672: Special privileges assigned to new logon
    - 4688: New process created with elevated token
    """
    try:
        log_output("Starting Windows Event Log monitoring for privilege escalation", "INFO")
        
        # Query Event ID 4672 (Special privileges assigned to new logon)
        cmd_4672 = [
            'wevtutil', 'qe', 'Security',
            '/q:*[System[(EventID=4672)]]',
            '/c:20',
            '/f:xml',
            '/rd:true'
        ]
        
        result = subprocess.run(
            cmd_4672,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 and result.stdout:
            log_output(f"Event ID 4672 query successful, parsing results", "DEBUG")
            _parse_event_log_xml(result.stdout, send_event)
        else:
            log_output(f"Event ID 4672 query returned code {result.returncode}", "WARNING")
        
        # Query Event ID 4688 (New process created)
        cmd_4688 = [
            'wevtutil', 'qe', 'Security',
            '/q:*[System[(EventID=4688)]]',
            '/c:20',
            '/f:xml',
            '/rd:true'
        ]
        
        result = subprocess.run(
            cmd_4688,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 and result.stdout:
            log_output(f"Event ID 4688 query successful, parsing results", "DEBUG")
            _parse_process_creation_xml(result.stdout, send_event)
        else:
            log_output(f"Event ID 4688 query returned code {result.returncode}", "WARNING")
            
    except subprocess.TimeoutExpired:
        log_output("Windows Event Log query timed out", "ERROR")
    except Exception as e:
        log_output(f"Windows Event Log check failed: {str(e)}", "ERROR")


def _parse_event_log_xml(xml_text, send_event):
    """
    Parse Event ID 4672 XML output from Windows Event Log.
    
    Extracts privilege information and flags high-risk privileges.
    """
    try:
        root = ET.fromstring(xml_text)
        event_count = 0
        flag_count = 0
        
        for event in root.findall('.//Event'):
            event_count += 1
            timestamp_elem = event.find('.//TimeCreated')
            timestamp = timestamp_elem.get('SystemTime') if timestamp_elem is not None else get_iso_timestamp()
            
            # Extract user information
            subject_user = event.find('.//Data[@Name="SubjectUserName"]')
            subject_domain = event.find('.//Data[@Name="SubjectDomainName"]')
            user_name = f"{subject_domain.text if subject_domain is not None else 'UNKNOWN'}\\{subject_user.text if subject_user is not None else 'UNKNOWN'}"
            
            # Extract privilege list
            privilege_elem = event.find('.//Data[@Name="PrivilegeList"]')
            if privilege_elem is not None:
                privileges = privilege_elem.text or ""
                log_output(f"Event 4672 found for user {user_name} with privileges: {privileges}", "DEBUG")
                
                # Check for high-risk privileges
                for risk_priv in HIGH_RISK_PRIVILEGES:
                    if risk_priv in privileges:
                        flag_count += 1
                        data_dict = {
                            "check_type": "event_log",
                            "os": "windows",
                            "finding": f"Event ID 4672: High-risk privilege assigned to user {user_name}",
                            "process_name": "unknown",
                            "user": user_name,
                            "privilege": risk_priv,
                            "timestamp": timestamp,
                            "risk_reason": f"Privilege {risk_priv} enables critical system access and privilege escalation"
                        }
                        severity = "critical" if risk_priv in ['SeDebugPrivilege', 'SeTcbPrivilege'] else "high"
                        
                        log_output(f"ALERT [{severity}] Event 4672: {user_name} assigned privilege {risk_priv} - {data_dict['risk_reason']}", "ALERT")
                        print(f"\n{'='*80}")
                        print(f"PRIVILEGE ESCALATION DETECTED - SEVERITY: {severity.upper()}")
                        print(f"{'='*80}")
                        print(json.dumps(data_dict, indent=2))
                        print(f"{'='*80}\n")
                        sys.stdout.flush()
                        
                        FINDINGS.append({
                            'severity': severity,
                            'data': data_dict
                        })
                        
                        send_event('privilege_escalation', 33, data_dict, severity)
        
        if event_count > 0:
            log_output(f"Processed {event_count} Event 4672 events, flagged {flag_count} high-risk findings", "INFO")
                        
    except Exception as e:
        log_output(f"Error parsing Event 4672 XML: {str(e)}", "ERROR")


def _parse_process_creation_xml(xml_text, send_event):
    """
    Parse Event ID 4688 XML output from Windows Event Log.
    
    Detects suspicious process creation with elevated tokens.
    """
    try:
        root = ET.fromstring(xml_text)
        event_count = 0
        flag_count = 0
        
        for event in root.findall('.//Event'):
            event_count += 1
            timestamp_elem = event.find('.//TimeCreated')
            timestamp = timestamp_elem.get('SystemTime') if timestamp_elem is not None else get_iso_timestamp()
            
            # Extract process information
            new_process = event.find('.//Data[@Name="NewProcessName"]')
            parent_process = event.find('.//Data[@Name="ParentProcessName"]')
            subject_user = event.find('.//Data[@Name="SubjectUserName"]')
            
            new_proc_name = new_process.text if new_process is not None else "unknown"
            parent_proc_name = parent_process.text if parent_process is not None else "unknown"
            user_name = subject_user.text if subject_user is not None else "unknown"
            
            # Flag suspicious process creation from cmd.exe or powershell.exe
            parent_basename = os.path.basename(parent_proc_name).lower()
            if parent_basename in ['cmd.exe', 'powershell.exe'] and user_name.upper() != 'SYSTEM':
                # Additional check: is the new process name unusual/suspicious?
                suspicious_procs = ['system32', 'systemroot', 'cmd.exe', 'powershell.exe', 'svchost.exe']
                new_proc_basename = os.path.basename(new_proc_name).lower()
                
                if not any(susp in new_proc_basename for susp in suspicious_procs):
                    flag_count += 1
                    data_dict = {
                        "check_type": "event_log",
                        "os": "windows",
                        "finding": f"Event ID 4688: Suspicious process {new_proc_name} spawned from {parent_proc_name}",
                        "process_name": new_proc_name,
                        "user": user_name,
                        "privilege": "unknown",
                        "timestamp": timestamp,
                        "risk_reason": f"Non-system user {user_name} spawned unusual process from shell"
                    }
                    
                    log_output(f"ALERT [medium] Event 4688: Process {new_proc_name} spawned from {parent_proc_name} by {user_name}", "ALERT")
                    print(f"\n{'='*80}")
                    print(f"PRIVILEGE ESCALATION DETECTED - SEVERITY: MEDIUM")
                    print(f"{'='*80}")
                    print(json.dumps(data_dict, indent=2))
                    print(f"{'='*80}\n")
                    sys.stdout.flush()
                    
                    FINDINGS.append({
                        'severity': 'medium',
                        'data': data_dict
                    })
                    
                    send_event('privilege_escalation', 33, data_dict, "medium")
        
        if event_count > 0:
            log_output(f"Processed {event_count} Event 4688 events, flagged {flag_count} suspicious findings", "INFO")
                    
    except Exception as e:
        log_output(f"Error parsing Event 4688 XML: {str(e)}", "ERROR")


def check_windows_token_elevation(send_event):
    """
    Check if the current process has elevated privileges.
    
    Uses ctypes to call Windows API functions to detect token elevation.
    """
    try:
        # Only run on Windows
        if platform.system() != 'Windows':
            return
        
        log_output("Checking Windows process token elevation status", "INFO")
        
        # Windows API constants
        TOKEN_QUERY = 8
        TokenElevation = 20
        
        # Get current process handle
        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()
        
        # Open process token
        token = wintypes.HANDLE()
        if not kernel32.OpenProcessToken(current_process, TOKEN_QUERY, ctypes.byref(token)):
            log_output("Failed to open process token", "WARNING")
            return
        
        # Check token elevation
        elevation = wintypes.DWORD()
        elevation_size = wintypes.DWORD(ctypes.sizeof(elevation))
        
        if kernel32.GetTokenInformation(
            token,
            TokenElevation,
            ctypes.byref(elevation),
            elevation_size,
            ctypes.byref(elevation_size)
        ):
            # If elevation is 1, token is elevated
            if elevation.value == 1:
                log_output("Process token is elevated", "DEBUG")
                # Check if running user is admin (this is a simplified check)
                try:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                    if not is_admin:
                        # Unexpected elevation
                        data_dict = {
                            "check_type": "token_elevation",
                            "os": "windows",
                            "finding": "Current process has elevated token without admin privileges",
                            "process_name": os.path.basename(__file__),
                            "user": "unknown",
                            "privilege": "TokenElevation",
                            "timestamp": get_iso_timestamp(),
                            "risk_reason": "Process elevated without admin context - potential privilege escalation"
                        }
                        
                        log_output(f"ALERT [medium] Unexpected token elevation detected on non-admin user", "ALERT")
                        print(f"\n{'='*80}")
                        print(f"PRIVILEGE ESCALATION DETECTED - SEVERITY: MEDIUM")
                        print(f"{'='*80}")
                        print(json.dumps(data_dict, indent=2))
                        print(f"{'='*80}\n")
                        sys.stdout.flush()
                        
                        FINDINGS.append({
                            'severity': 'medium',
                            'data': data_dict
                        })
                        
                        send_event('privilege_escalation', 33, data_dict, "medium")
                except Exception as e:
                    log_output(f"Error checking admin status: {str(e)}", "WARNING")
            else:
                log_output("Process token is not elevated", "DEBUG")
        else:
            log_output("Failed to get token information", "WARNING")
        
        # Close token handle
        kernel32.CloseHandle(token)
        
    except Exception as e:
        log_output(f"Windows token elevation check failed: {str(e)}", "ERROR")


def check_linux_setuid_binaries(send_event):
    """
    Scan for setuid binaries on Linux systems.
    
    Uses find command to locate setuid bits and compares against known safe list.
    """
    try:
        log_output("Starting Linux setuid binary scan", "INFO")
        
        # Find all setuid binaries
        cmd = ['find', '/usr', '/bin', '/sbin', '-perm', '-4000', '-type', 'f']
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            stderr=subprocess.DEVNULL
        )
        
        if result.returncode == 0:
            setuid_binaries = [b.strip() for b in result.stdout.strip().split('\n') if b.strip()]
            log_output(f"Found {len(setuid_binaries)} total setuid binaries", "INFO")
            
            flag_count = 0
            for binary in setuid_binaries:
                if binary and binary not in KNOWN_SAFE_SETUID:
                    flag_count += 1
                    data_dict = {
                        "check_type": "setuid_scan",
                        "os": "linux",
                        "finding": f"Unexpected setuid binary detected: {binary}",
                        "process_name": binary,
                        "user": "root",
                        "privilege": binary,
                        "timestamp": get_iso_timestamp(),
                        "risk_reason": f"Setuid binary {binary} not in known safe list - possible privilege escalation vector"
                    }
                    
                    log_output(f"ALERT [high] Unexpected setuid binary: {binary}", "ALERT")
                    print(f"\n{'='*80}")
                    print(f"PRIVILEGE ESCALATION DETECTED - SEVERITY: HIGH")
                    print(f"{'='*80}")
                    print(json.dumps(data_dict, indent=2))
                    print(f"{'='*80}\n")
                    sys.stdout.flush()
                    
                    FINDINGS.append({
                        'severity': 'high',
                        'data': data_dict
                    })
                    
                    send_event('privilege_escalation', 33, data_dict, "high")
            
            log_output(f"Flagged {flag_count} suspicious setuid binaries", "INFO")
                    
        else:
            log_output(f"Setuid scan failed with return code {result.returncode}", "WARNING")
            
    except subprocess.TimeoutExpired:
        log_output("Linux setuid binary scan timed out", "ERROR")
    except Exception as e:
        log_output(f"Linux setuid binary scan failed: {str(e)}", "ERROR")


def check_linux_unexpected_root_processes(send_event):
    """
    Detect unexpected processes running as root on Linux.
    
    Reads /proc/*/status files to identify root processes outside known system processes.
    """
    try:
        log_output("Starting Linux unexpected root process scan", "INFO")
        
        proc_dir = Path('/proc')
        checked_count = 0
        flag_count = 0
        
        for pid_dir in proc_dir.iterdir():
            if not pid_dir.is_dir() or not pid_dir.name.isdigit():
                continue
            
            status_file = pid_dir / 'status'
            if not status_file.exists():
                continue
            
            checked_count += 1
            try:
                with open(status_file, 'r', encoding='utf-8', errors='ignore') as f:
                    status_content = f.read()
                
                # Extract process name
                process_name = None
                uid_line = None
                
                for line in status_content.split('\n'):
                    if line.startswith('Name:'):
                        process_name = line.split('\t')[1].strip() if '\t' in line else "unknown"
                    if line.startswith('Uid:'):
                        uid_line = line
                
                # Check if all UIDs are 0 (root)
                if uid_line and process_name:
                    uid_parts = uid_line.split('\t')[1].split() if '\t' in uid_line else []
                    
                    # uid format: real effective saved filesystem
                    if len(uid_parts) >= 4 and all(uid == '0' for uid in uid_parts):
                        # Check if it's a known safe root process
                        if process_name not in KNOWN_SAFE_ROOT_PROCESSES:
                            flag_count += 1
                            data_dict = {
                                "check_type": "root_process",
                                "os": "linux",
                                "finding": f"Unexpected root process detected: {process_name} (PID: {pid_dir.name})",
                                "process_name": process_name,
                                "user": "root",
                                "privilege": "uid=0",
                                "timestamp": get_iso_timestamp(),
                                "risk_reason": f"Process {process_name} running as root but not in known safe list"
                            }
                            
                            log_output(f"ALERT [medium] Unexpected root process: {process_name} (PID: {pid_dir.name})", "ALERT")
                            print(f"\n{'='*80}")
                            print(f"PRIVILEGE ESCALATION DETECTED - SEVERITY: MEDIUM")
                            print(f"{'='*80}")
                            print(json.dumps(data_dict, indent=2))
                            print(f"{'='*80}\n")
                            sys.stdout.flush()
                            
                            FINDINGS.append({
                                'severity': 'medium',
                                'data': data_dict
                            })
                            
                            send_event('privilege_escalation', 33, data_dict, "medium")
                            
            except Exception:
                pass
        
        log_output(f"Checked {checked_count} processes, flagged {flag_count} unexpected root processes", "INFO")
                
    except Exception as e:
        log_output(f"Linux unexpected root process scan failed: {str(e)}", "ERROR")


def check_linux_sudoers_changes(send_event):
    """
    Detect recent modifications to sudoers files.
    
    Checks modification times of /etc/sudoers and /etc/sudoers.d/* files.
    Flags recent changes as potential privilege escalation setup.
    """
    try:
        log_output("Checking Linux sudoers file modifications", "INFO")
        
        current_time = time.time()
        sudoers_files = ['/etc/sudoers']
        
        # Add all files in /etc/sudoers.d/
        sudoers_d = Path('/etc/sudoers.d')
        if sudoers_d.exists():
            try:
                for file_path in sudoers_d.iterdir():
                    if file_path.is_file():
                        sudoers_files.append(str(file_path))
            except Exception:
                pass
        
        flag_count = 0
        for file_path in sudoers_files:
            try:
                file_stat = os.stat(file_path)
                mod_time = file_stat.st_mtime
                time_diff = current_time - mod_time
                
                log_output(f"Sudoers file {file_path} last modified {int(time_diff)} seconds ago", "DEBUG")
                
                if time_diff < SUDOERS_MODIFICATION_THRESHOLD:
                    flag_count += 1
                    data_dict = {
                        "check_type": "sudoers_change",
                        "os": "linux",
                        "finding": f"Sudoers file recently modified: {file_path}",
                        "process_name": "sudoers",
                        "user": "root",
                        "privilege": "sudoers_modification",
                        "timestamp": get_iso_timestamp(),
                        "risk_reason": f"Sudoers file modified {int(time_diff)} seconds ago - possible privilege escalation setup"
                    }
                    
                    log_output(f"ALERT [high] Recent sudoers modification: {file_path} ({int(time_diff)}s ago)", "ALERT")
                    print(f"\n{'='*80}")
                    print(f"PRIVILEGE ESCALATION DETECTED - SEVERITY: HIGH")
                    print(f"{'='*80}")
                    print(json.dumps(data_dict, indent=2))
                    print(f"{'='*80}\n")
                    sys.stdout.flush()
                    
                    FINDINGS.append({
                        'severity': 'high',
                        'data': data_dict
                    })
                    
                    send_event('privilege_escalation', 33, data_dict, "high")
                    
            except Exception:
                pass
        
        log_output(f"Checked {len(sudoers_files)} sudoers files, flagged {flag_count} recent modifications", "INFO")
                
    except Exception as e:
        log_output(f"Sudoers modification check failed: {str(e)}", "ERROR")


def print_summary_report():
    """Print a summary report of all findings"""
    print(f"\n{'='*80}")
    print(f"PRIVILEGE ESCALATION DETECTION SUMMARY REPORT")
    print(f"{'='*80}")
    print(f"Total Findings: {len(FINDINGS)}")
    print(f"Timestamp: {get_iso_timestamp()}")
    print(f"Operating System: {platform.system()}")
    print(f"\n")
    
    # Group by severity
    critical = [f for f in FINDINGS if f['severity'] == 'critical']
    high = [f for f in FINDINGS if f['severity'] == 'high']
    medium = [f for f in FINDINGS if f['severity'] == 'medium']
    
    if critical:
        print(f"CRITICAL FINDINGS: {len(critical)}")
        for i, finding in enumerate(critical, 1):
            print(f"  [{i}] {finding['data']['finding']}")
    
    if high:
        print(f"HIGH FINDINGS: {len(high)}")
        for i, finding in enumerate(high, 1):
            print(f"  [{i}] {finding['data']['finding']}")
    
    if medium:
        print(f"MEDIUM FINDINGS: {len(medium)}")
        for i, finding in enumerate(medium, 1):
            print(f"  [{i}] {finding['data']['finding']}")
    
    if not FINDINGS:
        print("NO FINDINGS - System appears clean")
    
    print(f"\n{'='*80}\n")
    sys.stdout.flush()


def run(send_event):
    """
    Main entry point for privilege escalation detection.
    
    Dispatches checks based on the operating system.
    Prints all outputs to console and log file.
    
    Args:
        send_event: Callback function to report security events
                   Signature: send_event(event_type, event_id, data_dict, severity)
    """
    try:
        log_output(f"Starting privilege escalation detection scan", "INFO")
        current_os = platform.system()
        log_output(f"Detected operating system: {current_os}", "INFO")
        
        if current_os == 'Windows':
            # Windows-specific privilege escalation checks
            log_output("Running Windows-specific checks", "INFO")
            check_windows_event_log(send_event)
            check_windows_token_elevation(send_event)
            
        elif current_os == 'Linux':
            # Linux-specific privilege escalation checks
            log_output("Running Linux-specific checks", "INFO")
            check_linux_setuid_binaries(send_event)
            check_linux_unexpected_root_processes(send_event)
            check_linux_sudoers_changes(send_event)
        
        else:
            log_output(f"Unsupported operating system: {current_os}", "WARNING")
        
        # Print summary report
        print_summary_report()
        log_output(f"Privilege escalation detection scan completed", "INFO")
        
    except Exception as e:
        log_output(f"Fatal error in privilege escalation detection: {str(e)}", "ERROR")
        print(f"\nFATAL ERROR: {str(e)}\n")
        sys.stdout.flush()


# Example test function - can be run directly
if __name__ == '__main__':
    def dummy_send_event(event_type, event_id, data_dict, severity):
        """Dummy callback for testing"""
        pass
    
    print("Starting Privilege Escalation Detection Feature Test")
    print("=" * 80)
    run(dummy_send_event)
