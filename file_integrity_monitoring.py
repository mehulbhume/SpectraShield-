# =======================================================================================
# FEATURE NAME : File Integrity Monitoring
# FEATURE ID : 21
# INTERN ID : 2126
# =======================================================================================
import platform
import os
import hashlib

# Global state to remember file hashes between scheduled runs
_LAST_KNOWN_HASHES = {}

def run(send_event):
    """
    This function runs automatically every X minutes.
    send_event() is given to you — just call it with your data.
    """
    # ==== STEP 1: Collect your data ====================================================
    try:
        changed_files = []
        target_files = []
        
        current_os = platform.system()
        
        # Define highly sensitive files to monitor based on OS
        if current_os == "Windows":
            # Windows Hosts file (often targeted by malware for DNS redirection)
            target_files = [r"C:\Windows\System32\drivers\etc\hosts"]
        elif current_os == "Linux":
            # Linux user and password databases
            target_files = ["/etc/passwd", "/etc/shadow"]

        for filepath in target_files:
            if os.path.exists(filepath):
                # Read the file and generate a SHA-256 hash
                with open(filepath, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                # Compare current hash to the last known hash
                if filepath in _LAST_KNOWN_HASHES:
                    if _LAST_KNOWN_HASHES[filepath] != file_hash:
                        changed_files.append(filepath)
                        
                # Update the state for the next time the scheduler runs this function
                _LAST_KNOWN_HASHES[filepath] = file_hash

        changes_detected = len(changed_files) > 0
        
        data = {
            "monitored_files": target_files,
            "changes_detected": changes_detected,
            "changed_files": changed_files
        }
        
        # Severity Condition: FIM alerts on critical OS files indicate a likely breach
        severity = "info"
        if changes_detected:
            severity = "high"

        # == STEP 2: Send it to the backend ==============================================
        send_event(
            event_type="file_integrity_monitoring",
            feature_id=21,
            data_dict=data,
            severity=severity
        )
        
    except Exception as e:
        # Golden Rule #2: Always wrap OS calls in try/except. Never crash the main agent.
        pass
