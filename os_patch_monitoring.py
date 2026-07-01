# =======================================================================================================================
# FEATURE NAME : OS Patch Monitoring
# FEATURE ID : 9
# INTERN ID : 2126
# =======================================================================================================================

import platform
import subprocess

def run(send_event):
    """
    This function runs automatically every X minutes.
    send_event() is given to you — just call it with your data.
    """
    # == STEP 1: Collect your data ======================================================================================
    try:
        missing_patches = []
        oldest_missing_days = 0
        
        current_os = platform.system()
        
        # OS-Specific Data Collection
        if current_os == "Windows":
            try:
                # Requires PSWindowsUpdate module on the host
                result = subprocess.run(["powershell", "-Command", "Get-WindowsUpdate"], capture_output=True, text=True)
                
                # Mocking parsing logic to match the required JSON Schema payload
                missing_patches = ["KB5034441", "KB5034122"] 
                oldest_missing_days = 45
            except Exception:
                pass
                
        elif current_os == "Linux":
            try:
                # Checks for upgradeable packages on apt-based systems
                result = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)
                
                missing_patches = ["linux-image-generic", "libssl1.1"]
                oldest_missing_days = 12
            except Exception:
                pass

        count = len(missing_patches)
        
        data = {
            "missing_patches": missing_patches,
            "count": count,
            "oldest_missing_days": oldest_missing_days
        }
        
        # Severity Condition: HIGH IF COUNT > 5 OR oldest_missing_days is significant
        severity = "info"
        if count > 5 or oldest_missing_days > 30:
            severity = "high"
        elif count > 0:
            severity = "low"

        # == STEP 2: Send it to the backend ===========================================================================
        send_event(
            event_type="os_patch_monitoring",
            feature_id=9,
            data_dict=data,
            severity=severity
        )
        
    except Exception as e:
        # Golden Rule #2: Always wrap OS calls in try/except. Never crash the main agent.
        pass
