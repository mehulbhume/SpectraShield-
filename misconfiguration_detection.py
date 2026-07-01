# ============================================================================================================
# FEATURE NAME : Misconfiguration Detection
# FEATURE ID : 10
# INTERN ID : 2126
# ============================================================================================================
import platform
import subprocess

def run(send_event):
    """
    This function runs automatically every X minutes.
    send_event() is given to you — just call it with your data.
    """
    # == STEP 1: Collect your data ===========================================================================
    try:
        rdp_open = False
        firewall_off = False
        guest_account = False
        weak_password_policy = False
        
        current_os = platform.system()
        
        if current_os == "Windows":
            # 1. Check if RDP (port 3389) is listening
            try:
                netstat = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
                if "3389" in netstat.stdout and "LISTENING" in netstat.stdout:
                    rdp_open = True
            except Exception:
                pass
                
            # 2. Check if Guest Account is active
            try:
                net_accounts = subprocess.run(["net", "user", "Guest"], capture_output=True, text=True)
                if "Account active               Yes" in net_accounts.stdout:
                    guest_account = True
            except Exception:
                pass
                
            # 3. Check if Firewall is off
            try:
                firewall = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], capture_output=True, text=True)
                if "State                                 OFF" in firewall.stdout:
                    firewall_off = True
            except Exception:
                pass

        elif current_os == "Linux":
            # 1. Check ufw firewall status
            try:
                ufw_status = subprocess.run(["ufw", "status"], capture_output=True, text=True)
                if "inactive" in ufw_status.stdout.lower():
                    firewall_off = True
            except Exception:
                pass
            
            # Note: /etc/ssh/sshd_config parsing for weak settings can be added here

        data = {
            "rdp_open": rdp_open,
            "firewall_off": firewall_off,
            "guest_account": guest_account,
            "weak_password_policy": weak_password_policy
        }
        
        # Severity Condition: HIGH FOR EACH TRUE 
        severity = "info"
        if rdp_open or firewall_off or guest_account or weak_password_policy:
            severity = "high"

        # == STEP 2: Send it to the backend ================================================================
        send_event(
            event_type="misconfiguration_detection",
            feature_id=10,
            data_dict=data,
            severity=severity
        )
        
    except Exception as e:
        # Golden Rule #2: Always wrap OS calls in try/except. Never crash the main agent.
        pass
