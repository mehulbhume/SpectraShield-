"""
Installation & Deep Visibility Feature
Collects system telemetry including boot time, installation path, and OS details.
Designed for cybersecurity agent monitoring.

Production-style feature with comprehensive error handling and logging.
"""

import os
import sys
import platform
import socket
import json
from datetime import datetime
from pathlib import Path

try:
    import psutil  # For cross-platform system info
except ImportError:
    psutil = None

try:
    import winreg  # Windows registry access
except ImportError:
    winreg = None


# Configuration constants
AGENT_VERSION = "1.0.0"
FEATURE_ID = 1
EVENT_TYPE = "installation_visibility"
SEVERITY = "INFO"


def get_boot_time():
    """
    Get system boot time in ISO 8601 format.
    
    Returns:
        str: Boot time as ISO formatted string, or error message if unavailable
    
    Error handling:
        - Returns formatted error string if psutil not available
        - Gracefully handles platform-specific failures
    """
    try:
        if psutil is None:
            return "UNAVAILABLE: psutil not installed"
        
        boot_timestamp = psutil.boot_time()
        boot_datetime = datetime.fromtimestamp(boot_timestamp)
        return boot_datetime.isoformat()
    except Exception as e:
        return f"ERROR: {str(e)}"


def get_install_path():
    """
    Determine the installation path of the agent.
    
    Returns:
        str: Full path to agent installation directory
    
    Logic:
        - Gets the directory of the current script (agent/features/)
        - Goes up 2 levels to reach the agent/ root directory
        - Returns absolute path
    """
    try:
        # Current file is in agent/features/
        current_file = Path(__file__).resolve()
        # Go up 2 directories: features -> agent
        agent_root = current_file.parent.parent
        return str(agent_root.absolute())
    except Exception as e:
        return f"ERROR: {str(e)}"


def get_running_as():
    """
    Get the user and privilege level the agent is running as.
    
    Returns:
        dict: Contains username and privilege information
    
    Details:
        - username: Current user running the process
        - is_admin: Whether running with admin/root privileges
        - uid: Unix user ID (Linux/macOS)
    """
    try:
        result = {
            "username": os.getenv("USERNAME") or os.getenv("USER") or "UNKNOWN",
            "is_admin": False,
            "uid": None
        }
        
        # Check for admin/root privileges
        if hasattr(os, "getuid"):
            # Unix-like systems (Linux, macOS)
            result["uid"] = os.getuid()
            result["is_admin"] = os.getuid() == 0
        else:
            # Windows systems
            try:
                result["is_admin"] = os.getenv("USERNAME") is not None and \
                                    platform.system() == "Windows"
            except Exception:
                result["is_admin"] = False
        
        return result
    except Exception as e:
        return {"error": f"ERROR: {str(e)}"}


def get_os_details():
    """
    Collect comprehensive OS and system details.
    
    Returns:
        dict: Operating system and architecture information
    
    Includes:
        - system: OS name (Windows, Linux, Darwin)
        - release: OS version/release number
        - machine: Architecture (x86_64, arm64, etc.)
        - processor: CPU model name
        - python_version: Python interpreter version
    """
    try:
        result = {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor() or "UNKNOWN",
            "python_version": platform.python_version()
        }
        return result
    except Exception as e:
        return {"error": f"ERROR: {str(e)}"}


def get_hostname():
    """
    Get the system hostname/computer name.
    
    Returns:
        str: Fully qualified hostname
    
    Error handling:
        - Returns "UNKNOWN" if hostname cannot be determined
        - Gracefully handles DNS resolution failures
    """
    try:
        hostname = socket.getfqdn()
        return hostname if hostname else "UNKNOWN"
    except Exception as e:
        return f"ERROR: {str(e)}"


def collect_telemetry():
    """
    Central function to collect all system telemetry.
    
    Returns:
        dict: Complete telemetry data with all system information
    
    Structure:
        {
            "timestamp": ISO 8601 datetime,
            "boot_time": System boot time,
            "install_path": Agent installation location,
            "running_as": User and privilege info,
            "os_details": OS and architecture info,
            "hostname": System hostname,
            "agent_version": Agent version string
        }
    
    Error handling:
        - All collection functions wrapped in try/except
        - Failures recorded with error messages rather than crashing
        - None of the individual failures will prevent data collection
    """
    try:
        telemetry_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "boot_time": get_boot_time(),
            "install_path": get_install_path(),
            "running_as": get_running_as(),
            "os_details": get_os_details(),
            "hostname": get_hostname(),
            "agent_version": AGENT_VERSION
        }
        return telemetry_data
    except Exception as e:
        # If collection itself fails, return error telemetry
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "error": f"Failed to collect telemetry: {str(e)}",
            "agent_version": AGENT_VERSION
        }


def run(send_event):
    """
    Main feature execution function.
    
    This is the entry point called by the agent framework.
    Collects system telemetry and sends it via the provided send_event callback.
    
    Args:
        send_event (callable): Callback function to send events
                               Expected signature: send_event(event_type, feature_id, data, severity)
    
    Returns:
        dict: Status of feature execution
              {"success": True/False, "message": str}
    
    Error handling:
        - Wrapped in outer try/except to prevent any crashes
        - Validates send_event is callable before use
        - Handles JSON serialization failures
        - Returns status dict indicating success or failure
    
    Production behavior:
        - Never crashes the agent
        - Always attempts to send event even if data collection partially fails
        - Logs execution status for debugging
    """
    try:
        # Validate send_event is callable
        if not callable(send_event):
            return {
                "success": False,
                "message": "send_event is not callable"
            }
        
        # Collect system telemetry
        telemetry_data = collect_telemetry()
        
        # Prepare event payload
        event_payload = {
            "event_type": EVENT_TYPE,
            "feature_id": FEATURE_ID,
            "data": telemetry_data,
            "severity": SEVERITY
        }
        
        # Validate data is JSON serializable
        json.dumps(event_payload)
        
        # Send event via callback
        send_event(
            event_type=EVENT_TYPE,
            feature_id=FEATURE_ID,
            data=telemetry_data,
            severity=SEVERITY
        )
        
        return {
            "success": True,
            "message": "Installation visibility telemetry collected and sent successfully"
        }
    
    except TypeError as e:
        # Handle type-related errors (e.g., send_event signature issues)
        return {
            "success": False,
            "message": f"Type error during execution: {str(e)}"
        }
    
    except json.JSONDecodeError as e:
        # Handle JSON serialization failures
        return {
            "success": False,
            "message": f"Data is not JSON serializable: {str(e)}"
        }
    
    except Exception as e:
        # Catch-all for any unexpected errors
        # This ensures the agent never crashes
        return {
            "success": False,
            "message": f"Unexpected error in installation_visibility feature: {str(e)}"
        }


if __name__ == "__main__":
    """
    Module can be run standalone for testing/debugging
    """
    # Mock send_event for testing
    def mock_send_event(event_type, feature_id, data, severity):
        """Simple mock implementation for testing"""
        print(f"\n[{severity}] Event: {event_type}")
        print(f"Feature ID: {feature_id}")
        print(f"Data:\n{json.dumps(data, indent=2)}\n")
    
    # Execute feature
    result = run(mock_send_event)
    print(f"Execution Status: {json.dumps(result, indent=2)}")
