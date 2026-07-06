"""
Silent Deployment Feature
Detects if the cybersecurity agent is running silently in the background.

This module identifies stealth characteristics of the current process,
including window visibility, startup type, and process information.
Useful for detecting covert execution patterns and monitoring agent behavior.
"""

import os
import sys
import subprocess
import psutil
from typing import Dict, Any


def run(send_event):
    """
    Main function to detect silent background deployment.
    
    Args:
        send_event: Callback function to report detection results.
                   Called with event data dictionary.
    
    Returns:
        dict: Dictionary containing deployment stealth indicators:
            - no_window: bool - True if process has no visible window
            - hidden: bool - True if process is hidden from user
            - startup_type: str - Process startup mode (system/user/background)
            - process_id: int - Current process ID
            - process_name: str - Name of the running process
            - parent_process: str - Name of parent process
            - is_silent: bool - Overall assessment of silent deployment
    """
    
    try:
        # Collect deployment information
        deployment_info = _detect_silent_deployment()
        
        # Send results via callback
        if send_event:
            send_event({
                'feature': 'silent_deployment',
                'status': 'success',
                'data': deployment_info
            })
        
        return deployment_info
        
    except Exception as e:
        # Handle errors gracefully without crashing
        error_info = {
            'feature': 'silent_deployment',
            'status': 'error',
            'error': str(e),
            'data': {
                'no_window': False,
                'hidden': False,
                'startup_type': 'unknown',
                'process_id': os.getpid(),
                'process_name': 'unknown',
                'parent_process': 'unknown',
                'is_silent': False
            }
        }
        
        if send_event:
            send_event(error_info)
        
        return error_info['data']


def _detect_silent_deployment() -> Dict[str, Any]:
    """
    Detect silent deployment characteristics.
    
    Returns:
        dict: Dictionary with deployment detection results
    """
    
    try:
        # Get current process information
        current_pid = os.getpid()
        current_process = psutil.Process(current_pid)
        
        # Initialize detection flags
        no_window = _detect_no_window()
        hidden = _detect_hidden_process()
        startup_type = _detect_startup_type()
        process_name = current_process.name()
        
        # Get parent process name
        try:
            parent_process_name = current_process.parent().name()
        except (psutil.NoSuchProcess, AttributeError):
            parent_process_name = "unknown"
        
        # Assess overall silent deployment status
        is_silent = no_window or hidden or startup_type in ['system', 'background']
        
        return {
            'no_window': no_window,
            'hidden': hidden,
            'startup_type': startup_type,
            'process_id': current_pid,
            'process_name': process_name,
            'parent_process': parent_process_name,
            'is_silent': is_silent
        }
        
    except Exception as e:
        # Return safe defaults on any error
        raise RuntimeError(f"Failed to detect silent deployment: {str(e)}")


def _detect_no_window() -> bool:
    """
    Detect if process has no visible window.
    
    Returns:
        bool: True if process appears to have no window
    """
    
    try:
        # Windows-specific check for console window
        if sys.platform == 'win32':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                
                # Get current process handle
                process_handle = kernel32.GetCurrentProcess()
                
                # Check if window title is empty (hidden process characteristic)
                # This is a reliable indicator on Windows
                try:
                    import win32gui
                    window = win32gui.GetForegroundWindow()
                    if window == 0:
                        return True
                except (ImportError, Exception):
                    # Fallback: check if running without a console
                    pass
                
                # Check for console window attachment
                console_window = kernel32.GetConsoleWindow()
                if console_window == 0:
                    return True
                    
            except (AttributeError, Exception):
                pass
        
        # Check environment variables for common GUI indicators
        if 'DISPLAY' not in os.environ and sys.platform != 'win32':
            return True
        
        return False
        
    except Exception:
        # Safe failure - assume window exists
        return False


def _detect_hidden_process() -> bool:
    """
    Detect if process is hidden from user view.
    
    Returns:
        bool: True if process appears hidden
    """
    
    try:
        current_pid = os.getpid()
        
        # Windows-specific hidden attribute check
        if sys.platform == 'win32':
            try:
                import ctypes
                import os.path
                
                # Get process executable path
                process = psutil.Process(current_pid)
                exe_path = process.exe()
                
                # Check file attributes for hidden flag
                attrs = ctypes.windll.kernel32.GetFileAttributesW(exe_path)
                FILE_ATTRIBUTE_HIDDEN = 2
                
                if attrs != -1 and (attrs & FILE_ATTRIBUTE_HIDDEN):
                    return True
                    
            except (AttributeError, OSError, Exception):
                pass
        
        # Check process name for common hidden process patterns
        try:
            process = psutil.Process(current_pid)
            process_name = process.name().lower()
            
            # Common hidden/background process patterns
            hidden_patterns = ['svchost', 'services', 'system', 'csrss', 'lsass']
            if any(pattern in process_name for pattern in hidden_patterns):
                return True
                
        except psutil.NoSuchProcess:
            pass
        
        return False
        
    except Exception:
        # Safe failure - assume visible
        return False


def _detect_startup_type() -> str:
    """
    Detect process startup type/mode.
    
    Returns:
        str: Startup type - 'user', 'system', 'background', or 'unknown'
    """
    
    try:
        current_pid = os.getpid()
        process = psutil.Process(current_pid)
        
        # Check if running as system process (PID 0-1000 typically)
        if current_pid < 1000:
            return 'system'
        
        # Check if running with elevated privileges (system indication)
        try:
            if sys.platform == 'win32':
                import ctypes
                if ctypes.windll.shell32.IsUserAnAdmin():
                    return 'system'
        except (AttributeError, Exception):
            pass
        
        # Check parent process for startup indicators
        try:
            parent = process.parent()
            parent_name = parent.name().lower()
            
            # System startup processes
            if any(x in parent_name for x in ['services', 'svchost', 'system']):
                return 'system'
            
            # Background/daemon indicators
            if any(x in parent_name for x in ['daemon', 'background', 'init']):
                return 'background'
                
        except (psutil.NoSuchProcess, AttributeError):
            pass
        
        # Check if parent is system shell or terminal
        try:
            parent = process.parent()
            if parent.pid == 1:
                return 'system'
        except (psutil.NoSuchProcess, AttributeError):
            pass
        
        # Default to user-initiated startup
        return 'user'
        
    except Exception:
        # Safe failure
        return 'unknown'


def get_detailed_process_info() -> Dict[str, Any]:
    """
    Get detailed information about current process (helper function).
    
    Returns:
        dict: Detailed process information
    """
    
    try:
        current_pid = os.getpid()
        process = psutil.Process(current_pid)
        
        return {
            'pid': current_pid,
            'name': process.name(),
            'exe': process.exe(),
            'cmdline': ' '.join(process.cmdline()),
            'status': process.status(),
            'create_time': process.create_time(),
            'num_threads': process.num_threads(),
            'memory_info': dict(process.memory_info()._asdict()) if process.memory_info() else {},
        }
        
    except Exception as e:
        return {'error': str(e)}


if __name__ == '__main__':
    # Example usage
    def example_callback(event):
        print(f"Event received: {event}")
    
    print("Running Silent Deployment Detection...")
    print("=" * 60)
    
    result = run(example_callback)
    
    print("\nDetection Results:")
    print("-" * 60)
    for key, value in result.items():
        print(f"{key:20s}: {value}")
    
    print("\n" + "=" * 60)
    print("Detailed Process Information:")
    print("-" * 60)
    detailed = get_detailed_process_info()
    for key, value in detailed.items():
        print(f"{key:20s}: {value}")
