import platform
import subprocess

try:
    import wmi   # Windows USB detection
except ImportError:
    wmi = None

def run(send_event):
    """
    Runs automatically every X minutes.
    Collects USB device info + Disk encryption status.
    """

    data = {}

    try:
        # STEP 1: USB Device Control
        if platform.system() == "Windows" and wmi:
            c = wmi.WMI()
            usb_devices = []
            for usb in c.Win32_USBControllerDevice():
                try:
                    device = usb.Dependent
                    usb_devices.append(str(device))
                except Exception:
                    continue

            data["usb_devices"] = usb_devices
                        # Example allow-list check (simplified)
            allowed_list = ["Logitech USB Keyboard", "Microsoft USB Mouse"]
            blocked = [d for d in usb_devices if not any(a in d for a in allowed_list)]
            data["blocked_devices"] = blocked
            data["usb_control_ok"] = len(blocked) == 0

        elif platform.system() == "Linux":
            # Check /sys/bus/usb/devices
            try:
                lsusb = subprocess.run(["lsusb"], capture_output=True, text=True)
                usb_devices = lsusb.stdout.splitlines()
                data["usb_devices"] = usb_devices
                # Simplified allow-list
                allowed_list = ["Logitech", "Microsoft"]
                blocked = [d for d in usb_devices if not any(a in d for a in allowed_list)]
                data["blocked_devices"] = blocked
                data["usb_control_ok"] = len(blocked) == 0
            except Exception:
                data["usb_devices"] = []
                data["usb_control_ok"] = False

        # STEP 2: Disk Encryption Check
        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ["manage-bde", "-status", "C:"],
                    capture_output=True, text=True
                )
                encrypted = "Protection On" in result.stdout
                data["drive"] = "C:"
                data["encrypted"] = encrypted
                data["method"] = "BitLocker"
                data["protection_on"] = encrypted
            except Exception:
                data["encrypted"] = False

        elif platform.system() == "Linux":
            try:
                result = subprocess.run(
                    ["lsblk", "-o", "NAME,MOUNTPOINT"],
                    capture_output=True, text=True
                )
                encrypted = "crypt" in result.stdout
                data["drive"] = "/"
                data["encrypted"] = encrypted
                data["method"] = "LUKS"
                data["protection_on"] = encrypted
            except Exception:
                data["encrypted"] = False

    except Exception as e:
        data["error"] = str(e)

    # STEP 3: Send Event
    send_event(
        event_type="usb_disk_control",
        feature_id=14,
        data=data,
        severity="HIGH" if not data.get("encrypted", False) or not data.get("usb_control_ok", True) else "INFO"
    )

