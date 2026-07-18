import platform
import time

def run(send_event):
    """
    F22: Registry Monitoring (Windows Run Keys)
    """

    if platform.system().lower() != "windows":
        return

    try:
        import winreg

        path = r"Software\Microsoft\Windows\CurrentVersion\Run"

        previous = {}

        while True:
            try:
                reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)

                current = {}
                i = 0

                while True:
                    try:
                        name, value, _ = winreg.EnumValue(reg, i)
                        current[name] = value
                        i += 1
                    except OSError:
                        break

                winreg.CloseKey(reg)

                added = {k: v for k, v in current.items() if k not in previous}

                if added:
                    send_event(
                        "registry_monitoring",
                        22,
                        {
                            "added_keys": added,
                            "os": "windows"
                        },
                        "medium"
                    )

                previous = current
                time.sleep(10)

            except Exception:
                time.sleep(10)

    except Exception:
        pass