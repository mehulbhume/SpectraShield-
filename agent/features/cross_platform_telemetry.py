# ==========================================================
# FEATURE NAME : Cross-Platform Telemetry
# FEATURE ID   : 11
# INTERN ID    : 2128
# ==========================================================

import platform
import socket
import uuid
import psutil
from datetime import datetime


def run(send_event):
    """
    Collects telemetry data from Windows/Linux/Mac
    and sends it using a unified JSON schema.
    """

    try:

        os_type = platform.system()

        data = {
            "schema_version": "1.0",
            "os_type": os_type,
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "processor": platform.processor(),
            "cpu_cores": psutil.cpu_count(logical=True),
            "ram_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
            "mac_address": hex(uuid.getnode()),
            "timestamp": datetime.utcnow().isoformat(),
            "format_valid": True,
            "fields_present": 10
        }

        send_event(
            event_type="cross_platform_telemetry",
            feature_id=11,
            data=data,
            severity="info"
        )

    except Exception as e:
        print(f"[Feature 11 Error] {e}")


# Temporary local testing
if __name__ == "__main__":

    def fake_send_event(event_type, feature_id, data, severity):
        print("EVENT SENT")
        print(data)

    run(fake_send_event)
