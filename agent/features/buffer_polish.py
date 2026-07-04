import platform
import psutil
import time
import uuid

def get_mac():
    return hex(uuid.getnode())


def run(send_event):
    """
    F38: Buffer / Polish (Final system health snapshot)
    """

    try:
        while True:

            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()

            send_event(
                "buffer_polish",
                38,
                {
                    "os": platform.system(),
                    "hostname": platform.node(),
                    "cpu_usage": cpu,
                    "ram_used_gb": round(mem.used / (1024**3), 2),
                    "ram_total_gb": round(mem.total / (1024**3), 2),
                    "mac": get_mac(),
                    "status": "healthy"
                },
                "info"
            )

            time.sleep(30)

    except Exception:
        pass