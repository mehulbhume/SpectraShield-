import psutil
import time
from datetime import datetime

LOG_FILE = "security_log.txt"

SUSPICIOUS_PROCESSES = [
    "notepad.exe",
    "mimikatz.exe",
    "procdump.exe",
    "dumpert.exe"
]


def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log = f"[{timestamp}] {message}"

    print(log)

    with open(LOG_FILE, "a") as f:
        f.write(log + "\n")


print("===================================")
print("Credential Dumping Protection Started")
print("Monitoring Processes...")
print("===================================")

detected = set()

while True:

    try:

        for process in psutil.process_iter(["pid", "name"]):

            try:

                process_name = process.info["name"]

                if process_name:

                    if process_name.lower() in SUSPICIOUS_PROCESSES:

                        key = (
                            process.info["pid"],
                            process_name
                        )

                        if key not in detected:

                            detected.add(key)

                            log_event(
                                f"ALERT: Suspicious Process Detected -> "
                                f"{process_name} "
                                f"(PID={process.info['pid']})"
                            )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                pass

        time.sleep(5)

    except KeyboardInterrupt:

        print("\nProtection Stopped")
        break