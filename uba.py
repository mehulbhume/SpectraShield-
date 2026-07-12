from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import time

MONITORED_FOLDER = "monitored_folder"
LOG_FILE = "activity_log.txt"

file_create_count = 0
file_delete_count = 0
risk_score = 0


def log_event(message):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log = f"[{timestamp}] {message}"

    print(log)

    with open(LOG_FILE, "a") as f:
        f.write(log + "\n")


class UBAHandler(FileSystemEventHandler):

    def on_created(self, event):

        global file_create_count
        global risk_score

        if event.is_directory:
            return

        file_create_count += 1

        log_event(
            f"FILE CREATED: {event.src_path}"
        )

        if file_create_count >= 5:

            risk_score += 25

            log_event(
                f"ALERT: Excessive File Creation Detected | Risk Score={risk_score}"
            )

    def on_deleted(self, event):

        global file_delete_count
        global risk_score

        if event.is_directory:
            return

        file_delete_count += 1

        log_event(
            f"FILE DELETED: {event.src_path}"
        )

        if file_delete_count >= 5:

            risk_score += 50

            log_event(
                f"ALERT: Excessive File Deletion Detected | Risk Score={risk_score}"
            )


event_handler = UBAHandler()

observer = Observer()

observer.schedule(
    event_handler,
    MONITORED_FOLDER,
    recursive=True
)

observer.start()

print("===================================")
print("User Behavior Analytics Started")
print(f"Monitoring: {MONITORED_FOLDER}")
print("===================================")

try:

    while True:
        time.sleep(1)

except KeyboardInterrupt:

    observer.stop()

observer.join()