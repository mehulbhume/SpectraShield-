from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time


WATCH_FOLDER = "sample_files"


class AVHandler(FileSystemEventHandler):

    def on_created(self, event):

        if event.is_directory:
            return

        print(f"\n[ALERT] New file detected: {event.src_path}")
        print("[INFO] Real-time protection triggered")


event_handler = AVHandler()

observer = Observer()

observer.schedule(
    event_handler,
    WATCH_FOLDER,
    recursive=True
)

observer.start()

print("===================================")
print("Real-Time Protection Started")
print(f"Monitoring Folder: {WATCH_FOLDER}")
print("===================================")

try:

    while True:
        time.sleep(1)

except KeyboardInterrupt:

    observer.stop()

observer.join()