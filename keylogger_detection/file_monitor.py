from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os

SUSPICIOUS_EXTENSIONS = [".log", ".txt"]
SUSPICIOUS_DIRECTORIES = ["temp", "appdata", "local"]


class SuspiciousFileHandler(FileSystemEventHandler):
    def __init__(self):
        self.alerts = []

    def on_modified(self, event):
        if event.is_directory:
            return

        file_path = event.src_path.lower()

        for ext in SUSPICIOUS_EXTENSIONS:
            if file_path.endswith(ext):
                for directory in SUSPICIOUS_DIRECTORIES:
                    if directory in file_path:
                        self.alerts.append({
                            "file": event.src_path,
                            "reason": "frequent modification of log file in suspicious directory"
                        })


def monitor_files(duration=10):
    """
    monitors filesystem activity for suspicious file modifications
    commonly associated with keylogger logging behavior.
    """

    event_handler = SuspiciousFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path=os.path.expanduser("~"), recursive=True)
    observer.start()

    try:
        time.sleep(duration)
    finally:
        observer.stop()
        observer.join()

    return event_handler.alerts
