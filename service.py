# service.py
# Minimal background worker example - can be started from main to run periodic scans.
import time, threading
from scanner import scan_folder_json
import json, os

def periodic_scan(path, interval_seconds=3600, callback=None):
    def _run():
        while True:
            try:
                res = scan_folder_json(path)
                if callback:
                    callback(res)
                # optionally write to log file
            except Exception:
                pass
            time.sleep(interval_seconds)
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t