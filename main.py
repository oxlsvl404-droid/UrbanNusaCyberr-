# main.py
# UrbanNusaCyberKivy - main app
# Kivy-based UI that uses scanner.py for scanning and service.py for background tasks.

import os
import json
import threading
from kivy.app import App
from kivy.lang import Builder
from kivy.properties import StringProperty, ListProperty
from kivy.clock import mainthread
from kivy.utils import platform
from scanner import scan_folder_json, scan_url_json, update_signatures_from_url
from datetime import datetime
from pathlib import Path
from shutil import move

KV_PATH = os.path.join("app", "ui.kv") if os.path.exists("app/ui.kv") else "ui.kv"
Builder.load_file(KV_PATH)

APP_DIR = os.path.expanduser("~/.urbannusa") if platform != "android" else "/data/user/0/org.urbannusa.cyber/files"
os.makedirs(APP_DIR, exist_ok=True)
LOG_FILE = os.path.join(APP_DIR, "scan_log.json")
QUARANTINE_DIR = os.path.join(APP_DIR, "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

def append_log(entry):
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except Exception:
            logs = []
    logs.append(entry)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)

class MainUI(App):
    status = StringProperty("Ready")
    results = ListProperty([])

    def build(self):
        return Builder.load_file(KV_PATH)

    def on_start(self):
        self.status = "Ready"

    def scan_folder(self, folder_path):
        self.status = "Scanning..."
        threading.Thread(target=self._scan_folder_thread, args=(folder_path,), daemon=True).start()

    def scan_url(self, url):
        self.status = "Scanning URL..."
        threading.Thread(target=self._scan_url_thread, args=(url,), daemon=True).start()

    def update_sigs(self, url):
        self.status = "Updating signatures..."
        threading.Thread(target=self._update_sigs_thread, args=(url,), daemon=True).start()

    def quarantine(self, path):
        try:
            fname = os.path.basename(path)
            dest = os.path.join(QUARANTINE_DIR, f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{fname}")
            move(path, dest)
            entry = {"action": "quarantine", "src": path, "dst": dest, "time": datetime.utcnow().isoformat()}
            append_log(entry)
            self._set_status("Quarantined: " + fname)
        except Exception as e:
            self._set_status("Quarantine failed: " + str(e))

    def _scan_folder_thread(self, folder):
        try:
            s = scan_folder_json(folder)
            data = json.loads(s)
            for item in data:
                entry = {"time": datetime.utcnow().isoformat(), "file": item.get("path"), "sha256": item.get("sha256"), "static": item.get("static"), "virustotal": item.get("virustotal")}
                append_log(entry)
            self._set_results(data)
            self._set_status("Scan complete: {} items".format(len(data)))
        except Exception as e:
            self._set_status("Scan error: " + str(e))

    def _scan_url_thread(self, url):
        try:
            s = scan_url_json(url)
            data = json.loads(s)
            append_log({"time": datetime.utcnow().isoformat(), "url_scan": data})
            self._set_results(data)
            self._set_status("URL scan done")
        except Exception as e:
            self._set_status("URL scan error: " + str(e))

    def _update_sigs_thread(self, url):
        try:
            ok = update_signatures_from_url(url)
            self._set_status("Signature update: " + ("ok" if ok else "failed"))
        except Exception as e:
            self._set_status("Update error: " + str(e))

    @mainthread
    def _set_status(self, text):
        self.status = text

    @mainthread
    def _set_results(self, items):
        self.results = items

if __name__ == "__main__":
    MainUI().run()