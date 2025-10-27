# scanner.py
# UrbanNusaCyber - Local-only scanner (no API, no remote lookups)
# Features:
# - compute sha256 for files
# - match against local signatures.json (sha256 -> metadata)
# - static heuristic checks (strings inside APK/zip/docx/text)
# - simple pattern rules (regex) support in signatures
# - returns JSON strings so UI can parse easily

import os
import zipfile
import hashlib
import json
import re

# Config: local signatures file (sha256 -> meta) and optional pattern rules
SIGFILE = "signatures.json"

# Heuristic suspicious substrings
SUSPICIOUS_SUBSTRINGS = [
    "su", "superuser", "/proc/", "Runtime.getRuntime", "dexclassloader",
    "socket", "exec(", "eval(", "https://", "http://", "adb", "install", "dex"
]

# Load signatures (sha256 keys) and pattern rules
def load_signatures(path=SIGFILE):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Normalize: ensure patterns compiled
            patterns = data.get("_patterns", {})
            compiled = {}
            for name, pat in patterns.items():
                try:
                    compiled[name] = re.compile(pat, re.IGNORECASE)
                except Exception:
                    # ignore bad patterns
                    pass
            data["_compiled_patterns"] = compiled
            return data
    except Exception:
        return {"_compiled_patterns": {}}

SIGNATURES = load_signatures()

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def quick_static_checks(path):
    result = {"size": None, "suspicious_strings": [], "matched_patterns": []}
    try:
        result["size"] = os.path.getsize(path)
        # If zip/apk, inspect textual entries
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as z:
                for name in z.namelist():
                    # check entries that are likely text (manifest, xml, assets, etc.)
                    if name.lower().endswith(('.xml', '.txt', '.properties', '.json', '.manifest', '.smali', '.dex', '.js')):
                        try:
                            data = z.read(name).decode(errors="ignore").lower()
                        except Exception:
                            continue
                        # substring heuristics
                        for s in SUSPICIOUS_SUBSTRINGS:
                            if s in data and s not in result["suspicious_strings"]:
                                result["suspicious_strings"].append(s)
                        # pattern rules
                        for pname, cre in SIGNATURES.get("_compiled_patterns", {}).items():
                            try:
                                if cre.search(data) and pname not in result["matched_patterns"]:
                                    result["matched_patterns"].append(pname)
                            except Exception:
                                pass
        else:
            # non-zip file: scan first chunk as text
            try:
                with open(path, "rb") as f:
                    chunk = f.read(200000).decode(errors="ignore").lower()
                    for s in SUSPICIOUS_SUBSTRINGS:
                        if s in chunk and s not in result["suspicious_strings"]:
                            result["suspicious_strings"].append(s)
                    for pname, cre in SIGNATURES.get("_compiled_patterns", {}).items():
                        try:
                            if cre.search(chunk) and pname not in result["matched_patterns"]:
                                result["matched_patterns"].append(pname)
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)
    return result

def list_targets(root):
    # files to consider: APK, doc, docx, zip, jar, rar, xls, xlsx, pdf
    exts = ('.apk', '.doc', '.docx', '.zip', '.jar', '.rar', '.xls', '.xlsx', '.pdf', '.exe', '.bin')
    for dirpath, dirs, files in os.walk(root):
        for fname in files:
            if fname.lower().endswith(exts):
                yield os.path.join(dirpath, fname)

def scan_folder_json(root):
    out = []
    sigs = SIGNATURES
    for p in list_targets(root):
        item = {"path": p, "sha256": None, "signature_match": None, "static": None}
        try:
            item["sha256"] = sha256_file(p)
            # signature match
            meta = sigs.get(item["sha256"])
            if meta:
                item["signature_match"] = meta
            # static heuristics
            item["static"] = quick_static_checks(p)
            # if signature or suspicious heuristics exist, mark severity
            sev = None
            if item["signature_match"]:
                sev = item["signature_match"].get("severity", "high")
            elif item["static"].get("matched_patterns"):
                sev = "high"
            elif item["static"].get("suspicious_strings"):
                sev = "medium"
            else:
                sev = "clean"
            item["severity"] = sev
        except Exception as e:
            item["error"] = str(e)
        out.append(item)
    return json.dumps(out)

def scan_file_json(path):
    try:
        item = {"path": path, "sha256": None, "signature_match": None, "static": None}
        item["sha256"] = sha256_file(path)
        meta = SIGNATURES.get(item["sha256"])
        if meta:
            item["signature_match"] = meta
        item["static"] = quick_static_checks(path)
        if item["signature_match"]:
            item["severity"] = item["signature_match"].get("severity", "high")
        elif item["static"].get("matched_patterns"):
            item["severity"] = "high"
        elif item["static"].get("suspicious_strings"):
            item["severity"] = "medium"
        else:
            item["severity"] = "clean"
        return json.dumps([item])
    except Exception as e:
        return json.dumps([{"path": path, "error": str(e)}])

# Utility to reload signatures at runtime (local only)
def reload_signatures():
    global SIGNATURES
    SIGNATURES = load_signatures()
    return True

# Simple function to add a signature locally (sha256 -> meta)
def add_signature(sha256, meta):
    try:
        data = {}
        if os.path.exists(SIGFILE):
            with open(SIGFILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        data[sha256] = meta
        with open(SIGFILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        reload_signatures()
        return True
    except Exception:
        return False

# For backward-compat: expose functions by name
__all__ = [
    "scan_folder_json",
    "scan_file_json",
    "reload_signatures",
    "add_signature",
    "sha256_file",
]
