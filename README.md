UrbanNusaCyberKivy
==================

Simple defensive antivirus/anti-phishing prototype using Kivy + Python.

Features
- Scan folder for .apk, .doc/.docx, .zip
- Static checks (suspicious strings)
- SHA256 computation + local signature DB
- Optional VirusTotal lookup (configure _vt_api_key in signatures.json)
- Quarantine (move to app private folder)
- Report/log saved to app data

Build instructions (recommended on PC with Ubuntu):
1. Install dependencies and Buildozer:
   sudo apt update && sudo apt install -y python3-pip build-essential git \
       python3 python3-pip openjdk-17-jdk unzip
   pip3 install --upgrade buildozer
2. In project root:
   buildozer android debug
3. Result APK in bin/ or app/build/outputs/apk/

If building on phone (Termux), use proot-distro Ubuntu then follow same steps (advanced, slow).

Notes & limitations
- This app performs static checks and hash lookups only. It does NOT run or execute scanned files.
- VirusTotal lookup sends hash or encoded URL to VT API; files are NOT uploaded.
- For broad filesystem access on Android 11+, MANAGE_EXTERNAL_STORAGE may be required.
- Keep VT API key secret; do NOT commit to public repos.

License: MIT (FOSS)# UrbanNusaCyberr-
# UrbanNusaCyberr-
