# Digital Forensics Toolkit — Implementation Plan

## Project Overview

A desktop/web-based forensic investigation toolkit that collects and analyzes digital evidence from a Windows system while maintaining evidence integrity through cryptographic hashing. Aligns with Digital Forensics and Incident Response (DFIR) workflows.

**Objectives:**
- Collect forensic artifacts
- Preserve evidence integrity
- Analyze browser and system artifacts
- Generate an investigation report

---

## 0. Project Setup & Architecture

```
forensic_toolkit/
├── main.py                 # GUI entry point
├── modules/
│   ├── hashing.py
│   ├── browser_analysis.py
│   ├── usb_analysis.py
│   ├── recent_files.py
│   ├── process_monitor.py
│   ├── startup_analysis.py
│   ├── event_logs.py
│   └── timeline.py
├── database/
│   ├── db_manager.py
│   └── schema.sql
├── reports/
│   └── report_generator.py
├── utils/
│   └── helpers.py
└── requirements.txt
```

**Core design principle:** Every module follows the same pattern — `collect() → return structured data → hash it → store in DB`. This consistency makes the timeline generator and report generator trivial to build later, since everything is uniformly structured.

**Install dependencies:**
```bash
pip install psutil pywin32 python-evtx pandas reportlab pillow
```

---

## 1. Database Schema

Build this first — every module writes into it.

```sql
-- schema.sql

CREATE TABLE evidence_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_type TEXT NOT NULL,      -- 'browser', 'usb', 'process', etc.
    source TEXT,                       -- e.g. 'Chrome', 'Registry'
    description TEXT,
    timestamp TEXT,                    -- ISO format, feeds the timeline
    raw_data TEXT,                     -- JSON blob of full details
    sha256_hash TEXT,                   -- hash of raw_data for integrity
    collected_at TEXT,                 -- when the tool collected it
    case_id TEXT
);

CREATE TABLE case_metadata (
    case_id TEXT PRIMARY KEY,
    investigator_name TEXT,
    case_name TEXT,
    start_time TEXT,
    target_system TEXT
);

CREATE TABLE file_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filepath TEXT,
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    file_size INTEGER,
    hashed_at TEXT
);
```

**Why this matters:** Every artifact gets hashed and timestamped the moment it's collected — this is the chain-of-custody story. When asked "how do you know your tool didn't alter evidence," point to this schema.

---

## 2. File Hashing Module

```python
# modules/hashing.py
import hashlib
import os

def hash_file(filepath):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):  # read in chunks - handles large files
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        'filepath': filepath,
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
        'file_size': os.path.getsize(filepath)
    }
```

**Key detail:** Reading in 8192-byte chunks instead of loading the whole file into memory means this works on multi-GB files without crashing.

---

## 3. Running Processes Module

```python
# modules/process_monitor.py
import psutil
from datetime import datetime

def collect_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'memory_info', 'create_time', 'exe']):
        try:
            info = proc.info
            processes.append({
                'pid': info['pid'],
                'name': info['name'],
                'parent_pid': info['ppid'],
                'memory_mb': round(info['memory_info'].rss / 1024 / 1024, 2) if info['memory_info'] else 0,
                'start_time': datetime.fromtimestamp(info['create_time']).isoformat(),
                'exe_path': info['exe']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue  # process ended or protected - skip gracefully
    return processes
```

**Talking point:** Handling `AccessDenied` and `NoSuchProcess` gracefully is the difference between a script that crashes on a real system and one that's actually usable.

---

## 4. Startup Programs Module (Registry-based)

```python
# modules/startup_analysis.py
import winreg

STARTUP_LOCATIONS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

SUSPICIOUS_PATHS = ['temp', 'appdata\\local\\temp', 'downloads']

def collect_startup_entries():
    entries = []
    for hive, path in STARTUP_LOCATIONS:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    is_suspicious = any(s in value.lower() for s in SUSPICIOUS_PATHS)
                    entries.append({
                        'name': name,
                        'command': value,
                        'registry_path': path,
                        'flagged_suspicious': is_suspicious
                    })
                    i += 1
                except OSError:
                    break  # no more values
        except FileNotFoundError:
            continue
    return entries
```

**Why flag "suspicious":** Malware commonly persists by running from `%TEMP%` or `AppData\Local\Temp` — legitimate software almost never does. This heuristic mirrors what real triage tools do as a first-pass filter.

---

## 5. Recent Files Module (Registry `RecentDocs`)

```python
# modules/recent_files.py
import winreg

def collect_recent_files():
    recent = []
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                if isinstance(value, bytes):
                    # RecentDocs stores null-terminated UTF-16 filename + MRU metadata
                    filename = value.split(b'\x00\x00')[0].decode('utf-16-le', errors='ignore')
                    recent.append({'filename': filename, 'raw_index': name})
                i += 1
            except OSError:
                break
    except FileNotFoundError:
        pass
    return recent
```

**Note:** The `RecentDocs` binary format is a legacy MRU (Most Recently Used) structure and is genuinely messy. Extracting the filename cleanly is enough for an MVP; full MRU parsing can be listed as a stretch goal.

---

## 6. USB Device Analysis Module (Registry `USBSTOR`)

```python
# modules/usb_analysis.py
import winreg

def collect_usb_history():
    devices = []
    path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        i = 0
        while True:
            try:
                device_class = winreg.EnumKey(key, i)  # e.g. "Disk&Ven_SanDisk&..."
                device_key = winreg.OpenKey(key, device_class)
                j = 0
                while True:
                    try:
                        serial = winreg.EnumKey(device_key, j)
                        subkey = winreg.OpenKey(device_key, serial)
                        friendly_name, _ = winreg.QueryValueEx(subkey, "FriendlyName")
                        devices.append({
                            'device_class': device_class,
                            'serial_number': serial,
                            'friendly_name': friendly_name
                        })
                        j += 1
                    except OSError:
                        break
                i += 1
            except OSError:
                break
    except FileNotFoundError:
        pass
    return devices
```

**Limitation to note:** `USBSTOR` doesn't directly store connection timestamps. For that, cross-reference the registry key's last-write time (via `winreg.QueryInfoKey`) or parse the `Properties` subkey timestamps. Listing this as a "future enhancement" demonstrates awareness of the artifact's real-world limitations.

---

## 7. Browser History Module

Browsers lock their SQLite databases while running — always copy the file first, then query the copy.

```python
# modules/browser_analysis.py
import sqlite3
import shutil
import os
from datetime import datetime, timedelta

CHROME_HISTORY_PATH = os.path.expanduser(
    r"~\AppData\Local\Google\Chrome\User Data\Default\History"
)

def chrome_timestamp_to_datetime(chrome_time):
    # Chrome stores time as microseconds since Jan 1, 1601 (Windows epoch)
    if chrome_time == 0:
        return None
    return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)

def collect_chrome_history():
    temp_copy = "chrome_history_copy.db"
    shutil.copy2(CHROME_HISTORY_PATH, temp_copy)  # copy since file is locked

    conn = sqlite3.connect(temp_copy)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT url, title, visit_count, last_visit_time
        FROM urls ORDER BY last_visit_time DESC
    """)

    history = []
    for url, title, visit_count, last_visit_time in cursor.fetchall():
        history.append({
            'url': url,
            'title': title,
            'visit_count': visit_count,
            'last_visited': chrome_timestamp_to_datetime(last_visit_time).isoformat() if last_visit_time else None
        })

    conn.close()
    os.remove(temp_copy)
    return history
```

**Two forensic principles baked into this module (best interview talking point in the project):**
1. **Never query the live file** — copy it first, since it's locked while the browser runs, and original evidence should never be touched directly.
2. **Chrome's timestamp epoch differs from Unix time** — microseconds since 1601, not 1970. Getting this conversion right (and knowing why it's different) is a genuine forensic detail.

Firefox uses `places.sqlite` with a similar copy-then-query approach, but its `moz_historyvisits` table uses standard Unix microseconds — worth mentioning as "handled two different browser timestamp epochs."

---

## 8. Windows Event Log Parsing (offline `.evtx`)

```python
# modules/event_logs.py
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

# Key Event IDs to look for
INTERESTING_EVENTS = {
    4624: "Successful Login",
    4625: "Failed Login",
    4720: "User Account Created",
    6416: "New External Device Recognized (USB)",
    1000: "Application Crash"
}

def parse_evtx(evtx_path):
    events = []
    with Evtx(evtx_path) as log:
        for record in log.records():
            xml_str = record.xml()
            root = ET.fromstring(xml_str)

            ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            event_id_elem = root.find('.//ns:EventID', ns)
            time_elem = root.find('.//ns:TimeCreated', ns)

            if event_id_elem is not None:
                event_id = int(event_id_elem.text)
                if event_id in INTERESTING_EVENTS:
                    events.append({
                        'event_id': event_id,
                        'description': INTERESTING_EVENTS[event_id],
                        'timestamp': time_elem.get('SystemTime') if time_elem is not None else None
                    })
    return events
```

**Why offline `.evtx` parsing instead of the live Event Log API:** Querying the live API means interacting with a running system service. Parsing an exported `.evtx` file directly is what real DFIR examiners do on disk images — non-invasive and repeatable. State this explicitly as a design decision.

**To get a test `.evtx` file:** Use PowerShell's `Get-WinEvent`, or point directly at `C:\Windows\System32\winevt\Logs\Security.evtx` (requires admin rights).

---

## 9. Timeline Generator

```python
# modules/timeline.py
import sqlite3

def generate_timeline(db_path, case_id):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT artifact_type, source, description, timestamp
        FROM evidence_items
        WHERE case_id = ? AND timestamp IS NOT NULL
        ORDER BY timestamp ASC
    """, (case_id,))

    timeline = []
    for artifact_type, source, description, timestamp in cursor.fetchall():
        timeline.append({
            'time': timestamp,
            'type': artifact_type,
            'source': source,
            'event': description
        })

    conn.close()
    return timeline
```

**Why this works cleanly:** Because the schema was designed upfront with a consistent `timestamp` field across every module, merging all artifacts into one sorted view is just a single `ORDER BY` query.

---

## 10. PDF Report Generation (ReportLab)

```python
# reports/report_generator.py
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf_report(case_info, timeline_data, output_path):
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(f"Forensic Investigation Report: {case_info['case_name']}", styles['Title']))
    elements.append(Paragraph(f"Investigator: {case_info['investigator_name']}", styles['Normal']))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Timeline of Events", styles['Heading2']))
    table_data = [['Time', 'Type', 'Source', 'Event']]
    table_data += [[e['time'], e['type'], e['source'], e['event']] for e in timeline_data]

    table = Table(table_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
    ]))
    elements.append(table)

    doc.build(elements)
```

---

## Build Order (Phased)

**Phase 1 — Core + Integrity (Week 1–2)**
- File hashing module (MD5/SHA1/SHA256)
- SQLite schema for evidence storage (with hash of every artifact — chain of custody)
- Basic Tkinter/PyQt shell to tie modules together

**Phase 2 — Collection Modules (Week 3–4)**
- Running processes (`psutil` — easiest win, do this first)
- Recent files (`RecentDocs` registry key + `pywin32`)
- Startup programs (`Run`/`RunOnce` registry keys + Startup folder scan)

**Phase 3 — The Hard/Impressive Stuff (Week 5–6)**
- Browser history (Chrome/Edge/Firefox SQLite parsing)
- USB device analysis (`USBSTOR` registry key)
- Event Log parsing (offline `.evtx` via `python-evtx`)

**Phase 4 — The Payoff Features (Week 7–8)**
- Timeline generator — merges all collected timestamps into one sorted view
- PDF report export via ReportLab
- CSV/JSON export

**If short on time, cut:** USB analysis and startup programs are "nice to have." Never cut hashing/integrity — that's the core differentiator vs. a plain script.

**Core four to prioritize:** Process monitor, browser history, event logs, timeline.

---

## Resume Bullet Points

> Built a Python-based digital forensics toolkit that collects and analyzes Windows system artifacts (browser history, USB devices, event logs, running processes) while preserving evidence integrity via cryptographic hashing (MD5/SHA-1/SHA-256)

> Developed an automated timeline reconstruction engine correlating multi-source forensic artifacts (login events, USB activity, file access) into a unified chronological investigation timeline

> Implemented offline Windows Event Log (.evtx) parsing to detect security-relevant events including failed login attempts, user account creation, and USB insertion, exportable as PDF/CSV/JSON forensic reports

**Keywords this unlocks for ATS scanning:** Digital Forensics, Incident Response, DFIR, Evidence Preservation, Chain of Custody, Windows Event Log Analysis, Python Automation, SQLite, Timeline Analysis.

---

## Portfolio / GitHub Checklist

- [ ] README with screenshots of the timeline view and a sample PDF report
- [ ] "Sample Investigation Walkthrough" section — a fake scenario (e.g., insider threat inserts USB, copies files, deletes them) showing the tool catching it end-to-end
- [ ] Explicit note that testing was done against synthetic/lab data only, never real user data
- [ ] Be ready to explain: why hashing matters for evidence integrity (legal chain of custody), and why offline `.evtx` parsing was chosen over live queries (forensic soundness)

---

## Future Enhancements

- Memory dump analysis
- Disk image analysis
- Full registry analysis
- YARA rule scanning
- Volatility integration
