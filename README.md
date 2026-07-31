<p align="center">
  <h1 align="center">🔍 TriageHound</h1>
  <p align="center">
    <strong>Advanced Digital Forensics & Incident Response Toolkit</strong><br>
    <em>Collect. Hunt. Prove. Seal.</em>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.11%20|%203.12%20|%203.13-blue?logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/platform-Windows%2010%20|%2011-0078D6?logo=windows&logoColor=white" alt="Platform">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
    <img src="https://img.shields.io/badge/interface-CLI%20%2B%20GUI-orange" alt="Interface">
  </p>
</p>

---

**TriageHound** is a modular, standalone Windows Incident Response toolkit for rapid live-system triage, advanced forensic artifact collection, and automated threat hunting.

It gathers volatile data, parses deep file-system artifacts to defeat anti-forensics, scans for malicious indicators using **YARA** and **Sigma** rules, and generates a **cryptographically sealed PDF report** for legal chain-of-custody.

> **Why "TriageHound"?** — In Incident Response, *triage* is the first 30 minutes on a compromised machine. Like a bloodhound tracking a scent, TriageHound follows every trace an attacker left behind — even the ones they tried to destroy.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Case Study: Insider Threat Walkthrough](#-case-study-insider-threat-walkthrough)
- [Screenshots](#-screenshots)
- [Quick Start](#-quick-start)
- [CLI Reference](#-cli-reference)
- [Project Architecture](#-project-architecture)
- [Sigma & YARA Rule Library](#-sigma--yara-rule-library)
- [Known Limitations & Error Handling](#-known-limitations--error-handling)
- [Environment & Compatibility](#-environment--compatibility)
- [License & Legal](#-license--legal)

---

## 🔥 Key Features

### Overlapping Artifact Collection (Anti-Forensics Resilience)

Real attackers don't leave evidence lying around. They delete malware, wipe Prefetch files, and clear event logs. TriageHound defeats this by collecting **redundant, overlapping proof** from multiple independent sources:

| Artifact | What It Proves | Survives Deletion Of... |
|---|---|---|
| **Prefetch** (`.pf` files) | Program was executed, how many times, and when | — |
| **ShimCache** (Registry) | Program was shimmed/executed by Windows | Prefetch files |
| **USN Journal** (`$UsnJrnl:$J`) | File was created/modified/deleted on disk | Prefetch + ShimCache |
| **Volume Shadow Copies** | Older versions of deleted files can be recovered | All of the above |

> 💡 **This is the single biggest differentiator.** Most student forensic tools only collect one of these. TriageHound collects all four, so even if an attacker defeats one artifact, the others still convict them.

### Automated Threat Hunting

| Engine | What It Does |
|---|---|
| **YARA** | Scans startup executables against malware signature rules (`.yar`) |
| **Sigma** | Evaluates Windows Event Logs against behavioral detection rules (`.yml`) |
| **VirusTotal** | Hashes processes/startup files → queries 70+ AV engines via API |

### Core Evidence Collection

- **Running Processes** — PID, name, CPU%, memory, username (via `psutil`)
- **Startup Programs** — Registry Run keys + Startup folders, with suspicious-flag heuristics
- **USB Device History** — Every USB device ever connected (serial numbers, device IDs)
- **Browser History** — Chrome, Edge, Firefox (URLs, titles, timestamps)
- **Recent Files** — Windows Recent Items from the Registry
- **Event Logs** — Full `.evtx` parsing with field-level extraction for Sigma matching

### Chain of Custody & Legal Defensibility

- **SHA-256 Cryptographic Sealing** — The final PDF report and SQLite database are hashed. A `seal_<CASE>.txt` manifest is generated so any tampering is instantly detectable.
- **Super Timeline** — All timestamps from every module are merged into a single chronological timeline, exportable to JSON/CSV for ingestion into tools like Timesketch or Splunk.
- **Audit Logging** — TriageHound logs its own execution actions for chain-of-custody integrity.

---

## 🕵️ Case Study: Insider Threat Walkthrough

> *This fictional scenario demonstrates TriageHound's capabilities against a realistic insider threat with anti-forensic countermeasures.*

### The Scenario

An employee at a financial firm is suspected of stealing sensitive client data. Before leaving the office, they:

1. ✅ Copied confidential `.xlsx` files to a personal USB drive.
2. 🗑️ Deleted the copied files from the desktop.
3. 🧹 Cleared the Windows Security Event Log to hide their tracks.
4. 🔥 Deleted the Prefetch files for `explorer.exe` and `xcopy.exe` to hide execution evidence.

The IR team plugs in a USB drive containing `TriageHound.exe` and runs a full triage.

### What TriageHound Finds

| Module | Evidence Recovered | Anti-Forensics Defeated? |
|---|---|---|
| **USB History** | Serial number `SanDisk_Ultra_4C530001231018` connected at 17:42 | N/A — attacker didn't wipe this |
| **Prefetch** | ❌ Empty — attacker deleted `.pf` files | Attacker wins this round |
| **ShimCache** | `xcopy.exe` found at cache position #3, last modified 17:38 | ✅ **Defeats Prefetch deletion** |
| **USN Journal** | `FILE_DELETE` entry for `client_financials_Q4.xlsx` at 17:45 | ✅ **Proves the file existed and was deleted** |
| **Sigma Engine** | 🚨 **CRITICAL: "Security Event Log Cleared" (Event ID 1102)** at 17:50 | ✅ **Catches the cover-up attempt** |
| **YARA** | No malware detected (this was insider theft, not malware) | N/A |

### The Verdict

Despite the attacker deleting Prefetch files AND clearing event logs, TriageHound reconstructed the full incident:

> *"At 17:38, `xcopy.exe` was executed (ShimCache). At 17:42, USB device `SanDisk_Ultra_4C530001231018` was connected. At 17:45, `client_financials_Q4.xlsx` was deleted from disk (USN Journal). At 17:50, the Security Event Log was cleared (Sigma Alert). The SHA-256 sealed report and database provide a tamper-evident evidence package for legal proceedings."*

**This is the story you tell in an interview.**

---

## 📸 Screenshots

> **Add your own screenshots here before publishing to GitHub!**

<!-- Uncomment and replace with your actual screenshots:
### GUI — Main Interface
![TriageHound GUI](screenshots/gui_main.png)

### PDF Report — Executive Summary
![PDF Report](screenshots/report_cover.png)

### PDF Report — YARA & Sigma Alerts
![Alert Section](screenshots/report_alerts.png)

### CLI — Full Triage Output
![CLI Output](screenshots/cli_output.png)
-->

*To add screenshots: run the tool, take screenshots of the GUI and PDF, save them in a `screenshots/` folder, and uncomment the lines above.*

---

## 🚀 Quick Start

### Option 1: Standalone `.exe` (Recommended for IR)

No Python installation required. Run from a USB drive on any Windows 10/11 machine.

```powershell
# Build the executable (one-time, on your dev machine)
.\build_exe.ps1

# Copy dist\DF_Toolkit\ folder to your USB drive
# Plug into target machine → Run DF_Toolkit.exe as Administrator
```

### Option 2: Run from Source

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/TriageHound.git
cd TriageHound

# Install pinned dependencies
pip install -r requirements.txt

# Launch the GUI
python gui.py

# Or run headless via CLI
python main.py --case INC-2026-001 --investigator "Your Name" --target "WORKSTATION-42" --yara-scan --shimcache
```

---

## 💻 CLI Reference

```bash
python main.py --case <CASE_ID> --investigator <NAME> --target <HOSTNAME> [OPTIONS]
```

| Flag | Description | Requires Admin? |
|---|---|---|
| `--case` | Unique case identifier (required) | No |
| `--investigator` | Analyst name for the report (required) | No |
| `--target` | Target system hostname (required) | No |
| `--yara-scan` | Scan startup executables against YARA rules | No |
| `--rules-dir <path>` | Custom YARA rules directory (default: `rules/`) | No |
| `--prefetch` | Parse Windows Prefetch files | **Yes** |
| `--shimcache` | Parse ShimCache (AppCompatCache) from registry | No |
| `--usn-journal` | Parse NTFS USN Journal for file system changes | **Yes** |
| `--evtx <path>` | Parse a Windows Event Log file (`.evtx`) | No |
| `--sigma-scan` | Run Sigma rules against parsed event logs | No (requires `--evtx`) |
| `--vt-api-key <key>` | VirusTotal API key for hash reputation lookups | No |
| `--vss` | Scan Volume Shadow Copies for deleted evidence | **Yes** |
| `--export-json` | Export timeline to JSON | No |
| `--export-csv` | Export timeline to CSV | No |

### Example: Full Investigation (as Administrator)

```powershell
python main.py --case INC-2026-042 `
    --investigator "Jane Doe" `
    --target "SRV-EXCHANGE-01" `
    --yara-scan --prefetch --shimcache --usn-journal `
    --evtx "C:\Windows\System32\winevt\Logs\Security.evtx" `
    --sigma-scan `
    --vt-api-key "YOUR_VT_API_KEY_HERE" `
    --export-json
```

---

## 🏗️ Project Architecture

```
TriageHound/
├── main.py                  # CLI entry point (headless automation)
├── gui.py                   # Multi-threaded Tkinter GUI
├── requirements.txt         # Version-pinned dependencies
├── DF_Toolkit.spec          # PyInstaller build spec
├── build_exe.ps1            # One-click .exe build script
│
├── modules/                 # Collection & analysis modules
│   ├── process_monitor.py   #   Running processes (psutil)
│   ├── recent_files.py      #   Recently accessed files (Registry)
│   ├── startup_analysis.py  #   Startup entries (Registry + folders)
│   ├── usb_analysis.py      #   USB device history (Registry)
│   ├── browser_analysis.py  #   Browser history (Chrome/Edge/Firefox)
│   ├── event_logs.py        #   Event log parser (.evtx) with full field extraction
│   ├── prefetch_parser.py   #   Windows Prefetch (.pf) parser
│   ├── shimcache_parser.py  #   ShimCache (AppCompatCache) registry parser
│   ├── usn_parser.py        #   NTFS USN Journal parser (raw ctypes IOCTL)
│   ├── vss_extractor.py     #   Volume Shadow Copy lister & scanner
│   ├── yara_scanner.py      #   YARA rule compiler & file scanner
│   ├── sigma_engine.py      #   Lightweight Sigma rule matcher
│   ├── virustotal.py        #   VirusTotal API v3 integration
│   ├── hashing.py           #   MD5/SHA1/SHA256 file hashing
│   ├── report_sealer.py     #   SHA-256 cryptographic sealing
│   └── timeline.py          #   Chronological timeline generator
│
├── database/
│   ├── db_manager.py        # SQLite ORM for evidence storage
│   └── schema.sql           # Database schema
│
├── reports/
│   └── report_generator.py  # Professional dark-themed PDF (ReportLab)
│
├── rules/                   # YARA malware signature rules (.yar)
│   └── sample_rules.yar
│
├── sigma_rules/             # Sigma behavioral detection rules (.yml)
│   ├── event_log_clearing.yml
│   ├── new_service_installed.yml
│   ├── scheduled_task_created.yml
│   ├── rdp_login.yml
│   └── user_account_created.yml
│
└── utils/
    └── helpers.py           # JSON/CSV export utilities
```

---

## 🛡️ Sigma & YARA Rule Library

### Sigma Rules (Behavioral Detection on Event Logs)

| Rule File | What It Detects | Severity | Why It Matters |
|---|---|---|---|
| `event_log_clearing.yml` | Security Event Log cleared (Event ID 1102) | **CRITICAL** | Classic anti-forensics — attacker trying to destroy evidence |
| `new_service_installed.yml` | New Windows service created (Event ID 7045) | HIGH | Common persistence mechanism for backdoors |
| `scheduled_task_created.yml` | Scheduled task registered (Event ID 4698) | HIGH | Persistence technique to survive reboots |
| `rdp_login.yml` | Remote Desktop login detected (Event ID 4624, Type 10) | MEDIUM | May indicate lateral movement within the network |
| `user_account_created.yml` | New local user account created (Event ID 4720) | HIGH | Attackers create backdoor accounts for persistent access |

### YARA Rules (Malware Signature Scanning)

| Rule | What It Detects | Severity |
|---|---|---|
| `SuspiciousPersistenceMechanism` | Executables with Run key or service-related strings | MEDIUM |
| `SuspiciousKeylogger` | Binaries containing keyboard hook API calls | HIGH |

> 💡 **Extend these!** Add your own `.yar` and `.yml` files to the `rules/` and `sigma_rules/` directories. TriageHound auto-discovers and loads them.

---

## ⚠️ Known Limitations & Error Handling

TriageHound is designed to **degrade gracefully**. If a module cannot access an artifact due to permissions or system configuration, it logs a warning and continues collecting everything else.

| Scenario | Behavior |
|---|---|
| **Not running as Administrator** | USN Journal, Prefetch, and VSS modules return empty results with a warning. All other modules (ShimCache, processes, browser, USB, YARA) work normally. |
| **USN Journal is disabled on target** | `collect_usn_journal()` returns an empty list. No crash. |
| **No `.evtx` file provided** | Sigma scan is skipped with a warning message. |
| **VirusTotal API rate limit hit** | Module auto-throttles to 4 requests/minute (free tier). Returns `rate_limited` status for excess hashes. |
| **VSS mount fails (permissions)** | `mount_shadow()` returns `False`. The shadow copy is skipped; others continue. |
| **`yara-python` not installed** | YARA scan is skipped entirely. A warning is printed. |
| **`pyyaml` not installed** | Sigma engine is skipped entirely. A warning is printed. |
| **Target has no shadow copies** | VSS module returns empty list. No crash. |
| **Corrupted Prefetch file** | Individual file is skipped via try/except. Other files continue parsing. |

---

## 🖥️ Environment & Compatibility

| Requirement | Supported |
|---|---|
| **Operating System** | Windows 10 (build 1809+), Windows 11 |
| **Python Version** | 3.11, 3.12, 3.13 |
| **Architecture** | x86-64 (64-bit) |
| **Privileges** | Standard user (partial collection) or Administrator (full collection) |
| **Disk Format** | NTFS (required for USN Journal and Prefetch) |

### Dependencies

All dependencies are version-pinned in `requirements.txt` for reproducible builds:

```
psutil==7.0.0          # Process enumeration
pywin32==310           # Windows Registry & API access
python-evtx==0.8.1     # Event Log (.evtx) parsing
pandas==2.2.3          # Timeline data handling
reportlab==5.0.0       # PDF report generation
pillow==11.2.1         # Image support for ReportLab
yara-python==4.5.4     # YARA malware scanning
PyYAML==6.0.3          # Sigma rule parsing
```

---

## 📜 License & Legal

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

### Authorized Use Only

TriageHound is a forensic investigation tool that accesses raw disk volumes, registry hives, and active system memory. **It must only be used on systems you own or are explicitly authorized to investigate.**

Unauthorized use of this tool on systems you do not own or have permission to investigate may violate local, state, and federal laws including but not limited to the Computer Fraud and Abuse Act (CFAA).

### Evidence Integrity

The SHA-256 cryptographic sealing feature provides tamper-evidence for collected artifacts. However, this tool is provided "as-is" and the authors make no guarantees about the admissibility of collected evidence in any legal proceeding. Always consult with legal counsel regarding evidence handling procedures in your jurisdiction.

---

## 🤝 Contributing

Contributions are welcome! To add new collection modules:

1. Create a new file in `modules/` following the `collect_*()` → `list[dict]` pattern.
2. Register the module in `main.py` (CLI flag) and `gui.py` (checkbox).
3. Add a report section in `reports/report_generator.py`.
4. Insert evidence via `db.insert_evidence()` using a unique `artifact_type`.

To add new detection rules:
- **YARA**: Drop `.yar` files into `rules/`
- **Sigma**: Drop `.yml` files into `sigma_rules/`

Both are auto-discovered at runtime.

---

<p align="center">
  <strong>Built for the front lines of Incident Response.</strong><br>
  <em>TriageHound — Because attackers delete evidence. We find it anyway.</em>
</p>
