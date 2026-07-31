import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import platform
from datetime import datetime

from database.db_manager import DBManager
from modules.hashing import hash_file
from modules.process_monitor import collect_processes
from modules.recent_files import collect_recent_files
from modules.startup_analysis import collect_startup_entries
from modules.usb_analysis import collect_usb_history
from modules.browser_analysis import collect_browser_history
from modules.event_logs import parse_evtx
from modules.prefetch_parser import collect_prefetch
from modules.usn_parser import collect_usn_journal
from modules.shimcache_parser import collect_shimcache
from modules.sigma_engine import load_sigma_rules, match_events
from modules.virustotal import batch_check as vt_batch_check
from modules.vss_extractor import collect_vss_info
from modules.timeline import generate_timeline
from modules.yara_scanner import compile_rules, scan_file
from modules.report_sealer import seal_report
from reports.report_generator import generate_pdf_report
from utils.helpers import export_to_json, export_to_csv


class ForensicToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensics Toolkit")
        self.root.geometry("950x720")
        self.root.minsize(800, 600)
        self.root.configure(bg="#1a1a2e")

        self.db = None
        self.case_id = None
        self.timeline_data = []

        self._setup_styles()
        self._build_ui()

    # ── Styles ────────────────────────────────────────────────
    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.BG = "#1a1a2e"
        self.FG = "#e0e0e0"
        self.ACCENT = "#0f3460"
        self.HIGHLIGHT = "#16213e"
        self.BTN_BG = "#e94560"
        self.BTN_FG = "#ffffff"
        self.SUCCESS = "#00b894"
        self.WARNING = "#fdcb6e"

        self.style.configure("TFrame", background=self.BG)
        self.style.configure("TLabel", background=self.BG, foreground=self.FG,
                             font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", background=self.BG, foreground=self.FG,
                             font=("Segoe UI", 18, "bold"))
        self.style.configure("Sub.TLabel", background=self.BG, foreground="#a0a0b0",
                             font=("Segoe UI", 9))
        self.style.configure("TEntry", fieldbackground=self.HIGHLIGHT, foreground=self.FG,
                             insertcolor=self.FG, font=("Segoe UI", 10))
        self.style.configure("Accent.TButton", background=self.BTN_BG, foreground=self.BTN_FG,
                             font=("Segoe UI", 10, "bold"), padding=(12, 6))
        self.style.map("Accent.TButton",
                       background=[("active", "#c0392b"), ("disabled", "#555555")])
        self.style.configure("Secondary.TButton", background=self.ACCENT, foreground=self.FG,
                             font=("Segoe UI", 9), padding=(8, 4))
        self.style.map("Secondary.TButton",
                       background=[("active", "#1a4a7a"), ("disabled", "#333333")])
        self.style.configure("TCheckbutton", background=self.BG, foreground=self.FG,
                             font=("Segoe UI", 10))
        self.style.configure("Treeview", background=self.HIGHLIGHT, foreground=self.FG,
                             fieldbackground=self.HIGHLIGHT, font=("Segoe UI", 9),
                             rowheight=24)
        self.style.configure("Treeview.Heading", background=self.ACCENT, foreground=self.FG,
                             font=("Segoe UI", 9, "bold"))
        self.style.map("Treeview", background=[("selected", self.ACCENT)])

    # ── Build UI ──────────────────────────────────────────────
    def _build_ui(self):
        # ── Header ──
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=20, pady=(15, 5))

        ttk.Label(header_frame, text="🔬 Digital Forensics Toolkit",
                  style="Header.TLabel").pack(side=tk.LEFT)
        ttk.Label(header_frame,
                  text=f"{platform.system()} {platform.release()}",
                  style="Sub.TLabel").pack(side=tk.RIGHT, pady=(8, 0))

        # ── Case Info ──
        case_frame = ttk.Frame(self.root)
        case_frame.pack(fill=tk.X, padx=20, pady=10)

        labels = ["Case ID:", "Investigator:", "Target System:"]
        self.case_id_var = tk.StringVar(value="CASE001")
        self.investigator_var = tk.StringVar()
        self.target_var = tk.StringVar(value=platform.node())
        entries = [self.case_id_var, self.investigator_var, self.target_var]

        for i, (lbl, var) in enumerate(zip(labels, entries)):
            ttk.Label(case_frame, text=lbl).grid(row=0, column=i * 2, sticky=tk.W, padx=(0, 5))
            e = ttk.Entry(case_frame, textvariable=var, width=20)
            e.grid(row=0, column=i * 2 + 1, sticky=tk.W, padx=(0, 15))

        # ── Module Selection ──
        modules_frame = ttk.LabelFrame(self.root, text="  Collection Modules  ",
                                       style="TFrame")
        modules_frame.configure(style="TFrame")
        modules_frame.pack(fill=tk.X, padx=20, pady=(5, 5))

        self.mod_processes = tk.BooleanVar(value=True)
        self.mod_recent = tk.BooleanVar(value=True)
        self.mod_startup = tk.BooleanVar(value=True)
        self.mod_usb = tk.BooleanVar(value=True)
        self.mod_browser = tk.BooleanVar(value=True)
        self.mod_evtx = tk.BooleanVar(value=False)
        self.evtx_path_var = tk.StringVar()

        checks = [
            ("Running Processes", self.mod_processes),
            ("Recent Files", self.mod_recent),
            ("Startup Programs", self.mod_startup),
            ("USB Devices", self.mod_usb),
            ("Browser History", self.mod_browser),
        ]
        inner = ttk.Frame(modules_frame)
        inner.pack(fill=tk.X, padx=10, pady=8)
        for i, (text, var) in enumerate(checks):
            ttk.Checkbutton(inner, text=text, variable=var).grid(
                row=0, column=i, sticky=tk.W, padx=(0, 15))

        evtx_row = ttk.Frame(modules_frame)
        evtx_row.pack(fill=tk.X, padx=10, pady=(0, 8))
        ttk.Checkbutton(evtx_row, text="Event Logs (.evtx):",
                        variable=self.mod_evtx).pack(side=tk.LEFT)
        ttk.Entry(evtx_row, textvariable=self.evtx_path_var, width=45).pack(
            side=tk.LEFT, padx=(5, 5))
        ttk.Button(evtx_row, text="Browse...", style="Secondary.TButton",
                   command=self._browse_evtx).pack(side=tk.LEFT)

        yara_row = ttk.Frame(modules_frame)
        yara_row.pack(fill=tk.X, padx=10, pady=(0, 8))
        self.mod_yara = tk.BooleanVar(value=False)
        ttk.Checkbutton(yara_row, text="YARA Malware Scan",
                        variable=self.mod_yara).pack(side=tk.LEFT)
        ttk.Label(yara_row, text="(scans startup entries against rules/ directory)",
                  style="Sub.TLabel").pack(side=tk.LEFT, padx=(8, 0))

        prefetch_row = ttk.Frame(modules_frame)
        prefetch_row.pack(fill=tk.X, padx=10, pady=(0, 8))
        self.mod_prefetch = tk.BooleanVar(value=False)
        ttk.Checkbutton(prefetch_row, text="Prefetch Files (Admin required)",
                        variable=self.mod_prefetch).pack(side=tk.LEFT)
        ttk.Label(prefetch_row, text="(parses C:\\Windows\\Prefetch for execution evidence)",
                  style="Sub.TLabel").pack(side=tk.LEFT, padx=(8, 0))

        usn_row = ttk.Frame(modules_frame)
        usn_row.pack(fill=tk.X, padx=10, pady=(0, 8))
        self.mod_usn = tk.BooleanVar(value=False)
        ttk.Checkbutton(usn_row, text="USN Journal (Admin required)",
                        variable=self.mod_usn).pack(side=tk.LEFT)
        ttk.Label(usn_row, text="(NTFS file system change log — defeats anti-forensics)",
                  style="Sub.TLabel").pack(side=tk.LEFT, padx=(8, 0))

        shim_row = ttk.Frame(modules_frame)
        shim_row.pack(fill=tk.X, padx=10, pady=(0, 8))
        self.mod_shimcache = tk.BooleanVar(value=False)
        ttk.Checkbutton(shim_row, text="ShimCache (Execution Evidence)",
                        variable=self.mod_shimcache).pack(side=tk.LEFT)
        ttk.Label(shim_row, text="(AppCompatCache — independent proof of program execution)",
                  style="Sub.TLabel").pack(side=tk.LEFT, padx=(8, 0))

        sigma_row = ttk.Frame(modules_frame)
        sigma_row.pack(fill=tk.X, padx=10, pady=(0, 8))
        self.mod_sigma = tk.BooleanVar(value=False)
        ttk.Checkbutton(sigma_row, text="Sigma Rules Scan",
                        variable=self.mod_sigma).pack(side=tk.LEFT)
        ttk.Label(sigma_row, text="(behavioral detections on Event Logs — requires .evtx)",
                  style="Sub.TLabel").pack(side=tk.LEFT, padx=(8, 0))

        vt_row = ttk.Frame(modules_frame)
        vt_row.pack(fill=tk.X, padx=10, pady=(0, 8))
        self.mod_vt = tk.BooleanVar(value=False)
        self.vt_api_key_var = tk.StringVar()
        ttk.Checkbutton(vt_row, text="VirusTotal Lookup",
                        variable=self.mod_vt).pack(side=tk.LEFT)
        ttk.Label(vt_row, text="API Key:",
                  style="Sub.TLabel").pack(side=tk.LEFT, padx=(8, 0))
        ttk.Entry(vt_row, textvariable=self.vt_api_key_var, width=35,
                  show="*").pack(side=tk.LEFT, padx=(5, 0))

        vss_row = ttk.Frame(modules_frame)
        vss_row.pack(fill=tk.X, padx=10, pady=(0, 8))
        self.mod_vss = tk.BooleanVar(value=False)
        ttk.Checkbutton(vss_row, text="Shadow Copy Recovery (Admin required)",
                        variable=self.mod_vss).pack(side=tk.LEFT)
        ttk.Label(vss_row, text="(recover deleted evidence from Volume Shadow Copies)",
                  style="Sub.TLabel").pack(side=tk.LEFT, padx=(8, 0))

        # ── Export Options ──
        export_frame = ttk.Frame(self.root)
        export_frame.pack(fill=tk.X, padx=20, pady=5)

        self.export_pdf = tk.BooleanVar(value=True)
        self.export_json = tk.BooleanVar(value=False)
        self.export_csv = tk.BooleanVar(value=False)

        ttk.Label(export_frame, text="Export:").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Checkbutton(export_frame, text="PDF Report", variable=self.export_pdf).pack(
            side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(export_frame, text="JSON", variable=self.export_json).pack(
            side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(export_frame, text="CSV", variable=self.export_csv).pack(
            side=tk.LEFT, padx=(0, 12))

        # ── Action Buttons ──
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill=tk.X, padx=20, pady=(5, 5))

        self.run_btn = ttk.Button(btn_frame, text="▶  Run Investigation",
                                  style="Accent.TButton", command=self._run_investigation)
        self.run_btn.pack(side=tk.LEFT)

        ttk.Button(btn_frame, text="Hash File...", style="Secondary.TButton",
                   command=self._hash_file_dialog).pack(side=tk.LEFT, padx=(10, 0))

        # ── Notebook with Log + Timeline tabs ──
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(5, 15))

        # Log tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="  📋 Collection Log  ")

        self.log_text = scrolledtext.ScrolledText(
            log_frame, bg=self.HIGHLIGHT, fg=self.FG, insertbackground=self.FG,
            font=("Consolas", 10), relief=tk.FLAT, wrap=tk.WORD, state=tk.DISABLED
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.tag_config("info", foreground="#00b894")
        self.log_text.tag_config("warn", foreground="#fdcb6e")
        self.log_text.tag_config("error", foreground="#e94560")
        self.log_text.tag_config("header", foreground="#74b9ff", font=("Consolas", 10, "bold"))

        # Timeline tab
        timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(timeline_frame, text="  🕐 Timeline  ")

        cols = ("time", "type", "source", "event")
        self.timeline_tree = ttk.Treeview(timeline_frame, columns=cols, show="headings")
        self.timeline_tree.heading("time", text="Timestamp")
        self.timeline_tree.heading("type", text="Type")
        self.timeline_tree.heading("source", text="Source")
        self.timeline_tree.heading("event", text="Event")
        self.timeline_tree.column("time", width=180, minwidth=150)
        self.timeline_tree.column("type", width=100, minwidth=80)
        self.timeline_tree.column("source", width=100, minwidth=80)
        self.timeline_tree.column("event", width=400, minwidth=200)

        vsb = ttk.Scrollbar(timeline_frame, orient="vertical",
                            command=self.timeline_tree.yview)
        self.timeline_tree.configure(yscrollcommand=vsb.set)
        self.timeline_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        vsb.pack(side=tk.RIGHT, fill=tk.Y, pady=5, padx=(0, 5))

        # ── Status Bar ──
        self.status_var = tk.StringVar(value="Ready.")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, style="Sub.TLabel",
                               anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=20, pady=(0, 8))

    # ── Helpers ───────────────────────────────────────────────
    def _log(self, msg, tag="info"):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _browse_evtx(self):
        path = filedialog.askopenfilename(
            title="Select .evtx file",
            filetypes=[("Event Log", "*.evtx"), ("All files", "*.*")]
        )
        if path:
            self.evtx_path_var.set(path)
            self.mod_evtx.set(True)

    def _hash_file_dialog(self):
        path = filedialog.askopenfilename(title="Select file to hash")
        if path:
            result = hash_file(path)
            msg = (f"File: {os.path.basename(path)}\n"
                   f"  MD5:    {result['md5']}\n"
                   f"  SHA-1:  {result['sha1']}\n"
                   f"  SHA-256:{result['sha256']}\n"
                   f"  Size:   {result['file_size']} bytes")
            messagebox.showinfo("Hash Result", msg)
            self._log(f"[HASH] {os.path.basename(path)}: SHA256={result['sha256'][:24]}...")

    # ── Investigation Runner ──────────────────────────────────
    def _run_investigation(self):
        case_id = self.case_id_var.get().strip()
        investigator = self.investigator_var.get().strip()
        target = self.target_var.get().strip()

        if not case_id or not investigator:
            messagebox.showwarning("Missing Info", "Please fill in Case ID and Investigator name.")
            return

        self.run_btn.configure(state=tk.DISABLED)
        self.status_var.set("Investigation running...")

        # Run collection in a background thread to keep the UI responsive
        thread = threading.Thread(target=self._collect, args=(case_id, investigator, target),
                                  daemon=True)
        thread.start()

    def _collect(self, case_id, investigator, target):
        try:
            db_path = f"forensics_{case_id}.db"
            if os.path.exists(db_path):
                os.remove(db_path)

            db = DBManager(db_path)
            db.insert_case_metadata(case_id, investigator, "Forensic Investigation", target)
            self.db = db
            self.case_id = case_id

            self._log("=" * 55, "header")
            self._log("  DIGITAL FORENSICS TOOLKIT — Collection Started", "header")
            self._log("=" * 55, "header")
            self._log(f"  Case: {case_id}  |  Investigator: {investigator}  |  Target: {target}")
            self._log("")

            # Processes
            if self.mod_processes.get():
                self._log("[*] Collecting running processes...")
                procs = collect_processes()
                for p in procs:
                    db.insert_evidence('process', 'psutil',
                                       f"Process: {p['name']} (PID: {p['pid']})",
                                       p['start_time'], p, case_id)
                self._log(f"    ✓ {len(procs)} processes collected.", "info")

            # Recent files
            if self.mod_recent.get():
                self._log("[*] Collecting recent files...")
                rfiles = collect_recent_files()
                for rf in rfiles:
                    db.insert_evidence('recent_file', 'Registry',
                                       f"Recent File: {rf['filename']}",
                                       None, rf, case_id)
                self._log(f"    ✓ {len(rfiles)} recent file entries.", "info")

            # Startup entries
            if self.mod_startup.get():
                self._log("[*] Collecting startup entries...")
                entries = collect_startup_entries()
                for se in entries:
                    flag = " [SUSPICIOUS]" if se.get('flagged_suspicious') else ""
                    db.insert_evidence('startup_entry', 'Registry',
                                       f"Startup: {se['name']} -> {se['command']}{flag}",
                                       None, se, case_id)
                suspicious = sum(1 for s in entries if s.get('flagged_suspicious'))
                self._log(f"    ✓ {len(entries)} startup entries ({suspicious} flagged).", "info")
                if suspicious:
                    self._log(f"    ⚠ {suspicious} suspicious startup entries detected!", "warn")

            # USB
            if self.mod_usb.get():
                self._log("[*] Collecting USB device history...")
                usbs = collect_usb_history()
                for u in usbs:
                    db.insert_evidence('usb_device', 'Registry',
                                       f"USB Device: {u['friendly_name']}",
                                       None, u, case_id)
                self._log(f"    ✓ {len(usbs)} USB devices found.", "info")

            # Browser
            if self.mod_browser.get():
                self._log("[*] Collecting browser history (Chrome, Edge, Firefox)...")
                bh = collect_browser_history()
                for ch in bh:
                    db.insert_evidence('browser_history', ch['browser'],
                                       f"Visited: {ch['title']} ({ch['url']})",
                                       ch['last_visited'], ch, case_id)
                self._log(f"    ✓ {len(bh)} browser history entries.", "info")

            # Event Logs
            if self.mod_evtx.get():
                evtx_path = self.evtx_path_var.get().strip()
                if evtx_path and os.path.exists(evtx_path):
                    self._log(f"[*] Parsing event log: {evtx_path}...")
                    events = parse_evtx(evtx_path)
                    for ev in events:
                        db.insert_evidence('event_log', 'Windows Event Log',
                                           f"Event {ev['event_id']}: {ev['description']}",
                                           ev['timestamp'], ev, case_id)
                    self._log(f"    ✓ {len(events)} security events found.", "info")
                else:
                    self._log("    ⚠ EVTX file path is invalid or not set.", "warn")

            # YARA Malware Scan
            if self.mod_yara.get():
                self._log("")
                self._log("[*] YARA Malware Scan...", "header")
                rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
                compiled = compile_rules(rules_dir)
                if compiled:
                    scan_targets = [se['command'] for se in entries if os.path.isfile(se.get('command', ''))]
                    self._log(f"    Scanning {len(scan_targets)} startup executables...")
                    yara_hits = 0
                    for target_path in scan_targets:
                        matches = scan_file(compiled, target_path)
                        for m in matches:
                            yara_hits += 1
                            db.insert_evidence('yara_match', 'YARA Scanner',
                                               f"YARA Hit: {m['rule']} ({m['description']}) in {os.path.basename(target_path)}",
                                               None, m, case_id)
                            self._log(f"    [!!] MATCH: {m['rule']} [{m['severity']}] in {os.path.basename(target_path)}", "error")
                    if yara_hits == 0:
                        self._log("    ✓ No malware signatures detected.", "info")
                    else:
                        self._log(f"    [!!] {yara_hits} YARA rule match(es) detected!", "error")
                else:
                    self._log("    ⚠ No YARA rules found in rules/ directory.", "warn")

            # Prefetch
            if self.mod_prefetch.get():
                self._log("")
                self._log("[*] Parsing Prefetch files...", "header")
                pf_entries = collect_prefetch()
                if pf_entries:
                    for pf in pf_entries:
                        db.insert_evidence('prefetch', 'Prefetch Parser',
                                           f"Executed: {pf['executable_name']} (x{pf['run_count']}) last at {pf['last_run']}",
                                           pf['last_run'], pf, case_id)
                    self._log(f"    ✓ {len(pf_entries)} prefetch entries found.", "info")
                else:
                    self._log("    ⚠ No prefetch entries found. Try running as Administrator.", "warn")

            # USN Journal
            if self.mod_usn.get():
                self._log("")
                self._log("[*] Parsing USN Journal...", "header")
                usn_entries = collect_usn_journal()
                if usn_entries:
                    for entry in usn_entries:
                        db.insert_evidence('usn_journal', 'USN Journal',
                                           f"USN: {entry['filename']} [{entry['reason_summary']}]",
                                           entry['timestamp'], entry, case_id)
                    self._log(f"    ✓ {len(usn_entries)} USN journal entries collected.", "info")
                else:
                    self._log("    ⚠ No USN entries found. Try running as Administrator.", "warn")

            # ShimCache
            if self.mod_shimcache.get():
                self._log("")
                self._log("[*] Parsing ShimCache...", "header")
                shim_entries = collect_shimcache()
                if shim_entries:
                    for entry in shim_entries:
                        db.insert_evidence('shimcache', 'ShimCache',
                                           f"ShimCache: {os.path.basename(entry['executable_path'])} (modified: {entry['last_modified']})",
                                           entry['last_modified'], entry, case_id)
                    self._log(f"    ✓ {len(shim_entries)} ShimCache entries found.", "info")
                else:
                    self._log("    ⚠ No ShimCache entries found.", "warn")

            # Sigma Rules Scan
            if self.mod_sigma.get():
                self._log("")
                self._log("[*] Sigma Rules Scan...", "header")
                evtx_path = self.evtx_path_var.get().strip()
                if evtx_path and os.path.exists(evtx_path):
                    sigma_rules = load_sigma_rules('sigma_rules')
                    if sigma_rules:
                        all_events = parse_evtx(evtx_path, extract_all=True)
                        sigma_alerts = match_events(sigma_rules, all_events)
                        for alert in sigma_alerts:
                            db.insert_evidence('sigma_alert', 'Sigma Engine',
                                               f"Sigma Alert: {alert['rule_title']} [{alert['rule_level'].upper()}]",
                                               alert['matched_event'].get('timestamp'), alert, case_id)
                            self._log(f"    [!!] SIGMA: {alert['rule_title']} [{alert['rule_level'].upper()}]", "error")
                        if not sigma_alerts:
                            self._log("    ✓ No Sigma rule matches found.", "info")
                        else:
                            self._log(f"    [!!] {len(sigma_alerts)} Sigma alert(s) triggered!", "error")
                    else:
                        self._log("    ⚠ No Sigma rules found in sigma_rules/ directory.", "warn")
                else:
                    self._log("    ⚠ Sigma scan requires an Event Log (.evtx) file.", "warn")

            # VirusTotal Lookups
            if self.mod_vt.get():
                self._log("")
                self._log("[*] VirusTotal Hash Lookups...", "header")
                api_key = self.vt_api_key_var.get().strip()
                if api_key:
                    from modules.hashing import hash_file as compute_hash
                    vt_targets = []
                    for se in entries:
                        cmd = se.get('command', '')
                        if os.path.isfile(cmd):
                            result = compute_hash(cmd)
                            vt_targets.append((os.path.basename(cmd), result['sha256']))
                    self._log(f"    Checking {len(vt_targets)} hashes (rate limited)...", "info")
                    def vt_cb(label, result):
                        if result.get('is_malicious'):
                            self._log(f"    [!!] MALICIOUS: {label} — {result['detection_ratio']}", "error")
                        elif result.get('status') == 'found':
                            self._log(f"    [OK] {label} — {result['detection_ratio']}", "info")
                        else:
                            self._log(f"    [--] {label} — {result.get('status', 'unknown')}", "info")
                    vt_results = vt_batch_check(vt_targets, api_key, callback=vt_cb)
                    for label, result in vt_results:
                        db.insert_evidence('virustotal', 'VirusTotal API',
                                           f"VT: {label} — {result['detection_ratio']}",
                                           None, result, case_id)
                else:
                    self._log("    ⚠ No API key provided. Enter your VirusTotal API key.", "warn")

            # VSS Extraction
            if self.mod_vss.get():
                self._log("")
                self._log("[*] Scanning Volume Shadow Copies...", "header")
                vss_results = collect_vss_info()
                if vss_results:
                    for vss in vss_results:
                        db.insert_evidence('vss', 'VSS Extractor',
                                           f"Shadow Copy: {vss['creation_time']} ({len(vss['artifacts_found'])} artifacts)",
                                           vss['creation_time'], vss, case_id)
                    self._log(f"    ✓ {len(vss_results)} shadow copies scanned.", "info")
                else:
                    self._log("    ⚠ No shadow copies found. Try running as Administrator.", "warn")

            # Timeline
            self._log("")
            self._log("[*] Generating timeline...", "header")
            self.timeline_data = generate_timeline(db_path, case_id)
            self._log(f"    ✓ {len(self.timeline_data)} timestamped events in timeline.", "info")

            # Populate timeline tree on the main thread
            self.root.after(0, self._populate_timeline)

            # Exports
            if self.export_pdf.get():
                report_path = f"report_{case_id}.pdf"
                case_info = {
                    'case_id': case_id,
                    'case_name': 'Forensic Investigation',
                    'investigator_name': investigator,
                    'target_system': target
                }
                generate_pdf_report(case_info, self.timeline_data, report_path, db_manager=db)
                self._log(f"    \u2713 PDF report: {report_path}", "info")

            if self.export_json.get():
                json_path = f"timeline_{case_id}.json"
                export_to_json(self.timeline_data, json_path)
                self._log(f"    ✓ JSON export: {json_path}", "info")

            if self.export_csv.get():
                csv_path = f"timeline_{case_id}.csv"
                export_to_csv(self.timeline_data, csv_path)
                self._log(f"    ✓ CSV export:  {csv_path}", "info")

            # Seal the artifacts
            if self.export_pdf.get():
                self._log("")
                self._log("[*] Sealing investigation artifacts...", "header")
                sp, sd = seal_report(report_path, db_path, case_id)
                for lbl, info in sd['artifacts'].items():
                    if info.get('sha256'):
                        self._log(f"    [{lbl}] SHA256: {info['sha256'][:32]}...", "info")
                self._log(f"    \u2713 Seal manifest: seal_{case_id}.txt", "info")

            self._log("")
            self._log("=" * 55, "header")
            self._log("  \u2713 Investigation Complete.", "header")
            self._log("=" * 55, "header")
            self.root.after(0, lambda: self.status_var.set("Investigation complete."))

        except Exception as e:
            self._log(f"\n[ERROR] {e}", "error")
            self.root.after(0, lambda: self.status_var.set(f"Error: {e}"))

        finally:
            self.root.after(0, lambda: self.run_btn.configure(state=tk.NORMAL))

    def _populate_timeline(self):
        for item in self.timeline_tree.get_children():
            self.timeline_tree.delete(item)
        for ev in self.timeline_data:
            self.timeline_tree.insert("", tk.END, values=(
                ev.get('time', ''), ev.get('type', ''),
                ev.get('source', ''), ev.get('event', '')
            ))
        self.notebook.select(1)  # Switch to Timeline tab


def main():
    root = tk.Tk()
    app = ForensicToolkitGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
# End of file
