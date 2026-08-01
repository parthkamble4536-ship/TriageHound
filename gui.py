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


# ── Colour Palette ───────────────────────────────────────────────────────────
BG_DARK      = "#0d1117"
BG_PANEL     = "#161b22"
BG_CARD      = "#1c2128"
BG_INPUT     = "#0d1117"
BG_HOVER     = "#21262d"
BORDER       = "#30363d"
ACCENT       = "#58a6ff"
ACCENT_GREEN = "#3fb950"
ACCENT_RED   = "#f85149"
ACCENT_AMBER = "#d29922"
TEXT_PRIMARY  = "#e6edf3"
TEXT_SECONDARY = "#8b949e"
TEXT_DIM      = "#484f58"
BRAND_CYAN   = "#79c0ff"


class ForensicToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("TriageHound — Digital Forensics & Incident Response")
        self.root.geometry("1120x720")
        self.root.minsize(1000, 650)
        self.root.configure(bg=BG_DARK)

        self.db = None
        self.case_id = None
        self.timeline_data = []

        self._setup_styles()
        self._build_ui()

    # ── Styles ────────────────────────────────────────────────────────────────
    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.style.configure("TFrame", background=BG_DARK)
        self.style.configure("Panel.TFrame", background=BG_PANEL)
        self.style.configure("Card.TFrame", background=BG_CARD)

        self.style.configure("TLabel", background=BG_DARK, foreground=TEXT_PRIMARY,
                             font=("Segoe UI", 10))
        self.style.configure("Panel.TLabel", background=BG_PANEL,
                             foreground=TEXT_PRIMARY, font=("Segoe UI", 10))
        self.style.configure("Category.TLabel", background=BG_PANEL,
                             foreground=ACCENT, font=("Segoe UI", 8, "bold"))
        self.style.configure("Dim.TLabel", background=BG_PANEL,
                             foreground=TEXT_DIM, font=("Segoe UI", 8))
        self.style.configure("Sub.TLabel", background=BG_DARK,
                             foreground=TEXT_SECONDARY, font=("Segoe UI", 9))
        self.style.configure("TopBar.TLabel", background=BG_PANEL,
                             foreground=TEXT_PRIMARY, font=("Segoe UI", 9))
        self.style.configure("Header.TLabel", background=BG_DARK,
                             foreground=TEXT_PRIMARY, font=("Segoe UI", 13, "bold"))

        # Stat card styles
        self.style.configure("StatVal.TLabel", background=BG_CARD,
                             foreground=TEXT_PRIMARY, font=("Segoe UI", 18, "bold"))
        self.style.configure("StatLbl.TLabel", background=BG_CARD,
                             foreground=TEXT_SECONDARY, font=("Segoe UI", 8))
        self.style.configure("StatGreen.TLabel", background=BG_CARD,
                             foreground=ACCENT_GREEN, font=("Segoe UI", 18, "bold"))
        self.style.configure("StatRed.TLabel", background=BG_CARD,
                             foreground=ACCENT_RED, font=("Segoe UI", 18, "bold"))
        self.style.configure("StatAmber.TLabel", background=BG_CARD,
                             foreground=ACCENT_AMBER, font=("Segoe UI", 18, "bold"))

        # Entries
        self.style.configure("TEntry", fieldbackground=BG_INPUT,
                             foreground=TEXT_PRIMARY, insertcolor=TEXT_PRIMARY,
                             font=("Segoe UI", 10))

        # Buttons
        self.style.configure("Run.TButton", background=ACCENT_GREEN,
                             foreground="#ffffff", font=("Segoe UI", 11, "bold"),
                             padding=(20, 8))
        self.style.map("Run.TButton",
                       background=[("active", "#2ea043"), ("disabled", "#21262d")])
        self.style.configure("Secondary.TButton", background=BG_CARD,
                             foreground=TEXT_PRIMARY, font=("Segoe UI", 9),
                             padding=(8, 4))
        self.style.map("Secondary.TButton",
                       background=[("active", BG_HOVER), ("disabled", "#21262d")])

        # Checkbuttons
        self.style.configure("Mod.TCheckbutton", background=BG_PANEL,
                             foreground=TEXT_PRIMARY, font=("Segoe UI", 9))
        self.style.map("Mod.TCheckbutton", background=[("active", BG_HOVER)])
        self.style.configure("Export.TCheckbutton", background=BG_PANEL,
                             foreground=TEXT_SECONDARY, font=("Segoe UI", 9))
        self.style.map("Export.TCheckbutton", background=[("active", BG_HOVER)])

        # Notebook
        self.style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=BG_CARD,
                             foreground=TEXT_SECONDARY, font=("Segoe UI", 10),
                             padding=(14, 6))
        self.style.map("TNotebook.Tab",
                       background=[("selected", BG_DARK)],
                       foreground=[("selected", TEXT_PRIMARY)])

        # Treeview
        self.style.configure("Treeview", background=BG_CARD, foreground=TEXT_PRIMARY,
                             fieldbackground=BG_CARD, font=("Segoe UI", 9),
                             rowheight=22)
        self.style.configure("Treeview.Heading", background=BG_PANEL,
                             foreground=TEXT_PRIMARY, font=("Segoe UI", 9, "bold"))
        self.style.map("Treeview", background=[("selected", "#1f6feb")])

        # Progressbar
        self.style.configure("Green.Horizontal.TProgressbar",
                             background=ACCENT_GREEN, troughcolor=BG_CARD,
                             borderwidth=0, thickness=4)

        # LabelFrame
        self.style.configure("Panel.TLabelframe", background=BG_PANEL,
                             foreground=ACCENT, font=("Segoe UI", 9, "bold"))
        self.style.configure("Panel.TLabelframe.Label", background=BG_PANEL,
                             foreground=ACCENT, font=("Segoe UI", 9, "bold"))

    # ── Build UI ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ═══ TOP BAR ═══ (Brand + Case Info + Run Button — always visible)
        self._build_topbar()

        # ═══ MAIN AREA ═══ (Modules panel left | Dashboard right)
        main = ttk.Frame(self.root)
        main.pack(fill=tk.BOTH, expand=True)

        # Left: Module selection panel
        self._build_modules_panel(main)

        # Right: Dashboard + Log
        self._build_dashboard(main)

    # ── Top Bar ───────────────────────────────────────────────────────────────
    def _build_topbar(self):
        topbar = tk.Frame(self.root, bg=BG_PANEL, height=60)
        topbar.pack(fill=tk.X)
        topbar.pack_propagate(False)

        # Brand
        brand = tk.Frame(topbar, bg=BG_PANEL)
        brand.pack(side=tk.LEFT, padx=(16, 20))
        tk.Label(brand, text="🔍 TriageHound", bg=BG_PANEL, fg=BRAND_CYAN,
                 font=("Segoe UI", 15, "bold")).pack(side=tk.LEFT)
        tk.Label(brand, text="  v1.0", bg=BG_PANEL, fg=TEXT_DIM,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, pady=(4, 0))

        # Thin vertical separator
        tk.Frame(topbar, bg=BORDER, width=1).pack(side=tk.LEFT, fill=tk.Y,
                                                    padx=(0, 16), pady=12)

        # Case fields — inline
        self.case_id_var = tk.StringVar(value="CASE001")
        self.case_name_var = tk.StringVar(value="Forensic Investigation")
        self.investigator_var = tk.StringVar()
        self.target_var = tk.StringVar(value=platform.node())

        fields = [("Case ID", self.case_id_var, 10),
                  ("Case Name", self.case_name_var, 16),
                  ("Investigator", self.investigator_var, 12),
                  ("Target", self.target_var, 12)]

        for label_text, var, width in fields:
            f = tk.Frame(topbar, bg=BG_PANEL)
            f.pack(side=tk.LEFT, padx=(0, 12))
            tk.Label(f, text=label_text, bg=BG_PANEL, fg=TEXT_SECONDARY,
                     font=("Segoe UI", 8)).pack(anchor=tk.W)
            e = tk.Entry(f, textvariable=var, bg=BG_INPUT, fg=TEXT_PRIMARY,
                         insertbackground=TEXT_PRIMARY, font=("Segoe UI", 10),
                         relief=tk.FLAT, width=width, highlightthickness=1,
                         highlightcolor=ACCENT, highlightbackground=BORDER)
            e.pack(ipady=2)

        # Right side: Run button + Hash button
        btn_frame = tk.Frame(topbar, bg=BG_PANEL)
        btn_frame.pack(side=tk.RIGHT, padx=16)

        self.run_btn = ttk.Button(btn_frame, text="▶  Run Investigation",
                                  style="Run.TButton",
                                  command=self._run_investigation)
        self.run_btn.pack(side=tk.LEFT)

        ttk.Button(btn_frame, text="🔑 Hash", style="Secondary.TButton",
                   command=self._hash_file_dialog).pack(side=tk.LEFT, padx=(8, 0))

        # Accent line under topbar
        tk.Frame(self.root, bg=ACCENT, height=2).pack(fill=tk.X)

    # ── Modules Panel (Left Side) ────────────────────────────────────────────
    def _build_modules_panel(self, parent):
        panel = tk.Frame(parent, bg=BG_PANEL, width=270)
        panel.pack(side=tk.LEFT, fill=tk.Y)
        panel.pack_propagate(False)

        # Thin right border
        tk.Frame(panel, bg=BORDER, width=1).pack(side=tk.RIGHT, fill=tk.Y)

        # Scrollable canvas for all module content
        canvas = tk.Canvas(panel, bg=BG_PANEL, highlightthickness=0, width=254)
        scrollbar = ttk.Scrollbar(panel, orient="vertical", command=canvas.yview)

        inner = tk.Frame(canvas, bg=BG_PANEL)
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw", width=254)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(14, 0),
                    pady=(10, 8))

        # Mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind("<Enter>",
                    lambda e: canvas.bind_all("<MouseWheel>", _on_mousewheel))
        canvas.bind("<Leave>",
                    lambda e: canvas.unbind_all("<MouseWheel>"))

        # ── CORE COLLECTION ──
        self._cat_label(inner, "📦 CORE COLLECTION")

        self.mod_processes = tk.BooleanVar(value=True)
        self.mod_recent = tk.BooleanVar(value=True)
        self.mod_startup = tk.BooleanVar(value=True)
        self.mod_usb = tk.BooleanVar(value=True)
        self.mod_browser = tk.BooleanVar(value=True)

        for text, var in [("Running Processes", self.mod_processes),
                          ("Recent Files", self.mod_recent),
                          ("Startup Programs", self.mod_startup),
                          ("USB Device History", self.mod_usb),
                          ("Browser History", self.mod_browser)]:
            ttk.Checkbutton(inner, text=text, variable=var,
                            style="Mod.TCheckbutton").pack(anchor=tk.W, pady=1)

        # Event Logs with browse
        self.mod_evtx = tk.BooleanVar(value=False)
        self.evtx_path_var = tk.StringVar()

        ttk.Checkbutton(inner, text="Event Logs (.evtx)",
                        variable=self.mod_evtx,
                        style="Mod.TCheckbutton").pack(anchor=tk.W, pady=1)

        evtx_row = tk.Frame(inner, bg=BG_PANEL)
        evtx_row.pack(fill=tk.X, padx=(18, 0), pady=(0, 2))
        tk.Entry(evtx_row, textvariable=self.evtx_path_var, bg=BG_INPUT,
                 fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                 font=("Segoe UI", 8), relief=tk.FLAT, highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=ACCENT
                 ).pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=1)
        ttk.Button(evtx_row, text="...", style="Secondary.TButton",
                   command=self._browse_evtx, width=3).pack(side=tk.LEFT,
                                                              padx=(3, 0))

        self._separator(inner)

        # ── ADVANCED FORENSICS ──
        self._cat_label(inner, "🔬 ADVANCED FORENSICS")

        self.mod_prefetch = tk.BooleanVar(value=False)
        self.mod_shimcache = tk.BooleanVar(value=False)
        self.mod_usn = tk.BooleanVar(value=False)
        self.mod_vss = tk.BooleanVar(value=False)

        for text, var in [("Prefetch Files ⚡", self.mod_prefetch),
                          ("ShimCache", self.mod_shimcache),
                          ("USN Journal ⚡", self.mod_usn),
                          ("Shadow Copies ⚡", self.mod_vss)]:
            ttk.Checkbutton(inner, text=text, variable=var,
                            style="Mod.TCheckbutton").pack(anchor=tk.W, pady=1)

        ttk.Label(inner, text="⚡ = Administrator required",
                  style="Dim.TLabel").pack(anchor=tk.W, padx=18, pady=(0, 2))

        self._separator(inner)

        # ── THREAT HUNTING ──
        self._cat_label(inner, "🎯 THREAT HUNTING")

        self.mod_yara = tk.BooleanVar(value=False)
        self.mod_sigma = tk.BooleanVar(value=False)
        self.mod_vt = tk.BooleanVar(value=False)
        self.vt_api_key_var = tk.StringVar()

        ttk.Checkbutton(inner, text="YARA Malware Scan",
                        variable=self.mod_yara,
                        style="Mod.TCheckbutton").pack(anchor=tk.W, pady=1)
        ttk.Checkbutton(inner, text="Sigma Rules Scan",
                        variable=self.mod_sigma,
                        style="Mod.TCheckbutton").pack(anchor=tk.W, pady=1)
        ttk.Checkbutton(inner, text="VirusTotal Lookup",
                        variable=self.mod_vt,
                        style="Mod.TCheckbutton").pack(anchor=tk.W, pady=1)

        vt_row = tk.Frame(inner, bg=BG_PANEL)
        vt_row.pack(fill=tk.X, padx=(18, 0), pady=(0, 2))
        tk.Label(vt_row, text="API Key:", bg=BG_PANEL, fg=TEXT_DIM,
                 font=("Segoe UI", 8)).pack(side=tk.LEFT)
        tk.Entry(vt_row, textvariable=self.vt_api_key_var, bg=BG_INPUT,
                 fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                 font=("Segoe UI", 8), relief=tk.FLAT, show="•",
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT).pack(side=tk.LEFT, fill=tk.X,
                                              expand=True, padx=(4, 0), ipady=1)

        self._separator(inner)

        # ── EXPORT OPTIONS ──
        self._cat_label(inner, "📤 EXPORT")

        self.export_pdf = tk.BooleanVar(value=True)
        self.export_json = tk.BooleanVar(value=False)
        self.export_csv = tk.BooleanVar(value=False)

        for text, var in [("PDF Report", self.export_pdf),
                          ("JSON Timeline", self.export_json),
                          ("CSV Timeline", self.export_csv)]:
            ttk.Checkbutton(inner, text=text, variable=var,
                            style="Export.TCheckbutton").pack(anchor=tk.W, pady=1)

        # Footer
        tk.Label(inner, text=f"{platform.system()} {platform.release()}  •  Python {platform.python_version()}",
                 bg=BG_PANEL, fg=TEXT_DIM, font=("Segoe UI", 7)
                 ).pack(side=tk.BOTTOM, anchor=tk.W, pady=(8, 0))

    def _cat_label(self, parent, text):
        tk.Label(parent, text=text, bg=BG_PANEL, fg=ACCENT,
                 font=("Segoe UI", 8, "bold")).pack(anchor=tk.W, pady=(6, 3))

    def _separator(self, parent):
        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X, pady=(6, 2))

    # ── Dashboard (Right Side) ───────────────────────────────────────────────
    def _build_dashboard(self, parent):
        dash = ttk.Frame(parent)
        dash.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # ── Progress Bar ──
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(
            dash, variable=self.progress_var, maximum=100,
            style="Green.Horizontal.TProgressbar")
        self.progress_bar.pack(fill=tk.X, padx=16, pady=(10, 0))

        # ── Status text ──
        status_row = tk.Frame(dash, bg=BG_DARK)
        status_row.pack(fill=tk.X, padx=16, pady=(4, 0))
        self.status_var = tk.StringVar(value="Ready — select modules and click Run Investigation")
        tk.Label(status_row, textvariable=self.status_var, bg=BG_DARK,
                 fg=TEXT_SECONDARY, font=("Segoe UI", 9)).pack(side=tk.LEFT)

        # ── Stats Cards ──
        stats_frame = tk.Frame(dash, bg=BG_DARK)
        stats_frame.pack(fill=tk.X, padx=16, pady=(8, 0))

        self.stat_cards = {}
        cards_config = [
            ("artifacts", "Evidence Items", "0", "StatVal.TLabel"),
            ("timeline", "Timeline Events", "0", "StatVal.TLabel"),
            ("alerts", "Alerts", "0", "StatGreen.TLabel"),
            ("modules", "Modules", "0 / 0", "StatVal.TLabel"),
        ]
        for i, (key, label, default, style) in enumerate(cards_config):
            card = tk.Frame(stats_frame, bg=BG_CARD, highlightthickness=1,
                            highlightbackground=BORDER)
            card.grid(row=0, column=i, padx=(0, 6) if i < 3 else 0,
                      sticky="nsew")
            stats_frame.columnconfigure(i, weight=1)

            val_lbl = ttk.Label(card, text=default, style=style)
            val_lbl.pack(pady=(10, 1))
            ttk.Label(card, text=label, style="StatLbl.TLabel").pack(pady=(0, 8))
            self.stat_cards[key] = val_lbl

        # ── Notebook ──
        self.notebook = ttk.Notebook(dash)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(10, 12))

        # Log tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="  📋 Collection Log  ")

        self.log_text = scrolledtext.ScrolledText(
            log_frame, bg=BG_CARD, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
            font=("Cascadia Code", 9), relief=tk.FLAT, wrap=tk.WORD,
            state=tk.DISABLED, borderwidth=0
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
        self.log_text.tag_config("info", foreground=ACCENT_GREEN)
        self.log_text.tag_config("warn", foreground=ACCENT_AMBER)
        self.log_text.tag_config("error", foreground=ACCENT_RED)
        self.log_text.tag_config("header", foreground=ACCENT,
                                 font=("Cascadia Code", 9, "bold"))

        # Timeline tab
        timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(timeline_frame, text="  🕐 Timeline  ")

        cols = ("time", "type", "source", "event")
        self.timeline_tree = ttk.Treeview(timeline_frame, columns=cols,
                                          show="headings")
        self.timeline_tree.heading("time", text="Timestamp")
        self.timeline_tree.heading("type", text="Type")
        self.timeline_tree.heading("source", text="Source")
        self.timeline_tree.heading("event", text="Event")
        self.timeline_tree.column("time", width=160, minwidth=130)
        self.timeline_tree.column("type", width=90, minwidth=70)
        self.timeline_tree.column("source", width=90, minwidth=70)
        self.timeline_tree.column("event", width=350, minwidth=200)

        vsb = ttk.Scrollbar(timeline_frame, orient="vertical",
                            command=self.timeline_tree.yview)
        self.timeline_tree.configure(yscrollcommand=vsb.set)
        self.timeline_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True,
                                padx=(3, 0), pady=3)
        vsb.pack(side=tk.RIGHT, fill=tk.Y, pady=3, padx=(0, 3))

        # Module Status tab
        status_tab = ttk.Frame(self.notebook)
        self.notebook.add(status_tab, text="  📊 Module Status  ")

        cols_s = ("module", "status", "count", "duration")
        self.status_tree = ttk.Treeview(status_tab, columns=cols_s,
                                        show="headings")
        self.status_tree.heading("module", text="Module")
        self.status_tree.heading("status", text="Status")
        self.status_tree.heading("count", text="Items Found")
        self.status_tree.heading("duration", text="Duration")
        self.status_tree.column("module", width=180)
        self.status_tree.column("status", width=100)
        self.status_tree.column("count", width=100)
        self.status_tree.column("duration", width=100)
        self.status_tree.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _log(self, msg, tag="info"):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _update_stat(self, key, value, style=None):
        def _do():
            self.stat_cards[key].configure(text=str(value))
            if style:
                self.stat_cards[key].configure(style=style)
        self.root.after(0, _do)

    def _update_progress(self, value):
        self.root.after(0, lambda: self.progress_var.set(value))

    def _add_module_status(self, module, status, count, duration):
        def _do():
            icon = "✓" if status == "Done" else ("⏭" if status == "Skipped" else "✗")
            self.status_tree.insert("", tk.END,
                                    values=(module, f"{icon} {status}",
                                            str(count), f"{duration:.1f}s"))
        self.root.after(0, _do)

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

    # ── Investigation Runner ──────────────────────────────────────────────────
    def _run_investigation(self):
        case_id = self.case_id_var.get().strip()
        case_name = self.case_name_var.get().strip() or 'Forensic Investigation'
        investigator = self.investigator_var.get().strip()
        target = self.target_var.get().strip()

        if not case_id or not investigator:
            messagebox.showwarning("Missing Info",
                                   "Please fill in Case ID and Investigator name.")
            return

        self.run_btn.configure(state=tk.DISABLED)
        self.status_var.set("⏳ Investigation running...")
        self._update_progress(0)

        # Clear previous
        for item in self.status_tree.get_children():
            self.status_tree.delete(item)

        thread = threading.Thread(target=self._collect,
                                  args=(case_id, case_name, investigator, target),
                                  daemon=True)
        thread.start()

    def _collect(self, case_id, case_name, investigator, target):
        try:
            db_path = f"forensics_{case_id}.db"
            if os.path.exists(db_path):
                os.remove(db_path)

            db = DBManager(db_path)
            db.insert_case_metadata(case_id, investigator,
                                    case_name, target)
            self.db = db
            self.case_id = case_id

            total_alerts = 0
            total_artifacts = 0

            self._log("=" * 55, "header")
            self._log("  TRIAGEHOUND — Investigation Started", "header")
            self._log("=" * 55, "header")
            self._log(f"  Case: {case_id}  |  Investigator: {investigator}"
                      f"  |  Target: {target}")
            self._log("")

            # Build module list for progress tracking
            modules = []
            if self.mod_processes.get():  modules.append("processes")
            if self.mod_recent.get():     modules.append("recent")
            if self.mod_startup.get():    modules.append("startup")
            if self.mod_usb.get():        modules.append("usb")
            if self.mod_browser.get():    modules.append("browser")
            if self.mod_evtx.get():       modules.append("evtx")
            if self.mod_prefetch.get():   modules.append("prefetch")
            if self.mod_shimcache.get():  modules.append("shimcache")
            if self.mod_usn.get():        modules.append("usn")
            if self.mod_vss.get():        modules.append("vss")
            if self.mod_yara.get():       modules.append("yara")
            if self.mod_sigma.get():      modules.append("sigma")
            if self.mod_vt.get():         modules.append("vt")
            modules.append("timeline")
            total_steps = len(modules)
            step = 0
            completed_modules = 0

            def advance(name=""):
                nonlocal step, completed_modules
                step += 1
                completed_modules += 1
                self._update_progress((step / total_steps) * 100)
                self._update_stat("modules", f"{completed_modules} / {total_steps}")

            # ── Processes ──
            if self.mod_processes.get():
                t0 = datetime.now()
                self._log("[*] Collecting running processes...", "header")
                procs = collect_processes()
                for p in procs:
                    db.insert_evidence('process', 'psutil',
                                       f"Process: {p['name']} (PID: {p['pid']})",
                                       p['start_time'], p, case_id)
                total_artifacts += len(procs)
                self._log(f"    ✓ {len(procs)} processes collected.", "info")
                self._add_module_status("Running Processes", "Done", len(procs),
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── Recent files ──
            if self.mod_recent.get():
                t0 = datetime.now()
                self._log("[*] Collecting recent files...", "header")
                rfiles = collect_recent_files()
                for rf in rfiles:
                    db.insert_evidence('recent_file', 'Registry',
                                       f"Recent File: {rf['filename']}",
                                       None, rf, case_id)
                total_artifacts += len(rfiles)
                self._log(f"    ✓ {len(rfiles)} recent file entries.", "info")
                self._add_module_status("Recent Files", "Done", len(rfiles),
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── Startup entries ──
            if self.mod_startup.get():
                t0 = datetime.now()
                self._log("[*] Collecting startup entries...", "header")
                entries = collect_startup_entries()
                for se in entries:
                    flag = " [SUSPICIOUS]" if se.get('flagged_suspicious') else ""
                    db.insert_evidence('startup_entry', 'Registry',
                                       f"Startup: {se['name']} -> {se['command']}{flag}",
                                       None, se, case_id)
                suspicious = sum(1 for s in entries if s.get('flagged_suspicious'))
                total_artifacts += len(entries)
                if suspicious > 0:
                    total_alerts += suspicious
                self._log(f"    ✓ {len(entries)} startup entries "
                          f"({suspicious} flagged).",
                          "info" if suspicious == 0 else "warn")
                self._add_module_status("Startup Programs", "Done", len(entries),
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── USB devices ──
            if self.mod_usb.get():
                t0 = datetime.now()
                self._log("[*] Collecting USB device history...", "header")
                usb_devs = collect_usb_history()
                for ud in usb_devs:
                    db.insert_evidence('usb_device', 'Registry',
                                       f"USB: {ud.get('friendly_name', ud.get('device_id', '?'))}",
                                       None, ud, case_id)
                total_artifacts += len(usb_devs)
                self._log(f"    ✓ {len(usb_devs)} USB devices.", "info")
                self._add_module_status("USB Devices", "Done", len(usb_devs),
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── Browser history ──
            if self.mod_browser.get():
                t0 = datetime.now()
                self._log("[*] Collecting browser history...", "header")
                bh = collect_browser_history()
                for entry in bh:
                    db.insert_evidence('browser_history', 'Browser',
                                       f"Browser: {entry.get('title', '?')} "
                                       f"({entry.get('browser', '?')})",
                                       entry.get('last_visited'), entry, case_id)
                total_artifacts += len(bh)
                self._log(f"    ✓ {len(bh)} browser history entries.", "info")
                self._add_module_status("Browser History", "Done", len(bh),
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── Event Logs ──
            if self.mod_evtx.get():
                t0 = datetime.now()
                evtx_path = self.evtx_path_var.get().strip()
                if evtx_path and os.path.exists(evtx_path):
                    self._log(f"[*] Parsing event log: "
                              f"{os.path.basename(evtx_path)}...", "header")
                    events = parse_evtx(evtx_path)
                    for ev in events:
                        db.insert_evidence('event_log', 'EVTX Parser',
                                           f"Event ID {ev.get('event_id', '?')}: "
                                           f"{ev.get('message', '')}",
                                           ev.get('timestamp'), ev, case_id)
                    total_artifacts += len(events)
                    self._log(f"    ✓ {len(events)} event log entries.", "info")
                    self._add_module_status("Event Logs", "Done", len(events),
                                            (datetime.now() - t0).total_seconds())
                else:
                    self._log("    ⚠ No valid .evtx path provided.", "warn")
                    self._add_module_status("Event Logs", "Skipped", 0, 0)
                advance()

            # ── Prefetch ──
            if self.mod_prefetch.get():
                t0 = datetime.now()
                self._log("[*] Parsing Prefetch files...", "header")
                pf_entries = collect_prefetch()
                if pf_entries:
                    for pf in pf_entries:
                        db.insert_evidence(
                            'prefetch', 'Prefetch Parser',
                            f"Executed: {pf['executable_name']} "
                            f"(x{pf['run_count']}) last at {pf['last_run']}",
                            pf['last_run'], pf, case_id)
                    total_artifacts += len(pf_entries)
                    self._log(f"    ✓ {len(pf_entries)} prefetch entries.", "info")
                else:
                    self._log("    ⚠ No prefetch entries. "
                              "Try running as Administrator.", "warn")
                self._add_module_status("Prefetch Files", "Done",
                                        len(pf_entries) if pf_entries else 0,
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── USN Journal ──
            if self.mod_usn.get():
                t0 = datetime.now()
                self._log("[*] Parsing USN Journal...", "header")
                usn_entries = collect_usn_journal()
                if usn_entries:
                    for entry in usn_entries:
                        db.insert_evidence(
                            'usn_journal', 'USN Journal',
                            f"USN: {entry['filename']} "
                            f"[{entry['reason_summary']}]",
                            entry['timestamp'], entry, case_id)
                    total_artifacts += len(usn_entries)
                    self._log(f"    ✓ {len(usn_entries)} USN journal entries.",
                              "info")
                else:
                    self._log("    ⚠ No USN entries. "
                              "Try running as Administrator.", "warn")
                self._add_module_status("USN Journal", "Done",
                                        len(usn_entries) if usn_entries else 0,
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── ShimCache ──
            if self.mod_shimcache.get():
                t0 = datetime.now()
                self._log("[*] Parsing ShimCache...", "header")
                shim_entries = collect_shimcache()
                if shim_entries:
                    for entry in shim_entries:
                        db.insert_evidence(
                            'shimcache', 'ShimCache',
                            f"ShimCache: {os.path.basename(entry['executable_path'])} "
                            f"(modified: {entry['last_modified']})",
                            entry['last_modified'], entry, case_id)
                    total_artifacts += len(shim_entries)
                    self._log(f"    ✓ {len(shim_entries)} ShimCache entries.",
                              "info")
                else:
                    self._log("    ⚠ No ShimCache entries found.", "warn")
                self._add_module_status("ShimCache", "Done",
                                        len(shim_entries) if shim_entries else 0,
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── VSS ──
            if self.mod_vss.get():
                t0 = datetime.now()
                self._log("[*] Scanning Volume Shadow Copies...", "header")
                vss_results = collect_vss_info()
                if vss_results:
                    for vss in vss_results:
                        db.insert_evidence(
                            'vss', 'VSS Extractor',
                            f"Shadow Copy: {vss['creation_time']} "
                            f"({len(vss['artifacts_found'])} artifacts)",
                            vss['creation_time'], vss, case_id)
                    total_artifacts += len(vss_results)
                    self._log(f"    ✓ {len(vss_results)} shadow copies.", "info")
                else:
                    self._log("    ⚠ No shadow copies found. "
                              "Try running as Administrator.", "warn")
                self._add_module_status("Shadow Copies", "Done",
                                        len(vss_results) if vss_results else 0,
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── YARA ──
            if self.mod_yara.get():
                t0 = datetime.now()
                self._log("[*] YARA Malware Scan...", "header")
                compiled = compile_rules('rules')
                yara_hits = 0
                if compiled:
                    scan_targets = []
                    if self.mod_startup.get():
                        scan_targets = [se['command'] for se in entries
                                        if os.path.isfile(se.get('command', ''))]
                    self._log(f"    Scanning {len(scan_targets)} executables...")
                    for target_path in scan_targets:
                        matches = scan_file(compiled, target_path)
                        for m in matches:
                            yara_hits += 1
                            self._log(
                                f"    [!!] MATCH: {m['rule']} "
                                f"[{m.get('severity', '?')}] "
                                f"in {os.path.basename(target_path)}", "error")
                            db.insert_evidence(
                                'yara_match', 'YARA Scanner',
                                f"YARA Hit: {m['rule']} ({m['description']}) "
                                f"in {os.path.basename(target_path)}",
                                None, m, case_id)
                    total_alerts += yara_hits
                    if yara_hits == 0:
                        self._log("    ✓ No malware signatures detected.", "info")
                    else:
                        self._log(f"    [!!] {yara_hits} YARA match(es)!", "error")
                else:
                    self._log("    ⚠ No YARA rules in rules/ directory.", "warn")
                self._add_module_status("YARA Scan", "Done", yara_hits,
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── Sigma ──
            if self.mod_sigma.get():
                t0 = datetime.now()
                self._log("[*] Sigma Rules Scan...", "header")
                evtx_path = self.evtx_path_var.get().strip()
                sigma_count = 0
                if evtx_path and os.path.exists(evtx_path):
                    sigma_rules = load_sigma_rules('sigma_rules')
                    if sigma_rules:
                        all_events = parse_evtx(evtx_path, extract_all=True)
                        sigma_alerts = match_events(sigma_rules, all_events)
                        sigma_count = len(sigma_alerts)
                        for alert in sigma_alerts:
                            db.insert_evidence(
                                'sigma_alert', 'Sigma Engine',
                                f"Sigma: {alert['rule_title']} "
                                f"[{alert['rule_level'].upper()}]",
                                alert['matched_event'].get('timestamp'),
                                alert, case_id)
                            self._log(
                                f"    [!!] SIGMA: {alert['rule_title']} "
                                f"[{alert['rule_level'].upper()}]", "error")
                        total_alerts += sigma_count
                        if not sigma_alerts:
                            self._log("    ✓ No Sigma matches.", "info")
                    else:
                        self._log("    ⚠ No Sigma rules in sigma_rules/.", "warn")
                else:
                    self._log("    ⚠ Sigma scan requires .evtx file.", "warn")
                self._add_module_status("Sigma Rules", "Done", sigma_count,
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── VirusTotal ──
            if self.mod_vt.get():
                t0 = datetime.now()
                self._log("[*] VirusTotal Hash Lookups...", "header")
                api_key = self.vt_api_key_var.get().strip()
                vt_count = 0
                if api_key:
                    from modules.hashing import hash_file as compute_hash
                    vt_targets = []
                    if self.mod_startup.get():
                        for se in entries:
                            cmd = se.get('command', '')
                            if os.path.isfile(cmd):
                                result = compute_hash(cmd)
                                vt_targets.append(
                                    (os.path.basename(cmd), result['sha256']))
                    self._log(f"    Checking {len(vt_targets)} hashes...")
                    def vt_cb(label, result):
                        if result.get('is_malicious'):
                            self._log(f"    [!!] MALICIOUS: {label} — "
                                      f"{result['detection_ratio']}", "error")
                        elif result.get('status') == 'found':
                            self._log(f"    [OK] {label} — "
                                      f"{result['detection_ratio']}", "info")
                        else:
                            self._log(f"    [--] {label} — "
                                      f"{result.get('status', 'unknown')}", "info")
                    vt_results = vt_batch_check(vt_targets, api_key, callback=vt_cb)
                    for label, result in vt_results:
                        db.insert_evidence('virustotal', 'VirusTotal API',
                                           f"VT: {label} — "
                                           f"{result['detection_ratio']}",
                                           None, result, case_id)
                        if result.get('is_malicious'):
                            vt_count += 1
                    total_alerts += vt_count
                else:
                    self._log("    ⚠ No API key provided.", "warn")
                self._add_module_status("VirusTotal", "Done", vt_count,
                                        (datetime.now() - t0).total_seconds())
                advance()

            # ── Timeline ──
            t0 = datetime.now()
            self._log("")
            self._log("[*] Generating timeline...", "header")
            self.timeline_data = generate_timeline(db_path, case_id)
            self._log(f"    ✓ {len(self.timeline_data)} timeline events.", "info")
            self._add_module_status("Timeline", "Done",
                                    len(self.timeline_data),
                                    (datetime.now() - t0).total_seconds())
            advance()

            # Update dashboard
            self._update_stat("artifacts", f"{total_artifacts:,}")
            self._update_stat("timeline", f"{len(self.timeline_data):,}")
            if total_alerts > 0:
                self._update_stat("alerts", str(total_alerts), "StatRed.TLabel")
            else:
                self._update_stat("alerts", "0", "StatGreen.TLabel")

            self.root.after(0, self._populate_timeline)

            # ── Exports ──
            if self.export_pdf.get():
                report_path = f"report_{case_id}.pdf"
                case_info = {
                    'case_id': case_id,
                    'case_name': case_name,
                    'investigator_name': investigator,
                    'target_system': target
                }
                generate_pdf_report(case_info, self.timeline_data,
                                    report_path, db_manager=db)
                self._log(f"    ✓ PDF report: {report_path}", "info")

            if self.export_json.get():
                json_path = f"timeline_{case_id}.json"
                export_to_json(self.timeline_data, json_path)
                self._log(f"    ✓ JSON export: {json_path}", "info")

            if self.export_csv.get():
                csv_path = f"timeline_{case_id}.csv"
                export_to_csv(self.timeline_data, csv_path)
                self._log(f"    ✓ CSV export: {csv_path}", "info")

            # Seal
            if self.export_pdf.get():
                self._log("")
                self._log("[*] Sealing artifacts...", "header")
                sp, sd = seal_report(report_path, db_path, case_id)
                for lbl, info in sd['artifacts'].items():
                    if info.get('sha256'):
                        self._log(f"    [{lbl}] SHA256: "
                                  f"{info['sha256'][:32]}...", "info")
                self._log(f"    ✓ Seal manifest: seal_{case_id}.txt", "info")

            self._log("")
            self._log("=" * 55, "header")
            self._log("  ✓ Investigation Complete.", "header")
            self._log("=" * 55, "header")
            self.root.after(0, lambda: self.status_var.set(
                "✓ Investigation complete"))

        except Exception as e:
            self._log(f"\n[ERROR] {e}", "error")
            self._update_stat("modules", "Error", "StatRed.TLabel")
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
        self.notebook.select(1)


def main():
    root = tk.Tk()
    app = ForensicToolkitGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
