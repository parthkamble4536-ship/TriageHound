import argparse
import os
import sys
import platform
from database.db_manager import DBManager

from modules.hashing import hash_file
from modules.process_monitor import collect_processes
from modules.recent_files import collect_recent_files
from modules.startup_analysis import collect_startup_entries
from modules.usb_analysis import collect_usb_history
from modules.browser_analysis import collect_browser_history
from modules.event_logs import parse_evtx
from modules.prefetch_parser import collect_prefetch
from modules.timeline import generate_timeline
from modules.yara_scanner import compile_rules, scan_file
from modules.report_sealer import seal_report
from reports.report_generator import generate_pdf_report
from utils.helpers import export_to_json, export_to_csv


def main():
    parser = argparse.ArgumentParser(description="Digital Forensics Toolkit")
    parser.add_argument('--case', type=str, required=True, help="Case ID")
    parser.add_argument('--investigator', type=str, required=True, help="Investigator Name")
    parser.add_argument('--target', type=str, required=True, help="Target System Name")
    parser.add_argument('--db-path', type=str, default='forensics.db', help="Path to SQLite database")
    parser.add_argument('--evtx', type=str, default=None, help="Path to .evtx file for event log parsing")
    parser.add_argument('--hash-file', type=str, default=None, action='append',
                        help="Path to a file to hash (can be specified multiple times)")
    parser.add_argument('--export-json', action='store_true', help="Export timeline to JSON")
    parser.add_argument('--export-csv', action='store_true', help="Export timeline to CSV")
    parser.add_argument('--yara-scan', action='store_true', help="Enable YARA malware scanning on startup entries")
    parser.add_argument('--rules-dir', type=str, default='rules', help="Directory containing .yar YARA rule files")
    parser.add_argument('--prefetch', action='store_true', help="Parse Windows Prefetch files (requires Admin)")

    args = parser.parse_args()

    # Remove stale DB if it exists to start fresh for this case
    if os.path.exists(args.db_path):
        os.remove(args.db_path)

    # Initialize DB
    db = DBManager(args.db_path)
    db.insert_case_metadata(args.case, args.investigator, "Forensic Investigation", args.target)

    print("=" * 60)
    print("       DIGITAL FORENSICS TOOLKIT")
    print("=" * 60)
    print(f"  Case ID       : {args.case}")
    print(f"  Investigator  : {args.investigator}")
    print(f"  Target System : {args.target}")
    print(f"  Platform      : {platform.system()} {platform.release()}")
    print(f"  Database      : {args.db_path}")
    print("=" * 60)
    print()
    print("[*] Starting Collection Modules...")
    print()

    # ── File Hashing ──────────────────────────────────────────
    if args.hash_file:
        print("  -> Hashing specified files...")
        for fpath in args.hash_file:
            if os.path.exists(fpath):
                result = hash_file(fpath)
                db.insert_file_hash(
                    result['filepath'], result['md5'],
                    result['sha1'], result['sha256'], result['file_size']
                )
                db.insert_evidence(
                    'file_hash', 'Hashing Module',
                    f"Hashed: {os.path.basename(fpath)} (SHA256: {result['sha256'][:16]}...)",
                    None, result, args.case
                )
                print(f"     [{os.path.basename(fpath)}] MD5={result['md5'][:12]}... SHA256={result['sha256'][:12]}...")
            else:
                print(f"     [!] File not found: {fpath}")

    # ── Collect Processes ─────────────────────────────────────
    print("  -> Collecting running processes...")
    processes = collect_processes()
    for p in processes:
        db.insert_evidence(
            'process', 'psutil', f"Process: {p['name']} (PID: {p['pid']})",
            p['start_time'], p, args.case
        )
    print(f"     Found {len(processes)} running processes.")

    # ── Collect Recent Files ──────────────────────────────────
    print("  -> Collecting recent files...")
    recent_files = collect_recent_files()
    for rf in recent_files:
        db.insert_evidence(
            'recent_file', 'Registry', f"Recent File: {rf['filename']}",
            None, rf, args.case
        )
    print(f"     Found {len(recent_files)} recent file entries.")

    # ── Collect Startup Entries ───────────────────────────────
    print("  -> Collecting startup entries...")
    startup_entries = collect_startup_entries()
    for se in startup_entries:
        flag = " [SUSPICIOUS]" if se.get('flagged_suspicious') else ""
        db.insert_evidence(
            'startup_entry', 'Registry', f"Startup: {se['name']} -> {se['command']}{flag}",
            None, se, args.case
        )
    suspicious_count = sum(1 for se in startup_entries if se.get('flagged_suspicious'))
    print(f"     Found {len(startup_entries)} startup entries ({suspicious_count} flagged suspicious).")

    # ── Collect USB History ───────────────────────────────────
    print("  -> Collecting USB device history...")
    usb_history = collect_usb_history()
    for usb in usb_history:
        db.insert_evidence(
            'usb_device', 'Registry', f"USB Device: {usb['friendly_name']}",
            None, usb, args.case
        )
    print(f"     Found {len(usb_history)} USB devices.")

    # ── Collect Browser History ───────────────────────────────
    print("  -> Collecting browser history (Chrome, Edge, Firefox)...")
    browser_history = collect_browser_history()
    for ch in browser_history:
        db.insert_evidence(
            'browser_history', ch['browser'], f"Visited: {ch['title']} ({ch['url']})",
            ch['last_visited'], ch, args.case
        )
    print(f"     Found {len(browser_history)} browser history entries.")

    # ── Parse Event Logs (.evtx) ─────────────────────────────
    if args.evtx:
        print(f"  -> Parsing event log: {args.evtx}...")
        if os.path.exists(args.evtx):
            events = parse_evtx(args.evtx)
            for ev in events:
                db.insert_evidence(
                    'event_log', 'Windows Event Log',
                    f"Event {ev['event_id']}: {ev['description']}",
                    ev['timestamp'], ev, args.case
                )
            print(f"     Found {len(events)} interesting security events.")
        else:
            print(f"     [!] EVTX file not found: {args.evtx}")
    else:
        print("  -> Skipping event log parsing (no --evtx path provided).")

    # -- Prefetch Parsing -----------------------------------------
    if args.prefetch:
        print("  -> Parsing Windows Prefetch files (requires Admin)...")
        pf_entries = collect_prefetch()
        for pf in pf_entries:
            db.insert_evidence(
                'prefetch', 'Prefetch Parser',
                f"Executed: {pf['executable_name']} (x{pf['run_count']}) last at {pf['last_run']}",
                pf['last_run'], pf, args.case
            )
        print(f"     Found {len(pf_entries)} prefetch entries.")
    else:
        print("  -> Skipping Prefetch parsing (use --prefetch to enable).")

    # -- YARA Malware Scan ----------------------------------------
    if args.yara_scan:
        print()
        print("[*] YARA Malware Scan...")
        compiled = compile_rules(args.rules_dir)
        if compiled:
            # Collect file paths from startup entries to scan
            scan_targets = [se['command'] for se in startup_entries if os.path.isfile(se.get('command', ''))]
            print(f"    Scanning {len(scan_targets)} startup executables against YARA rules...")
            yara_hits = 0
            for target_path in scan_targets:
                matches = scan_file(compiled, target_path)
                for m in matches:
                    yara_hits += 1
                    severity_tag = f"[{m['severity']}]" if m.get('severity') else ""
                    print(f"    [!!] MATCH: {m['rule']} {severity_tag} in {os.path.basename(target_path)}")
                    db.insert_evidence(
                        'yara_match', 'YARA Scanner',
                        f"YARA Hit: {m['rule']} ({m['description']}) in {os.path.basename(target_path)}",
                        None, m, args.case
                    )
            if yara_hits == 0:
                print("    No malware signatures detected.")
            else:
                print(f"    [!!] {yara_hits} YARA rule match(es) detected!")
        else:
            print(f"    [!] No YARA rules found in: {args.rules_dir}")
    else:
        print("  -> Skipping YARA scan (use --yara-scan to enable).")


    # ── Generate Timeline ─────────────────────────────────────
    print()
    print("[*] Generating Timeline...")
    timeline_data = generate_timeline(args.db_path, args.case)
    print(f"    Timeline contains {len(timeline_data)} timestamped events.")

    # ── Export CSV / JSON ─────────────────────────────────────
    if args.export_json:
        json_path = f"timeline_{args.case}.json"
        export_to_json(timeline_data, json_path)
        print(f"    Exported timeline to JSON: {json_path}")

    if args.export_csv:
        csv_path = f"timeline_{args.case}.csv"
        export_to_csv(timeline_data, csv_path)
        print(f"    Exported timeline to CSV:  {csv_path}")

    # ── Generate PDF Report ───────────────────────────────────
    report_path = f"report_{args.case}.pdf"
    print(f"[*] Generating PDF Report: {report_path}...")
    case_info = {
        'case_id': args.case,
        'case_name': 'Forensic Investigation',
        'investigator_name': args.investigator,
        'target_system': args.target
    }
    generate_pdf_report(case_info, timeline_data, report_path, db_manager=db)

    # ── Cryptographic Seal ────────────────────────────────────
    print("[*] Sealing investigation artifacts...")
    seal_path, seal_data = seal_report(report_path, args.db_path, args.case)
    for label, info in seal_data['artifacts'].items():
        if info.get('sha256'):
            print(f"    [{label}] SHA256: {info['sha256'][:32]}...")
    print(f"    Seal manifest saved: {seal_path}")

    print()
    print("=" * 60)
    print("  [+] Investigation Complete.")
    print(f"  [+] Report saved to  : {report_path}")
    print(f"  [+] Seal manifest    : {seal_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
