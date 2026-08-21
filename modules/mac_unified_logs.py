"""
macOS Unified Logs Collector (v2.0)
======================================
Collects macOS system logs using the native `log show` command.
Equivalent to Windows Event Logs (.evtx).

Requires: sudo privileges for full log access.
"""

import subprocess
import json
import re
from datetime import datetime, timedelta


def collect(db, case_id, hours=24):
    """
    Collect macOS Unified Logs for the last `hours` hours.

    Uses the native `log show` command with predicates to extract
    authentication, process execution, and security-relevant events.

    Args:
        db:       DBManager instance
        case_id:  Case identifier string
        hours:    How many hours back to search (default: 24)

    Returns:
        list of dicts with collected log entries
    """
    results = []

    # Calculate the time window
    start_time = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

    # Define predicates for forensically-relevant log categories
    predicates = {
        "authentication": (
            'eventMessage CONTAINS "authentication" OR '
            'eventMessage CONTAINS "login" OR '
            'eventMessage CONTAINS "sudo" OR '
            'eventMessage CONTAINS "failed"'
        ),
        "process_execution": (
            'processImagePath CONTAINS "bash" OR '
            'processImagePath CONTAINS "zsh" OR '
            'processImagePath CONTAINS "python" OR '
            'processImagePath CONTAINS "curl" OR '
            'processImagePath CONTAINS "wget" OR '
            'processImagePath CONTAINS "osascript"'
        ),
        "security": (
            'subsystem == "com.apple.securityd" OR '
            'subsystem == "com.apple.authd" OR '
            'category == "security"'
        ),
    }

    for category, predicate in predicates.items():
        try:
            cmd = [
                "log", "show",
                "--predicate", predicate,
                "--start", start_time,
                "--style", "json",
                "--info",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2-minute timeout per category
            )

            if result.returncode != 0:
                print(f"    [!] log show returned error for {category}: {result.stderr[:200]}")
                continue

            # Parse JSON output from log show
            entries = _parse_log_json(result.stdout, category)

            for entry in entries:
                detail = entry.get("eventMessage", "")[:200]
                timestamp = entry.get("timestamp", datetime.now().isoformat())
                raw_data = {
                    "category": category,
                    "process": entry.get("processImagePath", "unknown"),
                    "pid": entry.get("processID", 0),
                    "subsystem": entry.get("subsystem", ""),
                    "message": entry.get("eventMessage", "")[:500],
                    "sender": entry.get("senderImagePath", ""),
                    "timestamp": timestamp,
                }

                db.insert_evidence(
                    evidence_type="mac_unified_log",
                    source=f"log show ({category})",
                    detail=f"[{category.upper()}] {detail}",
                    timestamp=timestamp,
                    raw_data=raw_data,
                    case_id=case_id,
                )
                results.append(raw_data)

        except subprocess.TimeoutExpired:
            print(f"    [!] Timeout collecting {category} logs (>120s)")
        except FileNotFoundError:
            print("    [!] 'log' command not found. Are you running on macOS?")
            break
        except Exception as e:
            print(f"    [!] Error collecting {category}: {e}")

    print(f"    -> Collected {len(results)} Unified Log entries across {len(predicates)} categories.")
    return results


def _parse_log_json(raw_output, category):
    """
    Parse the JSON output from `log show --style json`.

    The output is a JSON array of log entry objects. If JSON parsing fails
    (e.g., truncated output), fall back to line-by-line regex extraction.
    """
    entries = []

    # Try direct JSON parse first
    try:
        parsed = json.loads(raw_output)
        if isinstance(parsed, list):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass

    # Fallback: line-by-line regex for non-JSON output
    pattern = re.compile(
        r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*[+-]\d{4})\s+"
        r"(\S+)\s+"                   # Thread ID
        r"(0x[0-9a-f]+)\s+"           # Activity ID
        r"(\d+)\s+"                    # PID
        r"(\d+)\s+"                    # EUID
        r"(\S+)\s+"                    # Process name
        r"(.+)"                        # Message
    )

    for line in raw_output.splitlines():
        m = pattern.match(line.strip())
        if m:
            entries.append({
                "timestamp": m.group(1),
                "processID": int(m.group(4)),
                "processImagePath": m.group(6),
                "eventMessage": m.group(7),
                "subsystem": "",
                "senderImagePath": "",
            })

    return entries
""" 
    Module contract:
    - collect(db, case_id) is the only public function.
    - All evidence is inserted via db.insert_evidence() with type 'mac_unified_log'.
    - Returns a list of raw_data dicts for downstream pipeline consumption.
"""
