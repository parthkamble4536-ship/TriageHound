"""
macOS Telemetry Collector (v2.0 - Advanced)
==============================================
Collects advanced macOS telemetry artifacts:

1. Quarantine Events (com.apple.LaunchServices.QuarantineEventsV2)
   - Tracks every file downloaded from the internet: URL, browser, timestamp.

2. KnowledgeC Database (knowledgeC.db)
   - Tracks application usage, screen time, device lock/unlock events.
   - Equivalent to Windows UserAssist.

Requires: Full Disk Access for reading user-level databases.
"""

import os
import sqlite3
import glob
from datetime import datetime, timedelta


# macOS Core Data epoch: 2001-01-01 00:00:00 UTC
CORE_DATA_EPOCH = datetime(2001, 1, 1)

# Quarantine Events database paths (per-user)
QUARANTINE_DB_PATTERN = "/Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"

# KnowledgeC database paths (per-user)
KNOWLEDGEC_DB_PATTERN = "/Users/*/Library/Application Support/Knowledge/knowledgeC.db"


def collect(db, case_id):
    """
    Collect macOS Quarantine Events and KnowledgeC telemetry.

    Args:
        db:       DBManager instance
        case_id:  Case identifier string

    Returns:
        list of dicts with telemetry entries
    """
    results = []

    results += _collect_quarantine_events(db, case_id)
    results += _collect_knowledgec(db, case_id)

    print(f"    -> Collected {len(results)} telemetry entries (Quarantine + KnowledgeC).")
    return results


def _collect_quarantine_events(db, case_id):
    """Collect Quarantine Events from all user profiles."""
    entries = []

    for db_path in glob.glob(QUARANTINE_DB_PATTERN):
        user = db_path.split("/Users/")[1].split("/")[0]
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    LSQuarantineEventIdentifier AS event_id,
                    LSQuarantineTimeStamp AS timestamp,
                    LSQuarantineAgentBundleIdentifier AS agent_bundle,
                    LSQuarantineAgentName AS agent_name,
                    LSQuarantineDataURLString AS data_url,
                    LSQuarantineOriginURLString AS origin_url,
                    LSQuarantineSenderName AS sender_name,
                    LSQuarantineSenderAddress AS sender_address,
                    LSQuarantineTypeNumber AS type_number
                FROM LSQuarantineEvent
                ORDER BY LSQuarantineTimeStamp DESC
                LIMIT 500
            """)

            for row in cursor.fetchall():
                # Convert Core Data timestamp to human-readable
                ts_value = row["timestamp"]
                if ts_value:
                    ts_datetime = CORE_DATA_EPOCH + timedelta(seconds=ts_value)
                    ts_str = ts_datetime.isoformat()
                else:
                    ts_str = datetime.now().isoformat()

                origin = row["origin_url"] or ""
                agent = row["agent_name"] or row["agent_bundle"] or "Unknown"
                data_url = row["data_url"] or ""

                raw_data = {
                    "event_id": row["event_id"],
                    "user": user,
                    "timestamp": ts_str,
                    "agent": agent,
                    "origin_url": origin,
                    "data_url": data_url,
                    "sender_name": row["sender_name"] or "",
                    "sender_address": row["sender_address"] or "",
                    "type": row["type_number"],
                    "category": "quarantine",
                }

                # Build a readable detail
                detail = f"[QUARANTINE] User '{user}' downloaded via {agent}"
                if origin:
                    detail += f" from {origin[:100]}"

                db.insert_evidence(
                    evidence_type="mac_telemetry",
                    source="Quarantine Events",
                    detail=detail[:250],
                    timestamp=ts_str,
                    raw_data=raw_data,
                    case_id=case_id,
                )
                entries.append(raw_data)

            conn.close()

        except sqlite3.OperationalError as e:
            if "no such table" in str(e):
                print(f"    [!] Quarantine DB for '{user}' has unexpected schema.")
            else:
                print(f"    [!] Cannot open Quarantine DB for '{user}': {e}")
        except PermissionError:
            print(f"    [!] Permission denied reading Quarantine DB for '{user}'.")
        except Exception as e:
            print(f"    [!] Error reading Quarantine for '{user}': {e}")

    return entries


def _collect_knowledgec(db, case_id):
    """Collect KnowledgeC application usage telemetry from all user profiles."""
    entries = []

    for db_path in glob.glob(KNOWLEDGEC_DB_PATTERN):
        user = db_path.split("/Users/")[1].split("/")[0]
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Query app usage events (equivalent to Windows UserAssist)
            cursor.execute("""
                SELECT
                    ZOBJECT.ZVALUESTRING AS app_bundle,
                    ZOBJECT.ZSTARTDATE AS start_date,
                    ZOBJECT.ZENDDATE AS end_date,
                    ZOBJECT.ZCREATIONDATE AS creation_date,
                    ZSOURCE.ZBUNDLEID AS source_bundle,
                    ZSTRUCTUREDMETADATA.Z_DKAPPLICATIONACTIVITYMETADATAKEY__ACTIVITYTYPE AS activity_type
                FROM ZOBJECT
                LEFT JOIN ZSOURCE ON ZOBJECT.ZSOURCE = ZSOURCE.Z_PK
                LEFT JOIN ZSTRUCTUREDMETADATA ON ZOBJECT.ZSTRUCTUREDMETADATA = ZSTRUCTUREDMETADATA.Z_PK
                WHERE ZOBJECT.ZSTREAMNAME = '/app/usage'
                   OR ZOBJECT.ZSTREAMNAME = '/app/inFocus'
                ORDER BY ZOBJECT.ZSTARTDATE DESC
                LIMIT 500
            """)

            for row in cursor.fetchall():
                app = row["app_bundle"] or "Unknown"

                # Convert Core Data timestamps
                start_ts = row["start_date"]
                if start_ts:
                    start_dt = CORE_DATA_EPOCH + timedelta(seconds=start_ts)
                    ts_str = start_dt.isoformat()
                else:
                    ts_str = datetime.now().isoformat()

                end_ts = row["end_date"]
                if end_ts and start_ts:
                    duration_sec = int(end_ts - start_ts)
                else:
                    duration_sec = 0

                raw_data = {
                    "app_bundle": app,
                    "user": user,
                    "timestamp": ts_str,
                    "duration_seconds": duration_sec,
                    "source_bundle": row["source_bundle"] or "",
                    "activity_type": row["activity_type"] or "",
                    "category": "knowledgec",
                }

                # Build readable detail
                if duration_sec > 0:
                    minutes = duration_sec // 60
                    detail = f"[KNOWLEDGEC] User '{user}' used {app} for {minutes}m{duration_sec % 60}s"
                else:
                    detail = f"[KNOWLEDGEC] User '{user}' launched {app}"

                db.insert_evidence(
                    evidence_type="mac_telemetry",
                    source="KnowledgeC",
                    detail=detail[:250],
                    timestamp=ts_str,
                    raw_data=raw_data,
                    case_id=case_id,
                )
                entries.append(raw_data)

            conn.close()

        except sqlite3.OperationalError as e:
            if "no such table" in str(e):
                print(f"    [!] KnowledgeC DB for '{user}' has unexpected schema (macOS version mismatch?).")
            else:
                print(f"    [!] Cannot open KnowledgeC DB for '{user}': {e}")
        except PermissionError:
            print(f"    [!] Permission denied reading KnowledgeC for '{user}'. Grant Full Disk Access.")
        except Exception as e:
            print(f"    [!] Error reading KnowledgeC for '{user}': {e}")

    return entries
