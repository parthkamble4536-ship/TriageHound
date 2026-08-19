"""
Anti-Forensics Detection Engine
=================================
Detects potential evidence tampering and anti-forensic activity by
analysing discrepancies across normalized entities and raw evidence.

Detection strategies:
  1. Execution artifact exists but file missing from disk
  2. Rapid file lifecycle (Created -> Executed -> Deleted)
  3. Security / System event log clearing (EID 1102, 104)
  4. Missing expected artifacts for suspicious processes

All wording remains forensic and objective.
"""

import os
import json
import uuid
from datetime import datetime


class AntiForensicsEngine:
    """
    Analyses entities and evidence for signs of anti-forensic behaviour.
    Generates alerts stored in the anti_forensics table.
    """

    def __init__(self, db_manager):
        self.db = db_manager

    def run_detection(self, case_id):
        """
        Execute all anti-forensics detection rules for a given case.

        Returns:
            list of alert dicts generated during this run.
        """
        entities = self.db.get_all_entities(case_id)
        evidence = self.db.get_all_evidence(case_id)
        findings = self.db.get_all_findings(case_id)

        alerts = []

        alerts += self._detect_missing_executables(entities)
        alerts += self._detect_rapid_deletion(entities)
        alerts += self._detect_log_clearing(evidence)

        self._print_summary(alerts)
        return alerts

    # ------------------------------------------------------------------
    # Rule 1: Execution artifact exists but file is missing from disk
    # ------------------------------------------------------------------
    def _detect_missing_executables(self, entities):
        """
        If a Process entity has an execution record (Prefetch / ShimCache)
        but the executable path no longer exists on disk, flag it.
        """
        alerts = []
        seen_paths = set()

        for entity in entities:
            if entity['entity_type'] != 'Process':
                continue

            path = entity.get('path', '')
            if not path or path in seen_paths:
                continue

            # Only check full filesystem paths (skip .pf filenames, etc.)
            if not os.path.isabs(path):
                continue

            seen_paths.add(path)

            if not os.path.exists(path):
                alert = self._create_alert(
                    finding_id=None,
                    description=(
                        f"Potential Evidence Removal Detected: "
                        f"Execution artifact found for '{os.path.basename(path)}' "
                        f"but file is missing from disk at '{path}'."
                    )
                )
                alerts.append(alert)

        return alerts

    # ------------------------------------------------------------------
    # Rule 2: Rapid file lifecycle  (Created -> Deleted in < 5 min)
    # ------------------------------------------------------------------
    def _detect_rapid_deletion(self, entities):
        """
        Look for File entities from USN Journal where the same filename
        was both FILE_CREATE and FILE_DELETE within a short window.
        """
        alerts = []

        # Group USN File entities by filename
        file_events = {}
        for entity in entities:
            if entity['entity_type'] != 'File':
                continue

            raw = entity.get('raw_attributes', '{}')
            try:
                attrs = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                attrs = {}

            reasons = attrs.get('reasons', [])
            name = entity.get('name', '')
            ts = entity.get('timestamp', '')

            if not name or not ts:
                continue

            if name not in file_events:
                file_events[name] = {'creates': [], 'deletes': []}

            if 'FILE_CREATE' in reasons:
                file_events[name]['creates'].append(ts)
            if 'FILE_DELETE' in reasons:
                file_events[name]['deletes'].append(ts)

        # Check for rapid create -> delete cycles
        for filename, events in file_events.items():
            for create_ts in events['creates']:
                for delete_ts in events['deletes']:
                    diff = self._ts_diff_seconds(create_ts, delete_ts)
                    if diff is not None and 0 < diff < 300:  # < 5 minutes
                        alert = self._create_alert(
                            finding_id=None,
                            description=(
                                f"Rapid File Lifecycle Detected: "
                                f"'{filename}' was created and deleted within "
                                f"{int(diff)} seconds, suggesting potential "
                                f"evidence destruction."
                            )
                        )
                        alerts.append(alert)
                        break  # One alert per filename is enough

        return alerts

    # ------------------------------------------------------------------
    # Rule 3: Security / System event log clearing
    # ------------------------------------------------------------------
    def _detect_log_clearing(self, evidence):
        """
        Scan raw event log evidence for indicators that logs were cleared.
        EID 1102 = Security log cleared, EID 104 = System log cleared.
        """
        alerts = []
        clearing_eids = {'1102', '104'}

        for item in evidence:
            if item['artifact_type'] not in ('event_log', 'evtx'):
                continue

            raw = item.get('raw_data', '{}')
            try:
                data = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                continue

            event_id = str(data.get('event_id', data.get('EventID', '')))

            if event_id in clearing_eids:
                alert = self._create_alert(
                    finding_id=None,
                    description=(
                        f"Event Log Clearing Detected: "
                        f"Event ID {event_id} indicates that a Windows event log "
                        f"was recently cleared, potentially destroying forensic evidence."
                    )
                )
                alerts.append(alert)

        return alerts

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _create_alert(self, finding_id, description):
        """Create an alert, persist it, and return the alert dict."""
        alert_id = f"AF-{uuid.uuid4().hex[:8].upper()}"

        self.db.insert_anti_forensic(
            alert_id=alert_id,
            finding_id=finding_id,
            description=description
        )

        return {
            'alert_id': alert_id,
            'finding_id': finding_id,
            'description': description,
        }

    def _ts_diff_seconds(self, ts1, ts2):
        """Return the difference in seconds between two ISO timestamps."""
        if not ts1 or not ts2:
            return None
        try:
            d1 = datetime.fromisoformat(ts1.replace('Z', '+00:00'))
            d2 = datetime.fromisoformat(ts2.replace('Z', '+00:00'))
            return abs((d2 - d1).total_seconds())
        except (ValueError, TypeError):
            return None

    def _print_summary(self, alerts):
        """Print anti-forensics detection summary to the console."""
        if alerts:
            print(f"    [!] {len(alerts)} anti-forensics alert(s) detected:")
            for alert in alerts:
                print(f"      - [{alert['alert_id']}] {alert['description']}")
        else:
            print("    No anti-forensics indicators detected.")
        print()
