import uuid
from datetime import datetime

class CorrelationEngine:
    """
    Analyzes normalized entities to find cross-artifact relationships.
    Generates unified Investigation Findings based on heuristic rules.
    """
    def __init__(self, db_manager):
        self.db = db_manager

    def run_correlation(self, case_id):
        entities = self.db.get_all_entities(case_id)
        if not entities:
            return

        try:
            self._rule_powershell_execution(entities)
        except Exception:
            pass
        try:
            self._rule_executable_dropped(entities)
        except Exception:
            pass
        # Additional rules (e.g., Persistence, Lateral Movement) will be added in future iterations.

    def _rule_powershell_execution(self, entities):
        # Find all Process entities involving PowerShell
        ps_entities = [e for e in entities if e['entity_type'] == 'Process' and e['name'] and 'powershell.exe' in str(e['name']).lower()]
        
        processed_ids = set()

        for ps in ps_entities:
            if ps['entity_id'] in processed_ids:
                continue

            # Find all other PowerShell entities that occurred around the same time (within 1 hour)
            related = [e for e in ps_entities if abs(self._ts_diff(ps['timestamp'], e['timestamp'])) < 3600]
            
            for rel in related:
                processed_ids.add(rel['entity_id'])

            finding_id = f"FND-PS-{uuid.uuid4().hex[:8].upper()}"
            
            # The more artifacts confirm this (e.g., Prefetch + ShimCache + EventLog), the higher the confidence
            confidence = 10 * len(related)
            severity = "HIGH" if len(related) > 1 else "MEDIUM"
            
            self.db.insert_finding(
                finding_id=finding_id,
                title="Suspicious PowerShell Execution",
                description=f"PowerShell execution detected, corroborated by {len(related)} artifact(s).",
                severity=severity,
                confidence_contribution=confidence,
                timestamp=ps['timestamp']
            )
            
            # Link evidence to the finding
            for rel in related:
                self.db.insert_correlation(finding_id, entity_id=rel['entity_id'], evidence_id=rel['evidence_id'])
                
    def _rule_executable_dropped(self, entities):
        # Look for executable files that were created (usually found via USN Journal)
        exe_files = [e for e in entities if e['entity_type'] == 'File' and e['name'] and str(e['name']).lower().endswith('.exe')]
        
        for exe in exe_files:
            finding_id = f"FND-EXE-{uuid.uuid4().hex[:8].upper()}"
            self.db.insert_finding(
                finding_id=finding_id,
                title="Executable File Dropped",
                description=f"Executable file '{exe['name']}' was observed on disk.",
                severity="MEDIUM",
                confidence_contribution=15,
                timestamp=exe['timestamp']
            )
            self.db.insert_correlation(finding_id, entity_id=exe['entity_id'], evidence_id=exe['evidence_id'])

    def _ts_diff(self, ts1, ts2):
        """Helper to calculate difference in seconds between two ISO timestamps."""
        if not ts1 or not ts2:
            return 999999
        try:
            # Handle potential 'Z' or missing milliseconds
            d1 = datetime.fromisoformat(ts1.replace('Z', '+00:00'))
            d2 = datetime.fromisoformat(ts2.replace('Z', '+00:00'))
            return (d1 - d2).total_seconds()
        except ValueError:
            return 999999
