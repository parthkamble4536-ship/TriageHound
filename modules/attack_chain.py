"""
Attack Chain Reconstruction Engine
=====================================
Transforms correlated findings into a sequential narrative of the attack,
ordered chronologically and linked by causal relationships.

Instead of a flat timeline of isolated events, this engine builds a
directed chain:

  User -> Browser -> Downloaded File -> PowerShell -> Executable -> Persistence -> Deletion

Each link in the chain is stored in the attack_chains table and can be
rendered visually in the GUI and PDF report.
"""

import uuid
from datetime import datetime


# Maps finding titles to an attack stage for ordering purposes.
# Lower numbers execute earlier in a typical attack lifecycle.
ATTACK_STAGE_ORDER = {
    'browser':      10,
    'download':     20,
    'execution':    30,
    'powershell':   35,
    'executable':   40,
    'persistence':  50,
    'privilege':    60,
    'lateral':      70,
    'exfiltration': 80,
    'deletion':     90,
    'anti-forensic': 95,
}


def _classify_stage(title):
    """
    Map a finding title to an attack stage number.
    Returns a default middle-stage value if unrecognised.
    """
    title_lower = title.lower() if title else ''
    for keyword, order in ATTACK_STAGE_ORDER.items():
        if keyword in title_lower:
            return order
    return 50  # default


def _infer_relationship(stage_a, stage_b):
    """Infer a human-readable relationship label between two stages."""
    diff = stage_b - stage_a
    if diff <= 0:
        return 'concurrent_with'
    if diff <= 10:
        return 'followed_by'
    if diff <= 30:
        return 'led_to'
    return 'escalated_to'


class AttackChainEngine:
    """
    Builds a sequential attack narrative from correlated findings.
    """

    def __init__(self, db_manager):
        self.db = db_manager

    def reconstruct(self, case_id):
        """
        Build the attack chain for a case.

        Returns:
            list of chain link dicts, each with finding_id, next_finding_id,
            and relationship.
        """
        findings = self.db.get_all_findings(case_id)
        af_alerts = self.db.get_anti_forensics(case_id)

        if not findings and not af_alerts:
            self._print_chain([])
            return []

        # Annotate each finding with its attack stage
        annotated = []
        for f in findings:
            stage = _classify_stage(f['title'])
            annotated.append({
                'finding_id': f['finding_id'],
                'title': f['title'],
                'timestamp': f['timestamp'],
                'stage': stage,
            })

        # If anti-forensics alerts exist, synthesise a virtual finding
        if af_alerts:
            annotated.append({
                'finding_id': af_alerts[0].get('alert_id', 'AF-VIRTUAL'),
                'title': 'Evidence Deletion / Tampering',
                'timestamp': af_alerts[0].get('detected_at', ''),
                'stage': 90,
            })

        # Sort by stage first, then by timestamp for ties
        annotated.sort(key=lambda x: (x['stage'], x['timestamp'] or ''))

        # Build chain links between consecutive findings
        chain_links = []
        for i in range(len(annotated) - 1):
            current = annotated[i]
            next_item = annotated[i + 1]

            relationship = _infer_relationship(current['stage'], next_item['stage'])
            chain_id = f"CHAIN-{uuid.uuid4().hex[:8].upper()}"

            self.db.insert_attack_chain(
                chain_id=chain_id,
                finding_id=current['finding_id'],
                next_finding_id=next_item['finding_id'],
                relationship=relationship
            )

            chain_links.append({
                'chain_id': chain_id,
                'from': current['title'],
                'to': next_item['title'],
                'relationship': relationship,
            })

        # Generate recommendations for each finding
        self._generate_recommendations(findings)

        self._print_chain(chain_links)
        return chain_links

    def _generate_recommendations(self, findings):
        """Attach investigative recommendations to each finding."""
        recommendation_map = {
            'powershell': 'Review PowerShell script block logs (EID 4104) and examine encoded commands.',
            'executable': 'Submit the executable to a sandbox for dynamic analysis. Check VirusTotal.',
            'persistence': 'Inspect startup locations, scheduled tasks, and registry run keys.',
            'browser': 'Examine browser download history and cache for payload delivery.',
            'deletion': 'Check Volume Shadow Copies and USN Journal for recoverable evidence.',
        }
        default_rec = 'Investigate this finding further and correlate with adjacent timeline events.'

        for f in findings:
            title_lower = f['title'].lower() if f['title'] else ''
            rec = default_rec
            for keyword, action in recommendation_map.items():
                if keyword in title_lower:
                    rec = action
                    break
            self.db.insert_recommendation(f['finding_id'], rec)

    def _print_chain(self, chain_links):
        """Print the attack chain narrative to the console."""
        if not chain_links:
            print("    No attack chain could be reconstructed.")
            print()
            return

        print(f"    Attack Chain ({len(chain_links)} link(s)):")
        for i, link in enumerate(chain_links):
            if i == 0:
                print(f"      [{link['from']}]")
            arrow = '  --[{0}]-->'.format(link['relationship'])
            print(f"      {arrow}")
            print(f"      [{link['to']}]")
        print()
