"""
Investigation Findings Engine
================================
Consolidates all v2.0 intelligence (findings, confidence score,
anti-forensics alerts, attack chain, recommendations) into a single
structured investigation summary.

This engine is the final consumer of all upstream engines and produces
the unified data structure that feeds the GUI Dashboard and PDF Report.
"""

import json


class FindingsEngine:
    """
    Packages correlated findings, confidence score, anti-forensics alerts,
    attack chain links, and recommendations into a structured investigation
    summary ready for presentation.
    """

    def __init__(self, db_manager):
        self.db = db_manager

    def generate_summary(self, case_id, confidence_result=None):
        """
        Build the full investigation summary for a case.

        Args:
            case_id: The case identifier.
            confidence_result: Optional dict from ConfidenceEngine.calculate_score().

        Returns:
            dict containing the complete investigation summary.
        """
        findings = self.db.get_all_findings(case_id)
        af_alerts = self.db.get_anti_forensics(case_id)
        chains = self.db.get_attack_chains(case_id)
        case_meta = self.db.get_case_metadata(case_id)
        artifact_counts = self.db.get_artifact_counts(case_id)

        # Build enriched findings with their supporting evidence
        enriched_findings = self._enrich_findings(findings, case_id)

        # Determine overall risk assessment
        score = confidence_result.get('score', 0) if confidence_result else 0
        severity = confidence_result.get('severity', 'INFO') if confidence_result else 'INFO'
        breakdown = confidence_result.get('breakdown', []) if confidence_result else []

        summary = {
            'case_id': case_id,
            'case_metadata': case_meta,
            'artifact_counts': artifact_counts,

            # Confidence
            'confidence_score': score,
            'confidence_severity': severity,
            'confidence_breakdown': breakdown,

            # Findings
            'total_findings': len(enriched_findings),
            'critical_findings': len([f for f in enriched_findings if f['severity'] == 'CRITICAL']),
            'high_findings': len([f for f in enriched_findings if f['severity'] == 'HIGH']),
            'medium_findings': len([f for f in enriched_findings if f['severity'] == 'MEDIUM']),
            'low_findings': len([f for f in enriched_findings if f['severity'] in ('LOW', 'INFO')]),
            'findings': enriched_findings,

            # Anti-Forensics
            'anti_forensics_count': len(af_alerts),
            'anti_forensics_alerts': af_alerts,

            # Attack Chain
            'attack_chain_links': len(chains),
            'attack_chain': chains,
        }

        self._print_summary(summary)
        return summary

    def _enrich_findings(self, findings, case_id):
        """
        For each finding, attach the list of supporting evidence sources
        and any recommendation.
        """
        enriched = []
        conn = self.db.get_connection()

        import sqlite3
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        for f in findings:
            fid = f['finding_id']

            # Get supporting evidence artifact types
            cursor.execute("""
                SELECT DISTINCT i.artifact_type, i.source, i.description
                FROM correlations c
                JOIN evidence_items i ON c.evidence_id = i.id
                WHERE c.finding_id = ?
            """, (fid,))
            evidence_rows = [dict(r) for r in cursor.fetchall()]

            # Get recommendation
            cursor.execute("""
                SELECT action FROM recommendations WHERE finding_id = ?
            """, (fid,))
            rec_row = cursor.fetchone()
            recommendation = dict(rec_row)['action'] if rec_row else None

            enriched.append({
                'finding_id': fid,
                'title': f['title'],
                'description': f['description'],
                'severity': f['severity'],
                'confidence_contribution': f['confidence_contribution'],
                'timestamp': f['timestamp'],
                'supporting_evidence': evidence_rows,
                'evidence_sources': list(set(e['artifact_type'] for e in evidence_rows)),
                'recommendation': recommendation,
            })

        conn.close()
        return enriched

    def _print_summary(self, summary):
        """Print the investigation summary to the console."""
        print()
        print("    ================================================")
        print("     INVESTIGATION SUMMARY")
        print("    ================================================")
        print(f"    Confidence Score : {summary['confidence_score']} / 100 ({summary['confidence_severity']})")
        print(f"    Total Findings   : {summary['total_findings']}")

        if summary['high_findings'] or summary['critical_findings']:
            print(f"    Critical/High    : {summary['critical_findings'] + summary['high_findings']}")
        if summary['medium_findings']:
            print(f"    Medium           : {summary['medium_findings']}")
        if summary['low_findings']:
            print(f"    Low/Info         : {summary['low_findings']}")

        print(f"    Anti-Forensics   : {summary['anti_forensics_count']} alert(s)")
        print(f"    Attack Chain     : {summary['attack_chain_links']} link(s)")
        print("    ================================================")

        # Print each finding
        if summary['findings']:
            print()
            for i, f in enumerate(summary['findings'], 1):
                print(f"    Finding #{i:03d}: {f['title']}")
                print(f"      Severity    : {f['severity']}")
                print(f"      Confidence  : +{f['confidence_contribution']}")
                sources = ', '.join(f['evidence_sources']) if f['evidence_sources'] else 'N/A'
                print(f"      Evidence    : {sources}")
                if f['recommendation']:
                    print(f"      Action      : {f['recommendation']}")
                print()
