"""
Endpoint Compromise Confidence Engine
=======================================
Calculates an explainable 0-100 confidence score indicating how likely
the endpoint is compromised, based on the correlated findings generated
by the Correlation Engine.

The score is NOT a black-box AI number. Every point is traceable back to
a specific finding, making it defensible in an investigation report.
"""


class ConfidenceEngine:
    """
    Aggregates finding confidence contributions into an overall
    Endpoint Compromise Confidence Score.
    """

    # Severity thresholds
    SEVERITY_HIGH = 71
    SEVERITY_MEDIUM = 31
    SEVERITY_LOW = 0

    def __init__(self, db_manager):
        self.db = db_manager

    def calculate_score(self, case_id):
        """
        Calculate and store the endpoint compromise confidence score.

        Returns:
            dict with 'score', 'severity', and 'breakdown' keys.
        """
        findings = self.db.get_all_findings(case_id)

        breakdown = []
        raw_score = 0

        for finding in findings:
            contribution = finding.get('confidence_contribution', 0) or 0
            raw_score += contribution
            breakdown.append({
                'finding_id': finding['finding_id'],
                'title': finding['title'],
                'severity': finding['severity'],
                'points': contribution,
            })

        # Cap at 100
        final_score = min(raw_score, 100)

        # Determine overall severity
        if final_score >= self.SEVERITY_HIGH:
            severity = 'HIGH'
        elif final_score >= self.SEVERITY_MEDIUM:
            severity = 'MEDIUM'
        elif final_score > 0:
            severity = 'LOW'
        else:
            severity = 'INFO'

        # Persist to database
        self.db.insert_confidence_score(case_id, final_score, severity)

        # Print the explainable breakdown to the console
        self._print_breakdown(final_score, severity, breakdown)

        return {
            'score': final_score,
            'severity': severity,
            'breakdown': breakdown,
        }

    def _print_breakdown(self, score, severity, breakdown):
        """Print a human-readable confidence breakdown to the console."""
        print()
        print("    +-----------------------------------------------+")
        print(f"    |  Endpoint Compromise Confidence: {score:>3} / 100  |")
        print(f"    |  Severity: {severity:<34s}|")
        print("    +-----------------------------------------------+")

        if breakdown:
            print("    Evidence Breakdown:")
            for item in breakdown:
                print(f"      - {item['title']:<35s} +{item['points']}")
        else:
            print("    No findings contributed to the score.")
        print()
