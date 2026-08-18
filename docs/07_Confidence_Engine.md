# 07 - Confidence Engine

The Confidence Engine assigns an explainable "Endpoint Compromise Confidence Score" (0-100) indicating the likelihood that the machine is compromised.

## Scoring Methodology
The score is cumulative, starting at 0, based on weighted findings.

**Example Weights:**
- Multiple execution artifacts (Prefetch+ShimCache): +20
- YARA Rule Hit: +20
- Sigma Rule Hit: +15
- Known Persistence Mechanism: +15
- High Confidence VirusTotal Match: +10
- Evidence Deletion / Tampering: +10
- Benign Uncertainty (e.g., normal admin activity): -3

## Explainability
The engine must output exactly *why* a score was given. Black-box AI scores are rejected by DFIR professionals. The output should be a transparent breakdown of points added and subtracted.
