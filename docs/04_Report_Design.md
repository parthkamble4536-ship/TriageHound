# 04 - Report Design

The v2.0 report retains the existing professional cover page but heavily revamps the internal contents to focus on correlated findings and explainable intelligence rather than raw data dumps.

## Final Report Structure

| Section | Status | Description |
|---------|--------|-------------|
| Existing Cover | Keep | Institutional branding, case metadata |
| Executive Summary | New | High-level summary of findings |
| Risk Assessment | New | Confidence score and severity |
| Investigation Summary | New | Narrative of the attack |
| Confidence Score | New | Breakdown of why the score was assigned |
| Evidence Correlation | New | Tables mapping artifacts to findings |
| Anti-Forensics | New | Warnings of potential evidence tampering |
| Attack Chain | New | Visual node narrative of execution |
| Timeline | Enhanced | Consolidated event history |
| Detailed Evidence | Existing | Raw artifact tables |
| SHA-256 Manifest | Existing | Integrity hashes |

## Example Section: Anti-Forensics
```text
Created
 ↓
Executed
 ↓
Deleted
 ↓
Missing on Disk
-------------------
Potential Evidence Removal Detected
```
