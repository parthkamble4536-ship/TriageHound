# 11 - Testing & Benchmarking

Ensuring the reliability and accuracy of TriageHound v2.0 requires robust testing methodologies.

## Testing Strategy
1. **Unit Testing:** Validate individual parsers (Prefetch, USN) and normalization routines against known datasets.
2. **Integration Testing:** Verify that normalized entities are correctly passed to and processed by the Correlation Engine.
3. **End-to-End Testing:** Run the full pipeline on a forensic image of a known compromised machine and validate the final PDF report.

## Benchmarking Metrics
- **Detection Rate:** Percentage of known malicious actions successfully identified.
- **False Positives:** Rate of benign activity incorrectly flagged as suspicious.
- **Processing Time:** Total time from evidence collection to final report generation.
- **Evidence Recovery:** Success rate in identifying deleted or hidden artifacts (Anti-Forensics).
