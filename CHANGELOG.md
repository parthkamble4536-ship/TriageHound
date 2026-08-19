# CHANGELOG

## v2.0.0 (2026-08-19)

### New Features
- **Evidence Normalization Layer** — Standardizes raw forensic artifacts into unified Process and File entities
- **Cross-Artifact Correlation Engine** — Detects patterns like PowerShell execution across multiple artifact sources
- **Endpoint Compromise Confidence Engine** — Assigns an explainable 0-100 score with transparent point breakdown
- **Anti-Forensics Detection Engine** — Detects evidence tampering: missing executables, rapid deletions, log clearing (EID 1102/104)
- **Attack Chain Reconstruction** — Builds sequential attack narratives ordered by attack lifecycle stage
- **Investigation Findings Engine** — Consolidates all intelligence into structured findings with recommendations
- **GUI Investigation Dashboard** — New tab showing confidence score, findings, anti-forensics alerts, and attack chain
- **Enhanced PDF Report** — New sections: Executive Summary, Correlated Findings, Anti-Forensics Analysis, Attack Chain
- **Performance Metrics Collector** — Pipeline instrumentation with timing and counter metrics
- **Comprehensive Test Suite** — 7 integration tests with synthetic data and benchmark reporting

### Improvements
- Error handling hardened across all v2.0 engines
- Pipeline resilience — malformed evidence records are skipped without crashing
- Updated version branding throughout (GUI, PDF footer, cover page)
- Updated README with v2.0 features and philosophy

### Database
- New tables: `entities`, `findings`, `correlations`, `confidence_scores`, `anti_forensics`, `attack_chains`, `recommendations`

---

## v1.0.0 (2026-07-01)

### Initial Release
- Core evidence collection (Processes, Recent Files, Startup, USB, Browser History)
- Advanced forensics (Prefetch, ShimCache, USN Journal, Volume Shadow Copies)
- Threat hunting (YARA, Sigma, VirusTotal)
- Professional PDF report with cover page and attestation
- Cryptographic sealing (SHA-256 manifest)
- Super timeline generation with JSON/CSV export
- Dark-themed GUI with module selection and live logging
