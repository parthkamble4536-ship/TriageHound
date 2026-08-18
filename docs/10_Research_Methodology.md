# 10 - Research Methodology

TriageHound v2.0 is framed around a core research question:
> **"Can cross-artifact correlation improve rapid Windows endpoint compromise assessment compared with isolated artifact analysis?"**

## Research Contributions
1. **Cross-Artifact Evidence Correlation:** Automating the linkage of disparate forensic artifacts.
2. **Explainable Confidence Scoring:** Providing transparent, weighted risk assessments.
3. **Anti-Forensics Detection:** Identifying tampering through missing or conflicting artifacts.
4. **Attack Reconstruction:** Building visual timelines of the intrusion.
5. **Empirical Evaluation:** Benchmarking the tool against standard manual analysis.

## Experiments
1. **Single Artifact Analysis:** How well can we detect compromise using only Prefetch or only Event Logs?
2. **Correlated Analysis:** How much does detection rate and accuracy improve when artifacts are analyzed collectively by the Correlation Engine?
