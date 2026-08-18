# 06 - Correlation Engine

The Correlation Engine is the core differentiator of TriageHound v2.0. It transforms fragmented evidence into unified investigation findings.

## Concept
Instead of reporting an isolated YARA hit and a separate isolated Event Log entry, the engine correlates them based on shared properties (e.g., file path, process name, timestamp proximity).

## Inputs
- Normalized Entities (from Phase 1)
- Raw Evidence (Prefetch, ShimCache, USN, Event Logs, etc.)

## Correlation Logic
The engine runs predefined heuristic rules across the dataset.

**Example Rule: PowerShell Activity**
If a process entity matches "powershell.exe", look for:
1. Prefetch entry for PowerShell.
2. ShimCache execution record.
3. Event Log (EID 4104 Script Block Logging).
4. USN Journal creation event for the script.

## Output
A single "Finding" record that references all supporting evidence.
```json
{
  "finding": "Suspicious PowerShell Execution",
  "supported_by": ["Prefetch", "ShimCache", "USN", "Event Log"],
  "severity": "HIGH"
}
```
