# 08 - Anti-Forensics Detection

The Anti-Forensics module detects attempts by an attacker to hide their tracks or delete evidence.

## Detection Strategies
The engine looks for specific discrepancies in the correlated artifacts:

1. **File Missing from Disk:** An execution artifact (Prefetch) exists, but the executable file is no longer on the filesystem.
2. **Rapid Deletion:** USN Journal shows a file was Created → Executed → Deleted within seconds or minutes.
3. **Log Clearing:** Event logs indicate that the Security or System logs were recently cleared (e.g., EID 1102).
4. **Missing Expected Artifacts:** A known malware family executed, but standard persistence keys are conspicuously absent or tampered with.

## Output Wording
The wording should remain forensic and objective:
> *"Potential Evidence Removal Detected: Execution artifact found but file missing from disk."*
