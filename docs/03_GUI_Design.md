# 03 - GUI Design

The GUI evolves in v2.0 from a simple status tracker into an **Investigation Dashboard**.

## Core Concept
The GUI should resemble a modern SOC (Security Operations Center) dashboard while remaining implementable in Tkinter.

## Layout

### Left Sidebar (Navigation)
- Dashboard
- Collection
- Detection
- Investigation
- Timeline
- Artifacts
- Reports
- Settings

### Main Dashboard Panel
Display high-level metrics:
- Endpoint name
- Collection status
- Compromise Confidence (Visual gauge)
- Critical findings count
- Anti-forensics alerts
- Top investigation findings

### Investigation Tab
A deep-dive view into the correlated findings:
- List of correlated findings
- Confidence breakdown
- Evidence explanation (Why did the engine flag this?)
- Attack chain visualization (if applicable)
- Recommended actions
