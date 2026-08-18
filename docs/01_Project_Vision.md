# 01 - Project Vision

## Executive Summary
TriageHound is a Windows DFIR platform designed to perform rapid endpoint triage, collect high-value forensic artifacts, detect suspicious activity, and generate legally defensible investigation reports. 

Its defining capability is automatically correlating redundant forensic artifacts, detecting potential anti-forensic behavior, assigning an explainable **Endpoint Compromise Confidence Score**, reconstructing attack activity, and prioritizing investigations.

## Core Philosophy
> **Collect → Correlate → Detect → Reason → Prioritize → Explain**

## The Problem We're Solving
The project is **not** trying to replace KAPE, Velociraptor, Autopsy, or enterprise EDRs. Instead, it addresses a different problem: the manual correlation fatigue experienced by analysts during the first few minutes of an incident response.

Current workflows often require analysts to manually correlate Prefetch, ShimCache, USN Journal, Event Logs, and Registry artifacts. TriageHound automates this reasoning to quickly answer:
- Is this endpoint likely compromised?
- What evidence supports that conclusion?
- Was evidence potentially deleted?
- What should I investigate first?
