"""
Cross-Platform Correlation Engine
===================================
Analyzes normalized entities to find cross-artifact relationships and
generate Investigation Findings based on heuristic detection rules.

Rules are organized by platform:
  - Windows (v1.0): PowerShell, Executable Drops, Startup Persistence
  - macOS   (v2.0): LaunchAgent persistence, Quarantine downloads, Suspicious processes
  - Linux   (v3.0): Privilege escalation, In-memory drops, Cron persistence, SSH anomalies
"""

import uuid
from datetime import datetime


# ── Known-good process whitelists (false positive reduction) ──────────────────
WINDOWS_BENIGN_PROCESSES = {
    'onedrive.exe', 'msedge.exe', 'chrome.exe', 'firefox.exe',
    'svchost.exe', 'explorer.exe', 'taskhostw.exe', 'searchindexer.exe',
    'docker desktop.exe', 'docker.exe', 'dockerd.exe',
    'acrord32.exe', 'teams.exe', 'zoom.exe', 'slack.exe',
    'msmpeng.exe', 'mssense.exe', 'mpcmdrun.exe',   # Windows Defender
}

MAC_BENIGN_LAUNCHAGENTS = {
    'com.apple.', 'com.microsoft.', 'com.google.',
    'com.adobe.', 'com.dropbox.', 'com.spotify.',
    'com.docker.', 'com.zoom.',
}

LINUX_BENIGN_SUID = {
    'su', 'sudo', 'passwd', 'ping', 'mount', 'umount',
    'chsh', 'chfn', 'newgrp', 'gpasswd', 'pkexec',
    'crontab', 'at', 'traceroute', 'ssh-agent',
    'fusermount', 'fusermount3', 'unix_chkpwd',
}

# Suspicious shell commands that attackers use on Linux/Mac
SUSPICIOUS_SHELL_KEYWORDS = [
    'curl', 'wget', 'nc ', 'ncat', 'netcat', 'nmap',
    'chmod +s', 'chmod 4', 'chown root',
    '/dev/tcp', '/dev/udp',
    'base64 -d', 'base64 --decode',
    'python -c', 'python3 -c', 'perl -e', 'ruby -e',
    'bash -i', 'sh -i', 'bash -c', 'sh -c',
    'rm -rf', 'shred', 'wipe',
    '/dev/shm', '/tmp/.', '/var/tmp/.',
    'iptables -F', 'ufw disable',
    'history -c', 'unset HISTFILE',
    'passwd root', 'useradd', 'usermod -aG sudo',
    'crontab -', 'echo * * * *',
]


class CorrelationEngine:
    """
    Analyzes normalized entities to find cross-artifact relationships.
    Generates unified Investigation Findings based on heuristic rules
    for Windows (v1.0), macOS (v2.0), and Linux (v3.0).
    """

    def __init__(self, db_manager):
        self.db = db_manager

    def run_correlation(self, case_id):
        entities = self.db.get_all_entities(case_id)
        if not entities:
            return

        # ── Windows (v1.0) Rules ──────────────────────────────────────────────
        self._safe_run(self._rule_powershell_execution, entities)
        self._safe_run(self._rule_executable_dropped, entities)
        self._safe_run(self._rule_windows_startup_persistence, entities)

        # ── macOS (v2.0) Rules ────────────────────────────────────────────────
        self._safe_run(self._rule_mac_suspicious_launch_agent, entities)
        self._safe_run(self._rule_mac_quarantine_download, entities)
        self._safe_run(self._rule_mac_suspicious_process, entities)

        # ── Linux (v3.0) Rules ────────────────────────────────────────────────
        self._safe_run(self._rule_linux_suspicious_shell_command, entities)
        self._safe_run(self._rule_linux_memory_drop, entities)
        self._safe_run(self._rule_linux_suid_anomaly, entities)
        self._safe_run(self._rule_linux_cron_persistence, entities)
        self._safe_run(self._rule_linux_ssh_anomaly, entities)

    def _safe_run(self, rule_fn, entities):
        """Run a rule function, swallowing exceptions so one rule never kills others."""
        try:
            rule_fn(entities)
        except Exception:
            pass

    # ==========================================================================
    # WINDOWS (v1.0) RULES
    # ==========================================================================

    def _rule_powershell_execution(self, entities):
        """
        Detects PowerShell execution corroborated across multiple artifacts.
        A PowerShell process seen in Prefetch + ShimCache + Process list
        strongly suggests intentional execution (not just a scheduled task).
        """
        ps_entities = [
            e for e in entities
            if e['entity_type'] == 'Process'
            and e['name']
            and 'powershell' in str(e['name']).lower()
        ]
        if not ps_entities:
            return

        processed_ids = set()
        for ps in ps_entities:
            if ps['entity_id'] in processed_ids:
                continue

            related = [
                e for e in ps_entities
                if abs(self._ts_diff(ps['timestamp'], e['timestamp'])) < 3600
            ]
            for rel in related:
                processed_ids.add(rel['entity_id'])

            finding_id = f"FND-PS-{uuid.uuid4().hex[:8].upper()}"
            confidence = min(10 * len(related), 40)
            severity = "HIGH" if len(related) > 2 else "MEDIUM"

            self.db.insert_finding(
                finding_id=finding_id,
                title="Suspicious PowerShell Execution",
                description=(
                    f"PowerShell execution detected and corroborated by {len(related)} "
                    f"artifact(s). Attackers frequently abuse PowerShell for "
                    f"downloading payloads, lateral movement, and credential dumping."
                ),
                severity=severity,
                confidence_contribution=confidence,
                timestamp=ps['timestamp']
            )
            for rel in related:
                self.db.insert_correlation(
                    finding_id, entity_id=rel['entity_id'], evidence_id=rel['evidence_id']
                )

    def _rule_executable_dropped(self, entities):
        """
        Detects new executable files observed on disk (via USN Journal or FSEvents).
        Excludes known-good signed vendor executables to reduce false positives.
        """
        exe_files = [
            e for e in entities
            if e['entity_type'] == 'File'
            and e['name']
            and str(e['name']).lower().endswith('.exe')
            and str(e['name']).lower() not in WINDOWS_BENIGN_PROCESSES
        ]
        for exe in exe_files:
            finding_id = f"FND-EXE-{uuid.uuid4().hex[:8].upper()}"
            self.db.insert_finding(
                finding_id=finding_id,
                title="Executable File Dropped on Disk",
                description=(
                    f"Executable '{exe['name']}' was observed on disk. "
                    f"Malware frequently drops executables to temp or AppData directories "
                    f"as a first stage of compromise."
                ),
                severity="MEDIUM",
                confidence_contribution=15,
                timestamp=exe['timestamp']
            )
            self.db.insert_correlation(
                finding_id, entity_id=exe['entity_id'], evidence_id=exe['evidence_id']
            )

    def _rule_windows_startup_persistence(self, entities):
        """
        Detects processes observed in ShimCache that are ALSO currently running.
        This dual presence strongly suggests a persistence mechanism that
        survived a reboot.
        """
        shimcache_names = {
            str(e['name']).lower(): e for e in entities
            if e['entity_type'] == 'Process'
            and e['name']
            and 'shimcache' in str(e.get('raw_attributes', '')).lower()
        }
        running_names = {
            str(e['name']).lower() for e in entities
            if e['entity_type'] == 'Process'
            and e['name']
        }
        overlap = set(shimcache_names.keys()) & running_names
        for name in overlap:
            if name in WINDOWS_BENIGN_PROCESSES:
                continue
            e = shimcache_names[name]
            finding_id = f"FND-PERSIST-{uuid.uuid4().hex[:8].upper()}"
            self.db.insert_finding(
                finding_id=finding_id,
                title="Startup Persistence Detected",
                description=(
                    f"Process '{name}' was found in ShimCache (historical execution) "
                    f"AND is currently running. This dual presence suggests a persistence "
                    f"mechanism that survived a reboot."
                ),
                severity="HIGH",
                confidence_contribution=25,
                timestamp=e['timestamp']
            )
            self.db.insert_correlation(
                finding_id, entity_id=e['entity_id'], evidence_id=e['evidence_id']
            )

    # ==========================================================================
    # macOS (v2.0) RULES
    # ==========================================================================

    def _rule_mac_suspicious_launch_agent(self, entities):
        """
        Detects third-party LaunchAgents/LaunchDaemons that are NOT from a known
        trusted vendor. On macOS, LaunchAgents are the primary persistence mechanism
        for both legitimate software and malware.
        """
        persistence_entities = [
            e for e in entities
            if e['entity_type'] == 'Process'
            and e['name']
            and not any(
                str(e['name']).lower().startswith(trusted)
                for trusted in MAC_BENIGN_LAUNCHAGENTS
            )
            and (
                'launchdaemon' in str(e.get('raw_attributes', '')).lower()
                or 'launchagent' in str(e.get('raw_attributes', '')).lower()
            )
        ]
        for pe in persistence_entities:
            finding_id = f"FND-MLAUNCH-{uuid.uuid4().hex[:8].upper()}"
            self.db.insert_finding(
                finding_id=finding_id,
                title="Suspicious LaunchAgent / LaunchDaemon Detected",
                description=(
                    f"A LaunchAgent/LaunchDaemon with label '{pe['name']}' was found "
                    f"and does not match any known trusted vendor signature. "
                    f"Attackers use LaunchAgents for persistent code execution on macOS."
                ),
                severity="HIGH",
                confidence_contribution=30,
                timestamp=pe['timestamp']
            )
            self.db.insert_correlation(
                finding_id, entity_id=pe['entity_id'], evidence_id=pe['evidence_id']
            )

    def _rule_mac_quarantine_download(self, entities):
        """
        Detects files flagged by macOS Gatekeeper's QuarantineEvents database.
        Every file downloaded from the internet is quarantined; this rule surfaces
        recent downloads that may have introduced malware.
        """
        quarantine_files = [
            e for e in entities
            if e['entity_type'] == 'File'
            and 'quarantine' in str(e.get('raw_attributes', '')).lower()
        ]
        if not quarantine_files:
            return

        finding_id = f"FND-MQUAR-{uuid.uuid4().hex[:8].upper()}"
        self.db.insert_finding(
            finding_id=finding_id,
            title="Internet-Downloaded Files in Quarantine",
            description=(
                f"{len(quarantine_files)} file(s) were found in the macOS QuarantineEvents "
                f"database, indicating they were downloaded from the internet. "
                f"Review these files for malicious content."
            ),
            severity="MEDIUM",
            confidence_contribution=20,
            timestamp=quarantine_files[0]['timestamp']
        )
        for qf in quarantine_files[:5]:
            self.db.insert_correlation(
                finding_id, entity_id=qf['entity_id'], evidence_id=qf['evidence_id']
            )

    def _rule_mac_suspicious_process(self, entities):
        """
        Detects suspicious macOS-native processes that are commonly abused by
        attackers: osascript (AppleScript), curl/wget for C2 communication,
        and python/ruby for in-memory execution.
        """
        suspicious_mac_procs = {
            'osascript', 'curl', 'wget', 'python3', 'python', 'ruby',
            'perl', 'bash', 'zsh', 'sh', 'nc', 'ncat', 'screencapture',
            'security', 'ditto', 'xattr',
        }
        suspicious_found = [
            e for e in entities
            if e['entity_type'] == 'Process'
            and e['name']
            and str(e['name']).lower().split('/')[-1] in suspicious_mac_procs
        ]
        if not suspicious_found:
            return

        # Group by process name
        by_name = {}
        for e in suspicious_found:
            key = str(e['name']).lower().split('/')[-1]
            by_name.setdefault(key, []).append(e)

        for proc_name, proc_list in by_name.items():
            finding_id = f"FND-MPROC-{uuid.uuid4().hex[:8].upper()}"
            count = len(proc_list)
            self.db.insert_finding(
                finding_id=finding_id,
                title=f"Suspicious macOS Process: {proc_name}",
                description=(
                    f"'{proc_name}' was detected running {count} time(s). "
                    f"This process is commonly abused on macOS for command-and-control "
                    f"communication, credential theft, or in-memory code execution."
                ),
                severity="MEDIUM",
                confidence_contribution=min(10 * count, 25),
                timestamp=proc_list[0]['timestamp']
            )
            for e in proc_list[:3]:
                self.db.insert_correlation(
                    finding_id, entity_id=e['entity_id'], evidence_id=e['evidence_id']
                )

    # ==========================================================================
    # LINUX (v3.0) RULES
    # ==========================================================================

    def _rule_linux_suspicious_shell_command(self, entities):
        """
        Detects suspicious shell commands in bash/zsh history that indicate
        privilege escalation, reverse shells, data exfiltration, or anti-forensics.
        """
        shell_entities = [
            e for e in entities
            if e['entity_type'] == 'Process'
            and e['path']
        ]
        for e in shell_entities:
            cmd = str(e['path']).lower()
            matched_keywords = [kw for kw in SUSPICIOUS_SHELL_KEYWORDS if kw in cmd]
            if not matched_keywords:
                continue

            finding_id = f"FND-LSHELL-{uuid.uuid4().hex[:8].upper()}"
            self.db.insert_finding(
                finding_id=finding_id,
                title="Suspicious Shell Command Detected",
                description=(
                    f"Shell history entry '{str(e['path'])[:120]}' matched "
                    f"suspicious keyword(s): {', '.join(matched_keywords)}. "
                    f"This may indicate reverse shell activity, data exfiltration, "
                    f"privilege escalation, or anti-forensics attempts."
                ),
                severity="HIGH",
                confidence_contribution=20,
                timestamp=e['timestamp']
            )
            self.db.insert_correlation(
                finding_id, entity_id=e['entity_id'], evidence_id=e['evidence_id']
            )

    def _rule_linux_memory_drop(self, entities):
        """
        Detects files written to in-memory volatile paths (/dev/shm, /run/shm, /tmp).
        Writing executables to these paths is a classic fileless malware technique.
        """
        memory_paths = ['/dev/shm', '/run/shm', '/tmp/.', '/var/tmp/.']
        mem_drops = [
            e for e in entities
            if e['entity_type'] == 'File'
            and e['path']
            and any(mp in str(e['path']) for mp in memory_paths)
        ]
        for drop in mem_drops:
            finding_id = f"FND-LMEMDROP-{uuid.uuid4().hex[:8].upper()}"
            self.db.insert_finding(
                finding_id=finding_id,
                title="In-Memory File Drop Detected (Fileless Malware Indicator)",
                description=(
                    f"File '{drop['name']}' was found at volatile path '{drop['path']}'. "
                    f"Writing executables to /dev/shm or /tmp is a well-known fileless "
                    f"malware technique used to evade disk-based forensic tools."
                ),
                severity="CRITICAL",
                confidence_contribution=35,
                timestamp=drop['timestamp']
            )
            self.db.insert_correlation(
                finding_id, entity_id=drop['entity_id'], evidence_id=drop['evidence_id']
            )

    def _rule_linux_suid_anomaly(self, entities):
        """
        Detects SUID/SGID binaries NOT in the known-good whitelist.
        An unknown SUID binary is a classic privilege escalation persistence mechanism.
        """
        suid_entities = [
            e for e in entities
            if e['entity_type'] == 'File'
            and e['name']
            and 'suid' in str(e.get('raw_attributes', '')).lower()
            and str(e['name']).lower() not in LINUX_BENIGN_SUID
        ]
        for suid in suid_entities:
            finding_id = f"FND-LSUID-{uuid.uuid4().hex[:8].upper()}"
            self.db.insert_finding(
                finding_id=finding_id,
                title="Anomalous SUID Binary Found",
                description=(
                    f"SUID binary '{suid['name']}' at '{suid['path']}' is not in the "
                    f"known-good whitelist. SUID binaries execute as root regardless "
                    f"of who runs them and are a primary privilege escalation vector."
                ),
                severity="HIGH",
                confidence_contribution=30,
                timestamp=suid['timestamp']
            )
            self.db.insert_correlation(
                finding_id, entity_id=suid['entity_id'], evidence_id=suid['evidence_id']
            )

    def _rule_linux_cron_persistence(self, entities):
        """
        Detects non-standard cron jobs or systemd services as persistence mechanisms.
        """
        cron_entities = [
            e for e in entities
            if e['entity_type'] == 'Process'
            and e['name']
            and str(e['name']).startswith('cron:')
        ]
        service_entities = [
            e for e in entities
            if e['entity_type'] == 'Process'
            and e['path']
            and '/systemd/' in str(e['path']).lower()
            and e['name']
            and not any(
                trusted in str(e['name']).lower()
                for trusted in ['ssh', 'cron', 'rsyslog', 'udev', 'dbus', 'network', 'systemd']
            )
        ]
        all_persistence = cron_entities + service_entities
        for pe in all_persistence:
            finding_id = f"FND-LCRON-{uuid.uuid4().hex[:8].upper()}"
            kind = "Cron Job" if pe in cron_entities else "Systemd Service"
            self.db.insert_finding(
                finding_id=finding_id,
                title=f"Linux Persistence Mechanism: {kind}",
                description=(
                    f"A {kind} named '{pe['name']}' was found. "
                    f"Attackers use cron jobs and systemd services to survive reboots "
                    f"and maintain persistent access to compromised systems."
                ),
                severity="MEDIUM",
                confidence_contribution=20,
                timestamp=pe['timestamp']
            )
            self.db.insert_correlation(
                finding_id, entity_id=pe['entity_id'], evidence_id=pe['evidence_id']
            )

    def _rule_linux_ssh_anomaly(self, entities):
        """
        Detects suspicious SSH activity: brute-force failed logins,
        successful logins, and unauthorized sudo escalation.
        """
        ssh_failed = [
            e for e in entities
            if e['entity_type'] == 'User'
            and 'ssh_login_failed' in str(e.get('raw_attributes', '')).lower()
        ]
        ssh_success = [
            e for e in entities
            if e['entity_type'] == 'User'
            and 'ssh_login_success' in str(e.get('raw_attributes', '')).lower()
        ]
        sudo_usage = [
            e for e in entities
            if e['entity_type'] == 'User'
            and 'sudo_command' in str(e.get('raw_attributes', '')).lower()
        ]

        # Brute force: 5+ failed SSH logins
        if len(ssh_failed) >= 5:
            finding_id = f"FND-LSSH-BF-{uuid.uuid4().hex[:8].upper()}"
            self.db.insert_finding(
                finding_id=finding_id,
                title="SSH Brute-Force Attack Detected",
                description=(
                    f"{len(ssh_failed)} failed SSH login attempt(s) found in auth logs. "
                    f"This strongly indicates a brute-force or credential stuffing attack."
                ),
                severity="HIGH",
                confidence_contribution=30,
                timestamp=ssh_failed[0]['timestamp']
            )
            for e in ssh_failed[:5]:
                self.db.insert_correlation(
                    finding_id, entity_id=e['entity_id'], evidence_id=e['evidence_id']
                )

        # Successful login AFTER failures
        if ssh_failed and ssh_success:
            finding_id = f"FND-LSSH-SUC-{uuid.uuid4().hex[:8].upper()}"
            self.db.insert_finding(
                finding_id=finding_id,
                title="Successful SSH Login After Failed Attempts",
                description=(
                    f"A successful SSH login was recorded after {len(ssh_failed)} failed "
                    f"attempt(s). This pattern is consistent with a successful brute-force."
                ),
                severity="CRITICAL",
                confidence_contribution=40,
                timestamp=ssh_success[0]['timestamp']
            )
            for e in (ssh_success + ssh_failed[:3]):
                self.db.insert_correlation(
                    finding_id, entity_id=e['entity_id'], evidence_id=e['evidence_id']
                )

        # Sudo usage
        if sudo_usage:
            finding_id = f"FND-LSUDO-{uuid.uuid4().hex[:8].upper()}"
            self.db.insert_finding(
                finding_id=finding_id,
                title="Sudo / Privilege Escalation Activity",
                description=(
                    f"{len(sudo_usage)} sudo command(s) detected in auth logs. "
                    f"Review to verify authorization. Attackers use sudo to escalate to root."
                ),
                severity="MEDIUM",
                confidence_contribution=15,
                timestamp=sudo_usage[0]['timestamp']
            )
            for e in sudo_usage[:3]:
                self.db.insert_correlation(
                    finding_id, entity_id=e['entity_id'], evidence_id=e['evidence_id']
                )

    # ==========================================================================
    # HELPERS
    # ==========================================================================

    def _ts_diff(self, ts1, ts2):
        """Calculate difference in seconds between two ISO timestamps."""
        if not ts1 or not ts2:
            return 999999
        try:
            d1 = datetime.fromisoformat(str(ts1).replace('Z', '+00:00'))
            d2 = datetime.fromisoformat(str(ts2).replace('Z', '+00:00'))
            return (d1 - d2).total_seconds()
        except (ValueError, TypeError):
            return 999999
