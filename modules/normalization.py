import uuid
import json
import os

class NormalizationEngine:
    """
    Transforms raw evidence items into standardized Entities (Process, File, User)
    so they can be correlated by the Correlation Engine.
    """
    def __init__(self, db_manager):
        self.db = db_manager

    def normalize_case(self, case_id):
        evidence_items = self.db.get_all_evidence(case_id)
        for item in evidence_items:
            try:
                self.normalize_evidence(item)
            except Exception:
                # Skip malformed evidence records without crashing the pipeline
                pass
            
    def normalize_evidence(self, item):
        artifact_type = item['artifact_type']
        raw_data_str = item['raw_data']
        
        try:
            raw_data = json.loads(raw_data_str) if raw_data_str else {}
        except json.JSONDecodeError:
            raw_data = {}

        if artifact_type == 'prefetch':
            self._normalize_prefetch(item, raw_data)
        elif artifact_type == 'usn_journal':
            self._normalize_usn(item, raw_data)
        elif artifact_type == 'shimcache':
            self._normalize_shimcache(item, raw_data)
        elif artifact_type == 'process':
            self._normalize_running_process(item, raw_data)
        # ── macOS (v2.0) artifact types ──
        elif artifact_type == 'mac_unified_log':
            self._normalize_mac_log(item, raw_data)
        elif artifact_type == 'mac_persistence':
            self._normalize_mac_persistence(item, raw_data)
        elif artifact_type == 'mac_fsevents':
            self._normalize_mac_fsevents(item, raw_data)
        elif artifact_type == 'mac_telemetry':
            self._normalize_mac_telemetry(item, raw_data)
        # ── Linux (v3.0) artifact types ──
        elif artifact_type == 'linux_system_log':
            self._normalize_linux_log(item, raw_data)
        elif artifact_type == 'linux_shell_history':
            self._normalize_linux_shell(item, raw_data)
        elif artifact_type == 'linux_persistence':
            self._normalize_linux_persistence(item, raw_data)
        elif artifact_type == 'linux_memory_drop':
            self._normalize_linux_memory_drop(item, raw_data)

    def _normalize_prefetch(self, item, raw_data):
        entity_id = str(uuid.uuid4())
        name = raw_data.get('executable_name', '')
        path = raw_data.get('pf_filename', '')
        timestamp = raw_data.get('last_run', item['timestamp'])
        
        self.db.insert_entity(
            entity_id=entity_id,
            entity_type='Process',
            name=name,
            path=path,
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )

    def _normalize_usn(self, item, raw_data):
        entity_id = str(uuid.uuid4())
        name = raw_data.get('filename', '')
        path = '' # USN typically just gives filename, parent reference can resolve path in a real MFT lookup
        timestamp = raw_data.get('timestamp', item['timestamp'])
        
        self.db.insert_entity(
            entity_id=entity_id,
            entity_type='File',
            name=name,
            path=path,
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )

    def _normalize_shimcache(self, item, raw_data):
        entity_id = str(uuid.uuid4())
        path = raw_data.get('path', '')
        name = path.split('\\')[-1] if path else ''
        timestamp = raw_data.get('last_modified', item['timestamp'])
        
        self.db.insert_entity(
            entity_id=entity_id,
            entity_type='Process',
            name=name,
            path=path,
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )

    def _normalize_running_process(self, item, raw_data):
        entity_id = str(uuid.uuid4())
        name = raw_data.get('name', '')
        path = raw_data.get('exe', '')
        timestamp = raw_data.get('create_time', item['timestamp'])
        
        self.db.insert_entity(
            entity_id=entity_id,
            entity_type='Process',
            name=name,
            path=path,
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )

    # ── macOS (v2.0) normalization handlers ──────────────────────────────────

    def _normalize_mac_log(self, item, raw_data):
        """Normalize macOS Unified Log entries into Process entities."""
        entity_id = str(uuid.uuid4())
        name = raw_data.get('process', 'unknown')
        path = raw_data.get('process', '')
        timestamp = raw_data.get('timestamp', item['timestamp'])

        self.db.insert_entity(
            entity_id=entity_id,
            entity_type='Process',
            name=name.split('/')[-1] if '/' in name else name,
            path=path,
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )

    def _normalize_mac_persistence(self, item, raw_data):
        """Normalize macOS persistence (LaunchDaemons/Agents) into Process entities."""
        entity_id = str(uuid.uuid4())
        label = raw_data.get('label', '')
        cmd_line = raw_data.get('command_line', '')
        timestamp = raw_data.get('timestamp', item['timestamp'])

        self.db.insert_entity(
            entity_id=entity_id,
            entity_type='Process',
            name=label,
            path=raw_data.get('plist_path', ''),
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )

    def _normalize_mac_fsevents(self, item, raw_data):
        """Normalize macOS FSEvents into File entities."""
        entity_id = str(uuid.uuid4())
        filename = raw_data.get('filename', '')
        timestamp = raw_data.get('timestamp', item['timestamp'])

        self.db.insert_entity(
            entity_id=entity_id,
            entity_type='File',
            name=filename.split('/')[-1] if '/' in filename else filename,
            path=filename,
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )

    def _normalize_mac_telemetry(self, item, raw_data):
        """Normalize macOS telemetry (Quarantine/KnowledgeC) into File or Process entities."""
        entity_id = str(uuid.uuid4())
        category = raw_data.get('category', '')
        timestamp = raw_data.get('timestamp', item['timestamp'])

        if category == 'quarantine':
            name = raw_data.get('data_url', '').split('/')[-1] or 'download'
            entity_type = 'File'
        else:
            name = raw_data.get('app_bundle', 'unknown')
            entity_type = 'Process'

        self.db.insert_entity(
            entity_id=entity_id,
            entity_type=entity_type,
            name=name,
            path=raw_data.get('origin_url', raw_data.get('app_bundle', '')),
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )

    # ── Linux (v3.0) normalization handlers ──────────────────────────────────

    def _normalize_linux_log(self, item, raw_data):
        """Normalize Linux system log entries into Process or User entities."""
        entity_id = str(uuid.uuid4())
        event_type = raw_data.get('event_type', '')
        timestamp = raw_data.get('timestamp', item['timestamp'])
        groups = raw_data.get('match_groups', ())

        # SSH logins and sudo commands map to User entities
        if event_type in ('ssh_login_success', 'ssh_login_failed', 'sudo_command',
                          'user_added', 'user_deleted', 'su_switch', 'session_opened'):
            name = groups[0] if groups else 'unknown'
            entity_type = 'User'
        else:
            name = raw_data.get('raw_line', '')[:80]
            entity_type = 'Process'

        self.db.insert_entity(
            entity_id=entity_id,
            entity_type=entity_type,
            name=name,
            path=raw_data.get('log_file', ''),
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )

    def _normalize_linux_shell(self, item, raw_data):
        """Normalize Linux shell history commands into Process entities."""
        entity_id = str(uuid.uuid4())
        command = raw_data.get('command', raw_data.get('file_edited', ''))
        username = raw_data.get('username', 'unknown')
        timestamp = raw_data.get('timestamp', item['timestamp'])

        # Extract the base command name (first word)
        base_cmd = command.split()[0] if command.split() else command

        self.db.insert_entity(
            entity_id=entity_id,
            entity_type='Process',
            name=base_cmd,
            path=command,
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )

    def _normalize_linux_persistence(self, item, raw_data):
        """Normalize Linux persistence (cron, systemd, SUID) into Process entities."""
        entity_id = str(uuid.uuid4())
        timestamp = raw_data.get('timestamp', item['timestamp'])

        if 'service_name' in raw_data:
            name = raw_data['service_name']
            path = raw_data.get('exec_start', '')
        elif 'cron_entry' in raw_data:
            name = f"cron:{raw_data.get('owner', 'system')}"
            path = raw_data['cron_entry']
        elif 'filepath' in raw_data:
            name = raw_data.get('basename', os.path.basename(raw_data['filepath']))
            path = raw_data['filepath']
        else:
            name = 'unknown'
            path = ''

        self.db.insert_entity(
            entity_id=entity_id,
            entity_type='Process',
            name=name,
            path=path,
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )

    def _normalize_linux_memory_drop(self, item, raw_data):
        """Normalize Linux in-memory drops and SSH artifacts into File/User entities."""
        entity_id = str(uuid.uuid4())
        category = raw_data.get('category', '')
        timestamp = raw_data.get('timestamp', item['timestamp'])

        if category in ('authorized_keys', 'known_hosts', 'uid0_anomaly', 'shell_anomaly'):
            entity_type = 'User'
            name = raw_data.get('username', 'unknown')
            path = raw_data.get('file', '')
        else:
            entity_type = 'File'
            name = raw_data.get('filename', os.path.basename(raw_data.get('filepath', '')))
            path = raw_data.get('filepath', '')

        self.db.insert_entity(
            entity_id=entity_id,
            entity_type=entity_type,
            name=name,
            path=path,
            timestamp=timestamp,
            evidence_id=item['id'],
            raw_attributes_dict=raw_data
        )
