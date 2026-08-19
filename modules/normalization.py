import uuid
import json

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
        # Extending further types like event logs, browser history etc.

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
