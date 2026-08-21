import sqlite3
import os
import json
import hashlib
from datetime import datetime

class DBManager:
    def __init__(self, db_path='forensics.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        if not os.path.exists(self.db_path):
            with open(schema_path, 'r') as f:
                schema_script = f.read()
            conn = self.get_connection()
            conn.executescript(schema_script)
            conn.commit()
            conn.close()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def insert_evidence(self, artifact_type, source, description, timestamp, raw_data_dict, case_id):
        raw_data = json.dumps(raw_data_dict)
        sha256_hash = hashlib.sha256(raw_data.encode('utf-8')).hexdigest()
        collected_at = datetime.now().isoformat()
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO evidence_items 
            (artifact_type, source, description, timestamp, raw_data, sha256_hash, collected_at, case_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (artifact_type, source, description, timestamp, raw_data, sha256_hash, collected_at, case_id))
        conn.commit()
        conn.close()

    def insert_case_metadata(self, case_id, investigator_name, case_name, target_system):
        start_time = datetime.now().isoformat()
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO case_metadata 
            (case_id, investigator_name, case_name, start_time, target_system)
            VALUES (?, ?, ?, ?, ?)
        """, (case_id, investigator_name, case_name, start_time, target_system))
        conn.commit()
        conn.close()

    def insert_file_hash(self, filepath, md5, sha1, sha256, file_size):
        hashed_at = datetime.now().isoformat()
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO file_hashes 
            (filepath, md5, sha1, sha256, file_size, hashed_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (filepath, md5, sha1, sha256, file_size, hashed_at))
        conn.commit()
        conn.close()

    def get_evidence_by_type(self, case_id, artifact_type):
        """Return all evidence rows of a given artifact_type for a case as list of dicts."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM evidence_items
            WHERE case_id = ? AND artifact_type = ?
            ORDER BY collected_at ASC
        """, (case_id, artifact_type))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def get_all_evidence(self, case_id):
        """Return all evidence rows for a case as list of dicts."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM evidence_items
            WHERE case_id = ?
            ORDER BY collected_at ASC
        """, (case_id,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def get_case_metadata(self, case_id):
        """Return case metadata as a dict."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM case_metadata WHERE case_id = ?", (case_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else {}

    def get_artifact_counts(self, case_id):
        """Return a dict of artifact_type -> count for a case."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT artifact_type, COUNT(*) as cnt
            FROM evidence_items WHERE case_id = ?
            GROUP BY artifact_type
        """, (case_id,))
        rows = cursor.fetchall()
        conn.close()
        return {row[0]: row[1] for row in rows}

    # -- TriageHound v1.0 Methods ----------------------------------------------
    def insert_entity(self, entity_id, entity_type, name, path, timestamp, evidence_id, raw_attributes_dict):
        raw_attributes = json.dumps(raw_attributes_dict) if raw_attributes_dict else "{}"
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO entities 
            (entity_id, entity_type, name, path, timestamp, evidence_id, raw_attributes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (entity_id, entity_type, name, path, timestamp, evidence_id, raw_attributes))
        conn.commit()
        conn.close()

    def insert_finding(self, finding_id, title, description, severity, confidence_contribution, timestamp):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO findings 
            (finding_id, title, description, severity, confidence_contribution, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (finding_id, title, description, severity, confidence_contribution, timestamp))
        conn.commit()
        conn.close()

    def insert_correlation(self, finding_id, entity_id=None, evidence_id=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO correlations 
            (finding_id, entity_id, evidence_id)
            VALUES (?, ?, ?)
        """, (finding_id, entity_id, evidence_id))
        conn.commit()
        conn.close()

    def get_all_entities(self, case_id=None):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if case_id:
            # Join with evidence_items to filter by case_id
            cursor.execute("""
                SELECT e.* FROM entities e
                JOIN evidence_items i ON e.evidence_id = i.id
                WHERE i.case_id = ?
            """, (case_id,))
        else:
            cursor.execute("SELECT * FROM entities")
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def get_all_findings(self, case_id):
        """Return all findings linked to a case via the correlations → entities → evidence_items chain."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT f.* FROM findings f
            JOIN correlations c ON f.finding_id = c.finding_id
            JOIN evidence_items i ON c.evidence_id = i.id
            WHERE i.case_id = ?
        """, (case_id,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def insert_confidence_score(self, case_id, score, severity):
        from datetime import datetime
        calculated_at = datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO confidence_scores
            (case_id, score, severity, calculated_at)
            VALUES (?, ?, ?, ?)
        """, (case_id, score, severity, calculated_at))
        conn.commit()
        conn.close()

    def insert_anti_forensic(self, alert_id, finding_id, description):
        from datetime import datetime
        detected_at = datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO anti_forensics
            (alert_id, finding_id, description, detected_at)
            VALUES (?, ?, ?, ?)
        """, (alert_id, finding_id, description, detected_at))
        conn.commit()
        conn.close()

    def get_anti_forensics(self, case_id):
        """Return all anti-forensics alerts linked to a case."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT af.* FROM anti_forensics af
            JOIN findings f ON af.finding_id = f.finding_id
            JOIN correlations c ON f.finding_id = c.finding_id
            JOIN evidence_items i ON c.evidence_id = i.id
            WHERE i.case_id = ?
        """, (case_id,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def insert_attack_chain(self, chain_id, finding_id, next_finding_id, relationship):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attack_chains
            (chain_id, finding_id, next_finding_id, relationship)
            VALUES (?, ?, ?, ?)
        """, (chain_id, finding_id, next_finding_id, relationship))
        conn.commit()
        conn.close()

    def get_attack_chains(self, case_id):
        """Return all attack chain links for a case."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT ac.* FROM attack_chains ac
            JOIN findings f ON ac.finding_id = f.finding_id
            JOIN correlations c ON f.finding_id = c.finding_id
            JOIN evidence_items i ON c.evidence_id = i.id
            WHERE i.case_id = ?
            ORDER BY f.timestamp ASC
        """, (case_id,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def insert_recommendation(self, finding_id, action):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO recommendations (finding_id, action)
            VALUES (?, ?)
        """, (finding_id, action))
        conn.commit()
        conn.close()
