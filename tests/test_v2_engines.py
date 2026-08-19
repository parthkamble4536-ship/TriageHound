"""
TriageHound v2.0 — Test Suite & Benchmarks
=============================================
Validates all v2.0 intelligence engines against a synthetic dataset.

Run:  python tests/test_v2_engines.py
"""

import os
import sys
import time
import json
import sqlite3
import unittest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import DBManager
from modules.normalization import NormalizationEngine
from modules.correlation_engine import CorrelationEngine
from modules.confidence_engine import ConfidenceEngine
from modules.antiforensics import AntiForensicsEngine
from modules.attack_chain import AttackChainEngine
from modules.findings_engine import FindingsEngine


TEST_DB = "test_v2_engines.db"
TEST_CASE = "TEST-V2-UNIT"


class TestV2Engines(unittest.TestCase):
    """Integration tests for all v2.0 engines."""

    @classmethod
    def setUpClass(cls):
        """Create a test database with synthetic evidence data."""
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)

        cls.db = DBManager(TEST_DB)
        cls.db.insert_case_metadata(TEST_CASE, "TestBot", "Unit Test Case", "TEST-PC")

        # Insert synthetic process evidence (including PowerShell)
        ps_data = json.dumps({
            'name': 'powershell.exe',
            'pid': 1234,
            'exe': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            'create_time': '2026-08-01T10:00:00',
            'cmdline': 'powershell.exe -enc aQBlAHgA',
        })
        cls.db.insert_evidence(
            'process', 'psutil',
            'Process: powershell.exe (PID: 1234)',
            '2026-08-01T10:00:00', json.loads(ps_data), TEST_CASE
        )

        # Another PowerShell instance (to test correlation grouping)
        ps_data2 = json.dumps({
            'name': 'powershell.exe',
            'pid': 5678,
            'exe': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            'create_time': '2026-08-01T10:05:00',
        })
        cls.db.insert_evidence(
            'process', 'psutil',
            'Process: powershell.exe (PID: 5678)',
            '2026-08-01T10:05:00', json.loads(ps_data2), TEST_CASE
        )

        # Insert a normal process
        normal_data = json.dumps({
            'name': 'explorer.exe',
            'pid': 100,
            'exe': r'C:\Windows\explorer.exe',
            'create_time': '2026-08-01T09:00:00',
        })
        cls.db.insert_evidence(
            'process', 'psutil',
            'Process: explorer.exe (PID: 100)',
            '2026-08-01T09:00:00', json.loads(normal_data), TEST_CASE
        )

        # Insert a synthetic USN journal entry (exe file)
        usn_data = json.dumps({
            'filename': 'payload.exe',
            'reasons': ['FILE_CREATE'],
            'timestamp': '2026-08-01T10:01:00',
        })
        cls.db.insert_evidence(
            'usn_journal', 'USN Parser',
            'USN: payload.exe FILE_CREATE',
            '2026-08-01T10:01:00', json.loads(usn_data), TEST_CASE
        )

        # Insert a synthetic event log clearing event
        log_clear = json.dumps({
            'event_id': 1102,
            'message': 'The audit log was cleared',
            'timestamp': '2026-08-01T11:00:00',
        })
        cls.db.insert_evidence(
            'event_log', 'EVTX Parser',
            'Event ID 1102: The audit log was cleared',
            '2026-08-01T11:00:00', json.loads(log_clear), TEST_CASE
        )

        cls.timings = {}

    @classmethod
    def tearDownClass(cls):
        """Clean up test database and print benchmarks."""
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)

        print("\n" + "=" * 60)
        print("  BENCHMARK RESULTS")
        print("=" * 60)
        for name, duration in cls.timings.items():
            print(f"  {name:<40s} {duration*1000:>8.2f} ms")
        print("=" * 60)

    def _bench(self, name, func, *args, **kwargs):
        """Run a function and record its execution time."""
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        self.__class__.timings[name] = elapsed
        return result

    # ── Phase 1: Normalization ──────────────────────────────────
    def test_01_normalization(self):
        """Normalization engine should create entities from evidence."""
        engine = NormalizationEngine(self.db)
        self._bench("Normalization Engine", engine.normalize_case, TEST_CASE)

        entities = self.db.get_all_entities(TEST_CASE)
        self.assertGreater(len(entities), 0, "Should produce at least one entity")

        # Check that PowerShell process entities exist
        ps_entities = [e for e in entities if 'powershell' in (e.get('name', '') or '').lower()]
        self.assertGreater(len(ps_entities), 0, "Should find PowerShell entities")

        # Check USN file entity
        file_entities = [e for e in entities if e['entity_type'] == 'File']
        self.assertGreater(len(file_entities), 0, "Should find File entities from USN")

    # ── Phase 2: Correlation ────────────────────────────────────
    def test_02_correlation(self):
        """Correlation engine should generate findings from entities."""
        engine = CorrelationEngine(self.db)
        self._bench("Correlation Engine", engine.run_correlation, TEST_CASE)

        findings = self.db.get_all_findings(TEST_CASE)
        self.assertGreater(len(findings), 0, "Should produce at least one finding")

        # Should detect PowerShell execution
        ps_findings = [f for f in findings if 'PowerShell' in (f.get('title', '') or '')]
        self.assertGreater(len(ps_findings), 0, "Should detect PowerShell execution")

        # Should detect executable dropped
        exe_findings = [f for f in findings if 'Executable' in (f.get('title', '') or '')]
        self.assertGreater(len(exe_findings), 0, "Should detect dropped executable")

    # ── Phase 3: Confidence ─────────────────────────────────────
    def test_03_confidence(self):
        """Confidence engine should calculate a score > 0."""
        engine = ConfidenceEngine(self.db)
        result = self._bench("Confidence Engine", engine.calculate_score, TEST_CASE)

        self.assertIn('score', result)
        self.assertIn('severity', result)
        self.assertIn('breakdown', result)
        self.assertGreater(result['score'], 0, "Score should be > 0 with findings")
        self.assertLessEqual(result['score'], 100, "Score should not exceed 100")
        self.assertIn(result['severity'], ('LOW', 'MEDIUM', 'HIGH', 'INFO'))
        self.confidence_result = result

    # ── Phase 4: Anti-Forensics ─────────────────────────────────
    def test_04_antiforensics(self):
        """Anti-forensics engine should detect log clearing."""
        engine = AntiForensicsEngine(self.db)
        alerts = self._bench("Anti-Forensics Engine", engine.run_detection, TEST_CASE)

        # Should detect log clearing (EID 1102)
        log_alerts = [a for a in alerts if 'Log Clearing' in a.get('description', '')]
        self.assertGreater(len(log_alerts), 0,
                           "Should detect Event ID 1102 log clearing")

    # ── Phase 5: Attack Chain ───────────────────────────────────
    def test_05_attack_chain(self):
        """Attack chain engine should reconstruct links between findings."""
        engine = AttackChainEngine(self.db)
        chain = self._bench("Attack Chain Engine", engine.reconstruct, TEST_CASE)

        # With multiple findings (PowerShell + Executable), we should have links
        self.assertGreater(len(chain), 0,
                           "Should reconstruct at least one attack chain link")

    # ── Phase 6: Findings Engine ────────────────────────────────
    def test_06_findings_engine(self):
        """Findings engine should produce a complete investigation summary."""
        engine = FindingsEngine(self.db)

        # Get confidence result for input
        conf_engine = ConfidenceEngine(self.db)
        confidence_result = conf_engine.calculate_score(TEST_CASE)

        summary = self._bench("Findings Engine",
                              engine.generate_summary, TEST_CASE, confidence_result)

        self.assertIn('confidence_score', summary)
        self.assertIn('total_findings', summary)
        self.assertIn('findings', summary)
        self.assertIn('anti_forensics_alerts', summary)
        self.assertIn('attack_chain', summary)
        self.assertGreater(summary['total_findings'], 0)

        # Each finding should have recommendation
        for f in summary['findings']:
            self.assertIn('recommendation', f)
            self.assertIn('evidence_sources', f)

    # ── Data Integrity ──────────────────────────────────────────
    def test_07_database_integrity(self):
        """All v2.0 tables should have data after the full pipeline."""
        conn = sqlite3.connect(TEST_DB)
        cursor = conn.cursor()

        tables = ['entities', 'findings', 'correlations',
                  'confidence_scores', 'anti_forensics',
                  'attack_chains', 'recommendations']

        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            self.assertGreater(count, 0,
                               f"Table '{table}' should contain data")

        conn.close()


if __name__ == '__main__':
    print("=" * 60)
    print("  TriageHound v2.0 — Test Suite & Benchmarks")
    print("=" * 60)
    print()

    # Run tests in order
    loader = unittest.TestLoader()
    loader.sortTestMethodsUsing = lambda x, y: (x > y) - (x < y)
    suite = loader.loadTestsFromTestCase(TestV2Engines)
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
