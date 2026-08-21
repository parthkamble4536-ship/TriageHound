import json
import os
from database.db_manager import DBManager
from modules.normalization import NormalizationEngine
from modules.correlation_engine import CorrelationEngine
from modules.confidence_engine import ConfidenceEngine
from modules.antiforensics import AntiForensicsEngine
from modules.attack_chain import AttackChainEngine
from modules.findings_engine import FindingsEngine
from reports.report_generator import generate_pdf_report

DB_PATH = "dummy_report.db"
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

db = DBManager(DB_PATH)
case_id = "TEST-DUMMY"
case_info = {
    'case_id': case_id,
    'case_name': "Dummy Synthetic Attack Case",
    'investigator_name': "John Doe",
    'target_system': "Synthetic-Host"
}
db.insert_case_metadata(case_id, case_info['investigator_name'], case_info['case_name'], case_info['target_system'])

# Insert synthetic process evidence (including PowerShell)
ps_data = json.dumps({'name': 'powershell.exe', 'pid': 1234, 'exe': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', 'create_time': '2026-08-01T10:00:00', 'cmdline': 'powershell.exe -enc aQBlAHgA'})
db.insert_evidence('process', 'psutil', 'Process: powershell.exe (PID: 1234)', '2026-08-01T10:00:00', json.loads(ps_data), case_id)

# Insert a synthetic USN journal entry (exe file)
usn_data = json.dumps({'filename': 'payload.exe', 'reasons': ['FILE_CREATE'], 'timestamp': '2026-08-01T10:01:00'})
db.insert_evidence('usn_journal', 'USN Parser', 'USN: payload.exe FILE_CREATE', '2026-08-01T10:01:00', json.loads(usn_data), case_id)

# Insert a synthetic event log clearing event
log_clear = json.dumps({'event_id': 1102, 'message': 'The audit log was cleared', 'timestamp': '2026-08-01T11:00:00'})
db.insert_evidence('event_log', 'EVTX Parser', 'Event ID 1102: The audit log was cleared', '2026-08-01T11:00:00', json.loads(log_clear), case_id)

# Run full pipeline
NormalizationEngine(db).normalize_case(case_id)
CorrelationEngine(db).run_correlation(case_id)
conf_result = ConfidenceEngine(db).calculate_score(case_id)
AntiForensicsEngine(db).run_detection(case_id)
AttackChainEngine(db).reconstruct(case_id)
summary = FindingsEngine(db).generate_summary(case_id, conf_result)

# Generate dummy timeline
timeline_data = [
    {"timestamp": "2026-08-01T09:00:00", "source": "Process", "event": "explorer.exe started"},
    {"timestamp": "2026-08-01T10:00:00", "source": "Process", "event": "powershell.exe -enc aQBlAHgA"},
    {"timestamp": "2026-08-01T10:01:00", "source": "USN", "event": "payload.exe dropped"},
    {"timestamp": "2026-08-01T11:00:00", "source": "EventLog", "event": "Event ID 1102 (Log Cleared)"}
]

output_pdf = "Dummy_Report_v1.0.pdf"
generate_pdf_report(case_info, timeline_data, output_pdf, db_manager=db, investigation_summary=summary)
print(f"Successfully Generated {output_pdf} with {summary['total_findings']} findings and a score of {conf_result['score']}.")
