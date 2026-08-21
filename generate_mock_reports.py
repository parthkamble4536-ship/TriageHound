import sqlite3
import os
import uuid
import datetime
from reports.report_generator import generate_pdf_report
from database.db_manager import DBManager
from modules.findings_engine import FindingsEngine

DB_PATH = 'database/DF_Toolkit_Mock.db'
os.makedirs('reports', exist_ok=True)

def setup_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    with open('database/schema.sql', 'r') as f:
        c.executescript(f.read())
        
    return conn

def generate_mac_report():
    conn = setup_db()
    c = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    case_id = "MAC-2026-001"
    case_info = {
        'case_id': case_id,
        'investigator_name': "Jane Doe",
        'case_name': "Mac Insider Threat",
        'start_time': now,
        'target_system': "MacBook-Pro-CEO"
    }
    
    c.execute("INSERT INTO case_metadata (case_id, investigator_name, case_name, start_time, target_system) VALUES (?, ?, ?, ?, ?)",
              (case_id, case_info['investigator_name'], case_info['case_name'], now, case_info['target_system']))
              
    c.execute("INSERT INTO confidence_scores (case_id, score, severity, calculated_at) VALUES (?, ?, ?, ?)",
              (case_id, 92, "CRITICAL", now))
              
    f1_id = str(uuid.uuid4())
    c.execute("INSERT INTO findings (finding_id, title, description, severity, confidence_contribution, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
              (f1_id, "Suspicious LaunchDaemon Installed", "A persistent LaunchDaemon was installed in /Library/LaunchDaemons/com.apple.updatesd.plist to maintain root access.", "HIGH", 40, now))
              
    f2_id = str(uuid.uuid4())
    c.execute("INSERT INTO findings (finding_id, title, description, severity, confidence_contribution, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
              (f2_id, "Data Exfiltration via Zip", "FSEvents recorded the creation of a massive archive 'financials.zip' in /tmp followed by rapid deletion.", "CRITICAL", 52, now))

    c.execute("INSERT INTO anti_forensics (alert_id, finding_id, description, detected_at) VALUES (?, ?, ?, ?)",
              (str(uuid.uuid4()), f2_id, "Rapid file deletion in FSEvents suggests anti-forensic clearing of staging directory.", now))

    c.execute("INSERT INTO attack_chains (chain_id, finding_id, next_finding_id, relationship) VALUES (?, ?, ?, ?)",
              (str(uuid.uuid4()), f1_id, f2_id, "Maintained persistence before staging data"))
              
    c.execute("INSERT INTO recommendations (finding_id, action) VALUES (?, ?)", (f1_id, "Remove /Library/LaunchDaemons/com.apple.updatesd.plist and revoke compromised certs"))
    c.execute("INSERT INTO recommendations (finding_id, action) VALUES (?, ?)", (f2_id, "Review network telemetry for large outbound transfers matching 4.2GB zip size"))
    
    conn.commit()
    conn.close()
    
    summary = {
        'case_id': case_id,
        'confidence_score': 92,
        'severity': 'CRITICAL',
        'findings': [
            {'finding_id': f1_id, 'title': 'Suspicious LaunchDaemon Installed', 'description': 'A persistent LaunchDaemon was installed in /Library/LaunchDaemons/com.apple.updatesd.plist to maintain root access.', 'severity': 'HIGH'},
            {'finding_id': f2_id, 'title': 'Data Exfiltration via Zip', 'description': "FSEvents recorded the creation of a massive archive 'financials.zip' in /tmp followed by rapid deletion.", 'severity': 'CRITICAL'}
        ],
        'anti_forensics': [
            {'finding_id': f2_id, 'description': 'Rapid file deletion in FSEvents suggests anti-forensic clearing of staging directory.'}
        ],
        'attack_chains': [
            {'finding_id': f1_id, 'next_finding_id': f2_id, 'relationship': 'Maintained persistence before staging data'}
        ],
        'recommendations': [
            {'finding_id': f1_id, 'action': 'Remove /Library/LaunchDaemons/com.apple.updatesd.plist and revoke compromised certs'},
            {'finding_id': f2_id, 'action': 'Review network telemetry for large outbound transfers matching 4.2GB zip size'}
        ]
    }
    
    import platform
    original_system = platform.system
    platform.system = lambda: "Darwin"
    try:
        generate_pdf_report(case_info, timeline_data=[], output_path="reports/Mac_Triage_Report.pdf", db_manager=None, investigation_summary=summary)
    finally:
        platform.system = original_system
    
    print("Generated Mac Report: reports/Mac_Triage_Report.pdf")

def generate_linux_report():
    conn = setup_db()
    c = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    case_id = "LNX-2026-002"
    case_info = {
        'case_id': case_id,
        'investigator_name': "John Smith",
        'case_name': "Linux Web Server Breach",
        'start_time': now,
        'target_system': "Ubuntu-Web-01"
    }
    
    c.execute("INSERT INTO case_metadata (case_id, investigator_name, case_name, start_time, target_system) VALUES (?, ?, ?, ?, ?)",
              (case_id, case_info['investigator_name'], case_info['case_name'], now, case_info['target_system']))
              
    f1_id = str(uuid.uuid4())
    f2_id = str(uuid.uuid4())
    
    conn.commit()
    conn.close()
    
    db = DBManager(DB_PATH)
    
    summary = {
        'case_id': case_id,
        'confidence_score': 88,
        'severity': 'HIGH',
        'findings': [
            {'finding_id': f1_id, 'title': 'Suspicious SUID Binary', 'description': "A hidden binary '/usr/bin/.systemd-network' was found with SUID root permissions.", 'severity': 'CRITICAL'},
            {'finding_id': f2_id, 'title': 'SSH Key Dropped', 'description': 'In-Memory Drop scan identified a new authorized_key added for root user originating from 185.15.22.1', 'severity': 'HIGH'}
        ],
        'anti_forensics': [
            {'finding_id': f1_id, 'description': 'auth.log entries for the time surrounding binary creation were cleared.'}
        ],
        'attack_chains': [
            {'finding_id': f2_id, 'next_finding_id': f1_id, 'relationship': 'Gained SSH access then dropped SUID backdoor'}
        ],
        'recommendations': [
            {'finding_id': f1_id, 'action': 'Chmod -s /usr/bin/.systemd-network and remove the binary'},
            {'finding_id': f2_id, 'action': 'Revoke the malicious SSH key from /root/.ssh/authorized_keys'}
        ]
    }
    
    import platform
    original_system = platform.system
    platform.system = lambda: "Linux"
    try:
        generate_pdf_report(case_info, timeline_data=[], output_path="reports/Linux_Triage_Report.pdf", db_manager=None, investigation_summary=summary)
    finally:
        platform.system = original_system
        
    print("Generated Linux Report: reports/Linux_Triage_Report.pdf")

if __name__ == "__main__":
    generate_mac_report()
    generate_linux_report()
