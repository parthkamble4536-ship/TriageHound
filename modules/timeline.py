import sqlite3

def generate_timeline(db_path, case_id):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT artifact_type, source, description, timestamp
        FROM evidence_items
        WHERE case_id = ? AND timestamp IS NOT NULL
        ORDER BY timestamp ASC
    """, (case_id,))

    timeline = []
    for artifact_type, source, description, timestamp in cursor.fetchall():
        timeline.append({
            'time': timestamp,
            'type': artifact_type,
            'source': source,
            'event': description
        })

    conn.close()
    return timeline
