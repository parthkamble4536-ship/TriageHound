import sqlite3
import shutil
import os
import glob
from datetime import datetime, timedelta

def chrome_timestamp_to_datetime(chrome_time):
    # Chrome/Edge stores time as microseconds since Jan 1, 1601 (Windows epoch)
    if not chrome_time or chrome_time == 0:
        return None
    return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)

def firefox_timestamp_to_datetime(ff_time):
    # Firefox uses PRTime (microseconds since Unix epoch Jan 1, 1970)
    if not ff_time or ff_time == 0:
        return None
    return datetime(1970, 1, 1) + timedelta(microseconds=ff_time)

def query_chromium_history(db_path, browser_name):
    if not os.path.exists(db_path):
        return []
        
    temp_copy = f"{browser_name}_history_copy.db"
    shutil.copy2(db_path, temp_copy)  # copy since file is locked

    history = []
    try:
        conn = sqlite3.connect(temp_copy)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls ORDER BY last_visit_time DESC
        """)

        for url, title, visit_count, last_visit_time in cursor.fetchall():
            dt = chrome_timestamp_to_datetime(last_visit_time)
            history.append({
                'browser': browser_name,
                'url': url,
                'title': title,
                'visit_count': visit_count,
                'last_visited': dt.isoformat() if dt else None
            })
    except sqlite3.Error:
        pass
    finally:
        conn.close()
        os.remove(temp_copy)
        
    return history

def query_firefox_history(db_path):
    if not os.path.exists(db_path):
        return []
        
    temp_copy = "firefox_history_copy.db"
    shutil.copy2(db_path, temp_copy)

    history = []
    try:
        conn = sqlite3.connect(temp_copy)
        cursor = conn.cursor()
        # Join moz_places (URLs) with moz_historyvisits (visits)
        cursor.execute("""
            SELECT p.url, p.title, p.visit_count, MAX(v.visit_date) as last_visit
            FROM moz_places p
            JOIN moz_historyvisits v ON p.id = v.place_id
            GROUP BY p.id
            ORDER BY last_visit DESC
        """)

        for url, title, visit_count, last_visit in cursor.fetchall():
            dt = firefox_timestamp_to_datetime(last_visit)
            history.append({
                'browser': 'Firefox',
                'url': url,
                'title': title,
                'visit_count': visit_count,
                'last_visited': dt.isoformat() if dt else None
            })
    except sqlite3.Error:
        pass
    finally:
        conn.close()
        os.remove(temp_copy)
        
    return history

def collect_browser_history():
    all_history = []
    
    # 1. Chrome
    chrome_path = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History")
    all_history.extend(query_chromium_history(chrome_path, "Chrome"))
    
    # 2. Edge
    edge_path = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History")
    all_history.extend(query_chromium_history(edge_path, "Edge"))
    
    # 3. Firefox
    ff_profiles_dir = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
    if os.path.exists(ff_profiles_dir):
        # Firefox has random profile folders, we look for places.sqlite in all of them
        for profile in os.listdir(ff_profiles_dir):
            places_db = os.path.join(ff_profiles_dir, profile, "places.sqlite")
            if os.path.exists(places_db):
                all_history.extend(query_firefox_history(places_db))
                
    return all_history
