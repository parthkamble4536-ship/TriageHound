import winreg
import os

STARTUP_LOCATIONS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

SUSPICIOUS_PATHS = ['temp', 'appdata\\local\\temp', 'downloads']

def collect_startup_entries():
    entries = []
    
    # 1. Check Registry Locations
    for hive, path in STARTUP_LOCATIONS:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    is_suspicious = any(s in value.lower() for s in SUSPICIOUS_PATHS)
                    entries.append({
                        'name': name,
                        'command': value,
                        'source_type': 'Registry',
                        'registry_path': path,
                        'flagged_suspicious': is_suspicious
                    })
                    i += 1
                except OSError:
                    break  # no more values
        except FileNotFoundError:
            continue
            
    # 2. Check Startup Folders
    startup_folders = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
    ]
    
    for folder in startup_folders:
        if os.path.exists(folder):
            for filename in os.listdir(folder):
                filepath = os.path.join(folder, filename)
                if os.path.isfile(filepath) and filename != "desktop.ini":
                    is_suspicious = any(s in filepath.lower() for s in SUSPICIOUS_PATHS)
                    entries.append({
                        'name': filename,
                        'command': filepath,
                        'source_type': 'Startup Folder',
                        'registry_path': folder,
                        'flagged_suspicious': is_suspicious
                    })
                    
    return entries
