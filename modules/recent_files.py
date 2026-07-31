import winreg

def collect_recent_files():
    recent = []
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                if isinstance(value, bytes):
                    # RecentDocs stores null-terminated UTF-16 filename + MRU metadata
                    filename = value.split(b'\x00\x00')[0].decode('utf-16-le', errors='ignore')
                    recent.append({'filename': filename, 'raw_index': name})
                i += 1
            except OSError:
                break
    except FileNotFoundError:
        pass
    return recent
