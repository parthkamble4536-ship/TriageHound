import platform

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False


def collect_usb_history():
    if platform.system() != 'Windows' or not WINREG_AVAILABLE:
        return []

    devices = []
    path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        i = 0
        while True:
            try:
                device_class = winreg.EnumKey(key, i)  # e.g. "Disk&Ven_SanDisk&..."
                device_key = winreg.OpenKey(key, device_class)
                j = 0
                while True:
                    try:
                        serial = winreg.EnumKey(device_key, j)
                        subkey = winreg.OpenKey(device_key, serial)
                        friendly_name, _ = winreg.QueryValueEx(subkey, "FriendlyName")
                        devices.append({
                            'device_class': device_class,
                            'serial_number': serial,
                            'friendly_name': friendly_name
                        })
                        j += 1
                    except OSError:
                        break
                i += 1
            except OSError:
                break
    except FileNotFoundError:
        pass
    return devices
