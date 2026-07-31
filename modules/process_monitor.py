import psutil
from datetime import datetime

def collect_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'memory_info', 'create_time', 'exe']):
        try:
            info = proc.info
            processes.append({
                'pid': info['pid'],
                'name': info['name'],
                'parent_pid': info['ppid'],
                'memory_mb': round(info['memory_info'].rss / 1024 / 1024, 2) if info['memory_info'] else 0,
                'start_time': datetime.fromtimestamp(info['create_time']).isoformat() if info['create_time'] else None,
                'exe_path': info['exe']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue  # process ended or protected - skip gracefully
    return processes
