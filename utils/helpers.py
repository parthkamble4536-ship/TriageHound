import os
import json
import csv
from datetime import datetime


def get_timestamp():
    """Return current timestamp in ISO format."""
    return datetime.now().isoformat()


def safe_path(path):
    """Normalize and expand a file path safely."""
    return os.path.normpath(os.path.expanduser(path))


def export_to_json(data, output_path):
    """Export a list of dicts to a JSON file."""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)
    return output_path


def export_to_csv(data, output_path):
    """Export a list of dicts to a CSV file."""
    if not data:
        return output_path
    
    fieldnames = data[0].keys()
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    return output_path


def format_bytes(size_bytes):
    """Format byte count into a human-readable string."""
    if size_bytes == 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while size_bytes >= 1024 and i < len(units) - 1:
        size_bytes /= 1024
        i += 1
    return f"{size_bytes:.2f} {units[i]}"
