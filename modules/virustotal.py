"""
VirusTotal API Integration
============================
Checks SHA-256 hashes of files against VirusTotal's database of 70+
antivirus engines.

Uses the free VT API v3 (4 lookups/minute, 500/day).
No additional dependencies — uses stdlib urllib.
"""

import json
import time
import urllib.request
import urllib.error


VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
RATE_LIMIT_DELAY = 16  # seconds between requests (4 per minute free tier)


def check_hash(sha256, api_key):
    """
    Look up a single SHA-256 hash on VirusTotal.

    Args:
        sha256: SHA-256 hex digest string
        api_key: VirusTotal API key

    Returns:
        dict with:
            sha256, detection_ratio, malicious_count, total_engines,
            reputation, threat_label, status ('found'/'not_found'/'error')
        None if the API call fails
    """
    if not sha256 or not api_key:
        return None

    url = VT_API_URL.format(hash=sha256)
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))

        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        total = malicious + suspicious + undetected + stats.get('harmless', 0)

        threat_label = attrs.get('popular_threat_classification', {})
        suggested_label = threat_label.get('suggested_threat_label', 'N/A') if threat_label else 'N/A'

        return {
            'sha256': sha256,
            'status': 'found',
            'malicious_count': malicious,
            'suspicious_count': suspicious,
            'total_engines': total,
            'detection_ratio': f"{malicious}/{total}",
            'reputation': attrs.get('reputation', 0),
            'threat_label': suggested_label,
            'meaningful_name': attrs.get('meaningful_name', 'N/A'),
            'is_malicious': malicious >= 3,
        }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                'sha256': sha256,
                'status': 'not_found',
                'malicious_count': 0,
                'total_engines': 0,
                'detection_ratio': 'N/A',
                'threat_label': 'Not in VT database',
                'is_malicious': False,
            }
        elif e.code == 429:
            return {
                'sha256': sha256,
                'status': 'rate_limited',
                'malicious_count': 0,
                'total_engines': 0,
                'detection_ratio': 'Rate limited',
                'threat_label': 'Try again later',
                'is_malicious': False,
            }
        return None
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return None


def batch_check(hash_list, api_key, callback=None):
    """
    Check multiple SHA-256 hashes against VirusTotal, with rate limiting.

    Args:
        hash_list: list of (label, sha256) tuples
                   label is a human-readable name (e.g., process name)
        api_key: VirusTotal API key
        callback: optional function(label, result) called after each lookup

    Returns:
        list of (label, result_dict) tuples
    """
    results = []

    for i, (label, sha256) in enumerate(hash_list):
        if i > 0:
            time.sleep(RATE_LIMIT_DELAY)

        result = check_hash(sha256, api_key)
        if result:
            result['label'] = label
            results.append((label, result))

            if callback:
                callback(label, result)

    return results
