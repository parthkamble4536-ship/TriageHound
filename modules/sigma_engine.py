"""
Lightweight Sigma Rules Engine
================================
A minimal Sigma-compatible rule matcher for Windows Event Log data.

Instead of importing the full pySigma library (heavy dependencies), this
module reads Sigma-format YAML rule files and matches them against
already-parsed EVTX event data.

Sigma is the industry standard for writing detection rules against log data,
used by Splunk, Elastic SIEM, and Microsoft Sentinel.
"""

import os
import glob

try:
    import yaml  # pyrefly: ignore[missing-import]
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


def load_sigma_rules(rules_dir):
    """
    Load all .yml Sigma rule files from the given directory.

    Returns:
        list of parsed rule dicts, each containing:
            title, description, level, logsource, detection
    """
    if not YAML_AVAILABLE:
        print("[!] pyyaml is not installed. Skipping Sigma rules.")
        return []

    rules = []
    if not os.path.exists(rules_dir):
        return rules

    for filepath in sorted(glob.glob(os.path.join(rules_dir, '*.yml'))):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                rule = yaml.safe_load(f)

            if not rule or not isinstance(rule, dict):
                continue

            # Validate minimum required fields
            if 'title' not in rule or 'detection' not in rule:
                continue

            rule['_filepath'] = filepath
            rule['_filename'] = os.path.basename(filepath)
            rules.append(rule)

        except (yaml.YAMLError, OSError) as e:
            continue

    return rules


def _match_condition(event_fields, selection):
    """
    Check if an event's fields match a Sigma selection block.

    A selection is a dict of field_name -> value (or list of values).
    All fields in the selection must match for the selection to trigger.

    Supports:
        - Exact string match (case-insensitive)
        - List of values (any match = True)
        - Integer match for EventID
    """
    if not isinstance(selection, dict):
        return False

    for field, expected in selection.items():
        actual = event_fields.get(field)
        if actual is None:
            # Try case-insensitive key match
            for k, v in event_fields.items():
                if k.lower() == field.lower():
                    actual = v
                    break

        if actual is None:
            return False

        # Normalize to list for uniform handling
        if not isinstance(expected, list):
            expected = [expected]

        # Check if any expected value matches
        matched = False
        for exp_val in expected:
            if isinstance(exp_val, int) and isinstance(actual, (int, str)):
                try:
                    if int(actual) == exp_val:
                        matched = True
                        break
                except (ValueError, TypeError):
                    pass
            elif isinstance(exp_val, str) and isinstance(actual, str):
                # Case-insensitive contains match (Sigma convention)
                if exp_val.lower() in actual.lower():
                    matched = True
                    break
            elif str(exp_val) == str(actual):
                matched = True
                break

        if not matched:
            return False

    return True


def match_events(rules, events):
    """
    Match a list of parsed events against Sigma rules.

    Args:
        rules: list of Sigma rule dicts (from load_sigma_rules)
        events: list of event dicts, each with at minimum:
                  event_id (int), timestamp (str), and any additional fields

    Returns:
        list of alert dicts:
            {
                'rule_title': str,
                'rule_level': str (critical/high/medium/low/informational),
                'rule_description': str,
                'matched_event': dict,
                'sigma_file': str,
            }
    """
    alerts = []

    for rule in rules:
        detection = rule.get('detection', {})
        if not detection:
            continue

        # Get the selection blocks (everything except 'condition')
        selections = {}
        for key, value in detection.items():
            if key == 'condition':
                continue
            if isinstance(value, dict):
                selections[key] = value

        if not selections:
            continue

        condition = detection.get('condition', '')

        for event in events:
            # Build event fields dict for matching
            event_fields = dict(event)

            # Normalize EventID field name
            if 'event_id' in event_fields and 'EventID' not in event_fields:
                event_fields['EventID'] = event_fields['event_id']

            # Evaluate condition
            triggered = False

            if 'all of' in str(condition):
                # All selections must match
                triggered = all(
                    _match_condition(event_fields, sel)
                    for sel in selections.values()
                )
            elif ' or ' in str(condition):
                # Any selection match triggers
                triggered = any(
                    _match_condition(event_fields, sel)
                    for sel in selections.values()
                )
            elif ' and ' in str(condition):
                # All named selections in the condition must match
                triggered = all(
                    _match_condition(event_fields, sel)
                    for sel in selections.values()
                )
            else:
                # Default: single selection or first selection
                for sel_name, sel_value in selections.items():
                    if _match_condition(event_fields, sel_value):
                        triggered = True
                        break

            if triggered:
                alerts.append({
                    'rule_title': rule.get('title', 'Unknown Rule'),
                    'rule_level': rule.get('level', 'medium'),
                    'rule_description': rule.get('description', ''),
                    'rule_status': rule.get('status', 'experimental'),
                    'matched_event': {
                        'event_id': event.get('event_id'),
                        'timestamp': event.get('timestamp'),
                        'description': event.get('description', ''),
                    },
                    'sigma_file': rule.get('_filename', ''),
                })

    return alerts
