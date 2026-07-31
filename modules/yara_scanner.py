import os

try:
    import yara  # pyrefly: ignore [missing-import]
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


def compile_rules(rules_dir):
    """Compile all .yar/.yara files in the given directory into a single YARA ruleset."""
    if not YARA_AVAILABLE:
        print("[!] yara-python is not installed. Skipping YARA scan.")
        return None
    rule_files = {}
    if not os.path.exists(rules_dir):
        return None

    for filename in os.listdir(rules_dir):
        if filename.endswith(('.yar', '.yara')):
            filepath = os.path.join(rules_dir, filename)
            # Use filename (without extension) as the namespace
            namespace = os.path.splitext(filename)[0]
            rule_files[namespace] = filepath

    if not rule_files:
        return None

    try:
        compiled = yara.compile(filepaths=rule_files)
        return compiled
    except yara.SyntaxError as e:
        print(f"[!] YARA syntax error: {e}")
        return None
    except Exception as e:
        print(f"[!] YARA compilation error: {e}")
        return None


def scan_file(compiled_rules, filepath):
    """Scan a single file against compiled YARA rules.
    
    Returns a list of match dicts, each containing:
        - rule: name of the matching rule
        - description: rule's meta description
        - severity: rule's meta severity
        - filepath: path that was scanned
        - matched_strings: list of matched string identifiers
    """
    if compiled_rules is None:
        return []
    if not os.path.exists(filepath):
        return []

    matches = []
    try:
        results = compiled_rules.match(filepath, timeout=30)
        for match in results:
            meta = match.meta if hasattr(match, 'meta') else {}
            matched_strings = []
            if hasattr(match, 'strings'):
                for s in match.strings:
                    matched_strings.append(str(s))

            matches.append({
                'rule': match.rule,
                'description': meta.get('description', 'No description'),
                'severity': meta.get('severity', 'UNKNOWN'),
                'filepath': filepath,
                'matched_strings': matched_strings
            })
    except yara.TimeoutError:
        pass
    except yara.Error:
        pass

    return matches


def scan_files(compiled_rules, file_list):
    """Scan a list of file paths against compiled YARA rules.
    
    Returns a list of all match dicts across all files.
    """
    all_matches = []
    for filepath in file_list:
        file_matches = scan_file(compiled_rules, filepath)
        all_matches.extend(file_matches)
    return all_matches
