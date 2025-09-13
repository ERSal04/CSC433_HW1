import hashlib
import os
import json

# Added feature 1: Logging to a file
import logging
from datetime import datetime

logging.basicConfig(
    filename='integrity_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def get_file_info(filepath):
    """Gets the SHA256 hash, size, and modification time of a file."""
    import time

    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            hasher.update(chunk)

    stat = os.stat(filepath)

    return {
        'hash': hasher.hexdigest(),
        'size': stat.st_size,
        'modified': time.ctime(stat.st_mtime),
        'accessed': time.ctime(stat.st_atime)
    }

def create_baseline(monitored_paths, baseline_file="baseline.json", history_file="history.json"):
    """Creates a baseline of file hashes and initializes history."""
    baseline = {}
    history = load_history(history_file)

    for path in monitored_paths:
        if os.path.isfile(path):
            print(path)
            file_info = get_file_info(path)
            baseline[path] = file_info
            add_to_history(history, path, file_info, history_file)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    file_info = get_file_info(filepath)
                    baseline[filepath] = file_info
                    add_to_history(history, filepath, file_info, history_file)
    with open(baseline_file, 'w') as f:
        json.dump(baseline, f, indent=4)
    print("Baseline created successfully.")
    print("Initial history entries created.")

def add_to_history(history, filepath, file_info, history_file="history.json"):
    """Add current file state to history."""
    from datetime import datetime

    entry = {
        'check_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'file_modified': file_info['modified'],
        'hash': file_info['hash'],
        'size': file_info['size'],
        'accessed': file_info['accessed']
    }

    if filepath not in history:
        history[filepath] = []

    history[filepath].append(entry)

    save_history(history, history_file)


def load_history(history_file="history.json"):
    """Load history from JSON file, return empty dict if the file does not exist."""
    if os.path.exists(history_file):
        with open(history_file, 'r') as f:
            return json.load(f)
    return{}

def save_history(history, history_file="history.json"):
    """Save history to JSON file."""
    with open(history_file, 'w') as f:
        json.dump(history, f, indent=4)

def check_hash_in_history(filepath, current_hash, history):
    """Check if a hash has appeared before in this file's history."""
    if filepath in history:
        for entry in history[filepath]:
            if entry['hash'] == current_hash:
                return True
    return False

def check_integrity(baseline_file="baseline.json", history_file="history.json"):
    """Checks file integrity against the baseline."""
    if not os.path.exists(baseline_file):
        print("Error: Baseline file not found. Create baseline first.")
        return

    with open(baseline_file, 'r') as f:
        baseline = json.load(f)

    history = load_history(history_file)

    violations_found = False
    log_entries_added = 0

    for filepath, stored_info in baseline.items():
        if not os.path.exists(filepath):
            print(f"Alert: File removed - {filepath}")
            logging.info(f"Alert: File removed - {filepath} (original hash: {stored_info['hash']})")
            violations_found = True
            log_entries_added += 1
            continue

        current_info = get_file_info(filepath)
        
        if current_info['hash'] != stored_info['hash']:
            print(f"Alert: File modified - {filepath}")
            logging.info(f"Alert: File modified - {filepath} (old hash: {stored_info['hash']}, new hash: {current_info['hash']})")
            violations_found = True
            log_entries_added += 1
   
        if check_hash_in_history(filepath, current_info['hash'], history):
            print(f"SPOOFING ALERT: Hash {current_info['hash'][:8]}... hash appeared before for {filepath}")
            logging.info(f"SPOOFING ALERT: Hash {current_info['hash']} previously seen for {filepath}")
            log_entries_added += 1
            add_to_history(history, filepath, current_info, history_file)


    if log_entries_added > 0:
        print(f"\n{log_entries_added} new log entries added to integrity_log.txt")
    else:
        print("\nNo new log entries added to integrity_log.txt")

    if not violations_found:
        print("No integrity violations detected.")

# Usage example:
monitored_items = ["sensitive_directory/important_file.txt", "sensitive_directory"]

# create_baseline(monitored_items)
check_integrity()