**File Integrity Monitoring System
**
A python-based intrusion detection system that monitors file integrity using cryptographic hashing and detects potnetial spoofing attacks through historical analysis.

**Features
**    Core Functionality
        - File Integrity Monitoring: Tracks changes to critical files and directories using SHA256 hashing
        - Baseline Creation: Establishes trusted file states for comparison
        - Real-time Detection: Identifies unauthorized modifications, deletions, and restorations.

    Enhanced Security Features
        - Comprehensive Logging: Records all security events with timestamps to `integrity_log.txt`
        - Spoofing Detection: Identifies when all files are restored to previous states to hide evidence of tampering
        - Historical Tracking: Maintains complete history of file changes in `history.json`
        - Multi-attribute Monitoring: Tracks file hash, size, modification time, and access time.

How it Works
    Baseline Creation
    create_baseline(monitored_paths)
    - Creates SHA256 has for each monitored file
    - Records file metadata (size, modification and access time)
    - Creates intitial entries in both baseline and history databases

    Integrity Checking
    `create_baseline(monitored_paths)`
    - Compares current file states against established baseline
    - Detects three types of security events:
        1. File Modification: Content changes detected via hash comparison
        2. File Deletion: Monitored files no longer exist
        3. Spoofing Attack: File restored to previous state to hide tampering

Spoofing Detection Algorithm
    The system maintains a complete history of all file states. When a file's hash matches a previously seen hash, it triggers a spoofing alert - indicating potential evidence tampering.

Attack Scenario Detected:
    1. Attacker modifies file (Hash: A → B)
    2. System detects change and logs it
    3. Attacker restores file to original state (Hash: B → A)
    4. System recognizes Hash A from history → SPOOFING ALERT

File Structure
    project/
    ├── main.py                 # Main monitoring script
    ├── baseline.json          # Trusted file states (static)
    ├── history.json           # Complete change history
    ├── integrity_log.txt      # Human-readable event log
    └── sensitive_directory/   # Example monitored directory
        └── important_file.txt
Usage
    Initial Setup
    # Define files/directories to monitor
    monitored_items = ["sensitive_directory/important_file.txt", "sensitive_directory"]

    # Create baseline (run once)
    create_baseline(monitored_items)

    Regular Monitoring
    # Run integrity checks (schedule regularly)
    check_integrity()

    Sample Output
    Alert: File modified - sensitive_directory/important_file.txt
    SPOOFING ALERT: Hash a0608e46... has appeared before for sensitive_directory/important_file.txt

    2 new log entries added to integrity_log.txt

Dependencies
    import hashlib    # Cryptographic hashing
    import os         # File system operations  
    import json       # Data serialization
    import logging    # Event logging
    import datetime   # Timestamp generation




