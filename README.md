File Integrity Monitoring System

A python-based intrusion detection system that monitors file integrity using cryptographic hashing and detects potnetial spoofing attacks through historical analysis.

Features
    Core Functionality
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
    `create_baseline(monitored_paths)`
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

Expository Question 1) ---
    An example of a host-based intrusion detection tool is the tripwire program. This is a file integrity checking tool that scans files and directories on the system on a regular basis and notifies the administrator of any changes. It uses a protected database of cryptographic checksums for each file checked and compares this value with that recomputed on each file as it is scanned. It must be configured with a list of files and directories to check and what changes, if any, are permissible to each. It can allow, for example, log files to have new entries appended, but not for existing entries to be changed. What are the advantages and disadvantages of using such a tool?
    
    Hint: Consider the problem of determining which files should only change rarely, which files may change more often and how, and which change frequently and hence cannot be checked. Hence consider the amount of work in both the configuration of the program and on the system administrator monitoring the responses generated.

Expository Answer 1) ---
    Some advantages may include:
        - Files that rarely need to be modified or accessed are easily monitored.
        - Organizations may need proof that files haven't/have been tampered with for compliance requirements.
        - Organizations may be able to identify when a file, that has predictable/scheduled modifications, has been accessed outside of the  
          norm 
    Some disadvantages may include:
        - Files that are modified/accessed often may cause the tripwire to be alerted accidentally, which is called "alert fatigue"
            Source: https://www.stamus-networks.com/blog/what-is-alert-fatigue-in-cybersecurity#:~:text=Cybersecurity%20alert%20fatigue%20is%20a,alert%20fatigue%20within%20your%20organization.
        - There may be legitimate changes to files that would trip the alert.
        - Performance may be negatively impacted because calculating the hash may take up too mnuch CPU time.


