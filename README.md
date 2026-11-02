# AuthLogSentinel - Lightweight Defensive Log Analyzer

A Python-based defensive security tool designed to parse Linux authentication logs (auth.log), detect potential brute-force attacks, track unauthorized root access attempts, and audit successful authentications.

This project was built to fulfill Task 13: Build a Small Defensive Security Tool from the Cybersecurity Assessment Task Catalogue.

---

## Features

- Automated Regex Parsing: Efficiently scans standard syslog/auth log formats for SSH authentication events.
- Brute-Force Attack Detection: Groups failed attempts by source IP and flags IP addresses that exceed a configurable threshold.
- Root Target Highlighting: Flags high-risk authentication probes directed specifically at the root account.
- Access Verification: Summarizes valid logins with authentication methods (e.g., password, public key).
- Zero External Dependencies: Built entirely with Python's standard library (re, argparse, collections, datetime).

---

## Repository Structure

- log_sentinel.py: Core defensive log analysis script.
- test_auth.log: Synthetic authentication log containing both benign events and brute-force attack vectors.
- requirements.txt: Environment and dependency details.
- README.md: Project documentation and execution instructions.

---

## Getting Started

### Prerequisites

- Python 3.8 or higher installed.

### Installation

1. Clone this repository:
   `bash
   git clone [https://github.com/](https://github.com/)chanchu88/AuthLogSentinel.git
   cd AuthLogSentinel

2. No third-party packages are required.

### Usage
Run the script by passing the path to the target log file:

`python3 log_sentinel.py <path_to_log_file> [-t THRESHOLD]

Options:
<log_file>: Path to the log file (e.g., test_auth.log or /var/log/auth.log).
-t, --threshold: Minimum number of failed attempts to trigger a brute-force alert (Default: 5).
Example Command: python3 log_sentinel.py test_auth.log -t 5

Verification & Test Results
Test Input (test_auth.log highlights)
The synthetic dataset includes:
IP 192.168.1.50: 6 consecutive failed password attempts targeting root, admin, ubuntu, and testuser.
IP 10.0.0.12: 1 failed password attempt, followed by a valid publickey login for user chanchlesh.
IP 203.0.113.88: 2 failed attempts for user git.
Output Sample:

![result](assets/result.png)