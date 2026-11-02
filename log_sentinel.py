#!/usr/bin/env python3
"""
AuthLogSentinel - Lightweight Defensive Log Analyzer
Analyzes authentication logs for failed login bursts, potential brute-force,
and root login attempts.
"""

import re
import sys
import argparse
from collections import defaultdict
from datetime import datetime

# Regex pattern for OpenSSH authentication logs
SSHD_FAILED_PATTERN = re.compile(
    r'(?P<timestamp>^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)
SSHD_ACCEPTED_PATTERN = re.compile(
    r'(?P<timestamp>^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)

def parse_auth_log(filepath, threshold=5):
    failed_attempts = defaultdict(lambda: {"count": 0, "users": set(), "timestamps": []})
    successful_logins = []
    root_probes = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                # Check for Failed SSH logins
                fail_match = SSHD_FAILED_PATTERN.search(line)
                if fail_match:
                    ip = fail_match.group("ip")
                    user = fail_match.group("user")
                    ts = fail_match.group("timestamp")
                    
                    failed_attempts[ip]["count"] += 1
                    failed_attempts[ip]["users"].add(user)
                    failed_attempts[ip]["timestamps"].append(ts)

                    if user.lower() == "root":
                        root_probes.append({"line": line_no, "ip": ip, "timestamp": ts})
                    continue

                # Check for Successful logins
                acc_match = SSHD_ACCEPTED_PATTERN.search(line)
                if acc_match:
                    successful_logins.append({
                        "line": line_no,
                        "ip": acc_match.group("ip"),
                        "user": acc_match.group("user"),
                        "method": acc_match.group("method"),
                        "timestamp": acc_match.group("timestamp")
                    })

    except FileNotFoundError:
        print(f"[-] Error: File '{filepath}' not found.", file=sys.stderr)
        sys.exit(1)

    return failed_attempts, successful_logins, root_probes

def generate_report(failed_attempts, successful_logins, root_probes, threshold):
    print("=" * 70)
    print("          AUTHLOGSENTINEL DEFENSIVE AUDIT REPORT")
    print("=" * 70)
    print(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Brute-Force Alert Threshold: >= {threshold} failed attempts\n")

    # 1. Flag Potential Brute-Force Attacks
    print("[!] HIGH-PRIORITY DETECTION: Suspicious Sources (Potential Brute-Force)")
    suspicious_ips = {ip: data for ip, data in failed_attempts.items() if data["count"] >= threshold}
    
    if suspicious_ips:
        for ip, data in sorted(suspicious_ips.items(), key=lambda x: x[1]["count"], reverse=True):
            users_targeted = ", ".join(sorted(data["users"]))
            print(f"  * Threat IP: {ip:<15} | Failures: {data['count']:<3} | Targeted Users: [{users_targeted}]")
    else:
        print("  None detected exceeding threshold.")

    # 2. Flag Direct Root Attacks
    print("\n[!] SECURITY RISK: Root Login Probes")
    if root_probes:
        print(f"  Total direct root brute-force attempts: {len(root_probes)}")
        unique_root_ips = set(p["ip"] for p in root_probes)
        print(f"  Source IPs targeting root: {', '.join(unique_root_ips)}")
    else:
        print("  No root login attempts detected.")

    # 3. Successful Logins Summary
    print("\n[i] VALIDATED ACCESS: Successful Logins")
    
    if successful_logins:
        for login in successful_logins:
            print(f"  * {login['timestamp']} - User '{login['user']}' authenticated via {login['method']} from {login['ip']}")
    else:
        print("  No successful logins in this log slice.")
    print("=" * 70)

def main():
    parser = argparse.ArgumentParser(description="Analyze authentication logs for security incidents.")
    parser.add_argument("log_file", help="Path to authentication log file (e.g., auth.log)")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Failure count threshold for brute-force alerting (default: 5)")
    args = parser.parse_args()

    failed_attempts, successful_logins, root_probes = parse_auth_log(args.log_file, args.threshold)
    generate_report(failed_attempts, successful_logins, root_probes, args.threshold)

if __name__ == "__main__":
    main()