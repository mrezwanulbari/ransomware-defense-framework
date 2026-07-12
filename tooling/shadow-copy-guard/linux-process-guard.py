#!/usr/bin/env python3
"""
linux_process_guard.py — Behavioral prevention control for Linux, watching
for and killing processes matching destructive backup/snapshot-deletion
command patterns before they complete.

Linux companion to shadow-copy-deletion-guard.ps1 (Windows), same design
concept inspired by Raccine (https://github.com/Neo23x0/Raccine): match on
the command pattern that precedes destructive action, kill fast, rather
than trying to detect the destructive action after the fact.

Linux-specific patterns watched (the LVM/Btrfs/ZFS snapshot-deletion and
backup-wipe equivalents of vssadmin/wbadmin on Windows):
    - lvremove targeting snapshot volumes
    - btrfs subvolume delete
    - zfs destroy (on snapshot datasets)
    - rm -rf targeting common backup directory patterns

Mechanism: polls /proc for new processes (lightweight, no special kernel
module or eBPF required — trades a small window of latency for
portability across distros/kernel versions without extra dependencies).
For lower-latency production use, an eBPF-based approach (e.g. via bcc/BPF
CO-RE) or auditd exec rules with an audispd plugin would close that gap
further — this polling approach is the dependency-free baseline.

Usage:
    sudo python3 linux_process_guard.py --poll-interval 0.2
    sudo python3 linux_process_guard.py --dry-run   # log matches without killing (for testing patterns safely)
"""

import argparse
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone

BLOCKED_PATTERNS = [
    re.compile(r"lvremove.*snap", re.IGNORECASE),
    re.compile(r"btrfs\s+subvolume\s+delete", re.IGNORECASE),
    re.compile(r"zfs\s+destroy.*@", re.IGNORECASE),  # @ indicates a snapshot dataset
    re.compile(r"rm\s+-rf\s+.*(backup|snapshot)", re.IGNORECASE),
]

LOG_PATH = "/var/log/linux-process-guard.log" if os.geteuid() == 0 else "/tmp/linux-process-guard.log"


def log_event(message):
    line = f"{datetime.now(timezone.utc).isoformat()} {message}"
    print(line)
    try:
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except PermissionError:
        pass  # best-effort logging; don't crash the guard over a log write failure


def get_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
        return raw.replace(b"\x00", b" ").decode(errors="replace").strip()
    except (FileNotFoundError, ProcessLookupError):
        return None


def matches_blocked_pattern(cmdline):
    for pattern in BLOCKED_PATTERNS:
        if pattern.search(cmdline):
            return pattern.pattern
    return None


def scan_and_block(seen_pids, dry_run):
    current_pids = set(int(p) for p in os.listdir("/proc") if p.isdigit())
    new_pids = current_pids - seen_pids

    for pid in new_pids:
        cmdline = get_cmdline(pid)
        if not cmdline:
            continue
        matched_pattern = matches_blocked_pattern(cmdline)
        if matched_pattern:
            if dry_run:
                log_event(f"DRY-RUN MATCH pid={pid} pattern='{matched_pattern}' cmdline='{cmdline}'")
            else:
                try:
                    os.kill(pid, signal.SIGKILL)
                    log_event(f"BLOCKED pid={pid} pattern='{matched_pattern}' cmdline='{cmdline}'")
                except ProcessLookupError:
                    pass  # process already exited on its own
                except PermissionError:
                    log_event(f"BLOCK FAILED (permission denied — run as root) pid={pid} cmdline='{cmdline}'")

    return current_pids


def main():
    parser = argparse.ArgumentParser(description="Linux behavioral prevention control for backup/snapshot deletion commands")
    parser.add_argument("--poll-interval", type=float, default=0.2, help="Seconds between /proc scans (default 0.2)")
    parser.add_argument("--dry-run", action="store_true", help="Log matches without killing — use to validate patterns before enforcing")
    parser.add_argument("--once", action="store_true", help="Run a single scan pass and exit (for testing)")
    args = parser.parse_args()

    if os.geteuid() != 0 and not args.dry_run:
        print("Warning: not running as root — process termination will fail for processes owned by other users.", file=sys.stderr)

    log_event(f"Guard started (dry_run={args.dry_run}, poll_interval={args.poll_interval}s)")
    seen_pids = set(int(p) for p in os.listdir("/proc") if p.isdigit())

    if args.once:
        scan_and_block(seen_pids, args.dry_run)
        return

    try:
        while True:
            seen_pids = scan_and_block(seen_pids, args.dry_run)
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        log_event("Guard stopped")


if __name__ == "__main__":
    main()
