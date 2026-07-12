#!/usr/bin/env python3
"""
backup_integrity_checker.py — Validates backup freshness and integrity
against a manifest, directly operationalizing the "Backup Resilience"
section of governance/readiness-checklist.md.

Why this exists: "we have backups" is not the same as "we have backups that
will actually restore," and readiness checklists tend to stay as unchecked
boxes because validating backups manually is tedious. This tool automates
the repeatable part — staleness and hash-integrity checking — so the
checklist item becomes something that runs on a schedule instead of
something that gets checked once and forgotten.

This does NOT perform a full restore test (that still requires an actual
restore exercise per the readiness checklist) — it validates that backup
files exist, match their expected hash (catching silent corruption or
tampering), and are within the expected freshness window.

Usage:
    # First run: generate a manifest from your current backup set
    python3 backup_integrity_checker.py generate-manifest \\
        --backup-dir /path/to/backups --output manifest.json --max-age-hours 26

    # Subsequent runs: validate against the manifest
    python3 backup_integrity_checker.py validate \\
        --backup-dir /path/to/backups --manifest manifest.json
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256_of_file(path, chunk_size=65536):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def generate_manifest(args):
    backup_dir = Path(args.backup_dir)
    if not backup_dir.exists():
        print(f"Error: backup directory not found: {backup_dir}", file=sys.stderr)
        sys.exit(1)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "max_age_hours": args.max_age_hours,
        "files": {},
    }

    files = [f for f in backup_dir.rglob("*") if f.is_file()]
    print(f"Hashing {len(files)} file(s) in {backup_dir}...")
    for f in files:
        rel_path = str(f.relative_to(backup_dir))
        manifest["files"][rel_path] = {
            "sha256": sha256_of_file(f),
            "size_bytes": f.stat().st_size,
        }

    with open(args.output, "w") as out:
        json.dump(manifest, out, indent=2)
    print(f"Manifest written to {args.output} ({len(files)} files recorded)")


def validate(args):
    backup_dir = Path(args.backup_dir)
    with open(args.manifest) as f:
        manifest = json.load(f)

    max_age_hours = manifest.get("max_age_hours", 26)
    now = datetime.now(timezone.utc)

    results = {"ok": [], "missing": [], "hash_mismatch": [], "stale": []}

    for rel_path, expected in manifest["files"].items():
        full_path = backup_dir / rel_path
        if not full_path.exists():
            results["missing"].append(rel_path)
            continue

        actual_hash = sha256_of_file(full_path)
        if actual_hash != expected["sha256"]:
            results["hash_mismatch"].append(rel_path)
            continue

        mtime = datetime.fromtimestamp(full_path.stat().st_mtime, tz=timezone.utc)
        age_hours = (now - mtime).total_seconds() / 3600
        if age_hours > max_age_hours:
            results["stale"].append({"file": rel_path, "age_hours": round(age_hours, 1)})
            continue

        results["ok"].append(rel_path)

    print(f"\n=== Backup Integrity Report ===")
    print(f"Backup directory: {backup_dir}")
    print(f"Manifest: {args.manifest}")
    print(f"Max age threshold: {max_age_hours} hours\n")

    print(f"OK: {len(results['ok'])}")

    if results["missing"]:
        print(f"\n⚠ MISSING ({len(results['missing'])}):")
        for f in results["missing"]:
            print(f"  {f}")

    if results["hash_mismatch"]:
        print(f"\n⚠ HASH MISMATCH — possible corruption or tampering ({len(results['hash_mismatch'])}):")
        for f in results["hash_mismatch"]:
            print(f"  {f}")

    if results["stale"]:
        print(f"\n⚠ STALE — older than {max_age_hours}h threshold ({len(results['stale'])}):")
        for s in results["stale"]:
            print(f"  {s['file']} (age: {s['age_hours']}h)")

    has_issues = bool(results["missing"] or results["hash_mismatch"] or results["stale"])

    if args.output:
        with open(args.output, "w") as out:
            json.dump(results, out, indent=2)
        print(f"\nFull results written to {args.output}")

    if has_issues:
        print("\nResult: ISSUES FOUND — see above")
        sys.exit(1)
    else:
        print("\nResult: ALL CHECKS PASSED")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Backup freshness and integrity validation")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("generate-manifest", help="Generate a baseline manifest from current backups")
    p.add_argument("--backup-dir", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--max-age-hours", type=float, default=26, help="Alert threshold for backup staleness (default 26h, i.e. daily backup + buffer)")
    p.set_defaults(func=generate_manifest)

    p = sub.add_parser("validate", help="Validate current backups against a manifest")
    p.add_argument("--backup-dir", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--output", help="Optional path to write JSON results")
    p.set_defaults(func=validate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
