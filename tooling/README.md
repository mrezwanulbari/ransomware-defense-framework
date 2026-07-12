# Prevention & Validation Tooling

Working tools operationalizing the controls documented elsewhere in this repository — not just describing what should happen, but running it.

## `backup-integrity-checker/`
Validates backup freshness and hash integrity against a manifest — automates the "Backup Resilience" checklist items in [`governance/readiness-checklist.md`](../governance/readiness-checklist.md). **Tested end-to-end**, including simulated tampering and missing-file detection — both correctly caught with a non-zero exit code suitable for cron/monitoring alerting.

## `shadow-copy-guard/`
- `shadow-copy-deletion-guard.ps1` (Windows) — behavioral prevention control that kills processes matching shadow-copy/backup-catalog deletion command patterns, operationalizing the top-priority indicator in [`detection/behavioral-indicators.md`](../detection/behavioral-indicators.md). Design inspired by [Raccine](https://github.com/Neo23x0/Raccine); written and syntax-reviewed but **not execution-tested** (no Windows environment available in this repository's build process) — validate in a lab before production use.
- `linux-process-guard.py` (Linux) — same concept for Linux backup/snapshot-deletion patterns (`lvremove` on snapshots, `btrfs subvolume delete`, `zfs destroy` on snapshot datasets, `rm -rf` targeting backup paths). **Tested end-to-end** — verified correctly detecting both a simulated `rm -rf backup` command and an `lvremove` snapshot-deletion command within roughly one poll interval, in dry-run mode.

Both guards default to (or support) **dry-run mode** — log matches without killing anything — which is the recommended first deployment step in any real environment: validate the pattern set against your actual legitimate backup administration traffic before enabling enforcement, to avoid blocking a real backup admin's routine work.

---
*Part of the [ransomware-defense-framework](../README.md) repository.*
