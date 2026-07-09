# Ransomware Behavioral Detection Indicators

Behavior-based detection logic for ransomware activity, designed to catch novel/unknown ransomware families that signature-based detection misses — because encryption behavior is far more consistent across ransomware families than file hashes or signatures are.

## High-Confidence Behavioral Indicators

| Indicator | Why It Matters | Detection Approach |
|---|---|---|
| Shadow copy deletion (`vssadmin delete shadows`, `wmic shadowcopy delete`) | Near-universal ransomware precursor — removes the easiest local recovery path before encryption starts | Process command-line monitoring via EDR/Sysmon Event ID 1 |
| Mass file rename/modification in a short window | Encryption routines touch large volumes of files rapidly across many directories | File integrity monitoring or EDR file-activity telemetry: alert on high modification rate per process |
| New/unusual file extensions appearing en masse | Most ransomware appends a distinct extension post-encryption | File system monitoring for extension pattern changes at volume |
| Backup software/agent process termination | Ransomware frequently kills backup agents before encrypting to prevent live backup interference | Process termination monitoring for known backup service names |
| High-entropy file writes | Encrypted files have near-random byte distribution, unlike most legitimate file types | Entropy analysis on file write operations (higher-effort, EDR-platform-dependent) |

## Detection Priority

Shadow copy deletion is the single highest-value early-warning indicator — it typically happens in the seconds before mass encryption begins, giving the shortest possible window for automated containment (network isolation) to actually get ahead of the encryption event rather than just documenting it after the fact.

## Recommended Response Automation

Pair a shadow-copy-deletion detection with an automated, no-human-in-the-loop network isolation action for the source host. The cost of a false-positive isolation is far lower than the cost of the minutes an analyst takes to review and manually isolate while encryption spreads.

---
*Part of the [ransomware-defense-framework](../README.md) repository.*
