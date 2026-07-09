# Ransomware Readiness Checklist

Governance-level checklist for assessing organizational ransomware readiness.

## Backup Resilience
- [ ] At least one backup copy is offline or immutable (air-gapped, WORM storage, or immutable cloud backup)
- [ ] Backup restoration has been tested end-to-end in the last 6 months, not just logged as successful
- [ ] Backup retention covers a window longer than realistic dwell time (30-90+ days)

## Identity & Access
- [ ] Domain admin credentials are not used for routine administration (separate privileged accounts, PAM/JIT elevation)
- [ ] MFA is enforced on all remote access paths, especially RDP and VPN
- [ ] Service account passwords are rotated and not shared across systems

## Detection & Response Readiness
- [ ] Behavioral ransomware detection (see [behavioral indicators](behavioral-indicators.md)) is deployed, not just signature-based AV
- [ ] The ransomware IR playbook has been tabletop-tested with the actual response team
- [ ] Network segmentation limits blast radius between workstations, file servers, backups, and domain controllers

## Governance
- [ ] Cyber insurance policy reviewed for ransomware-specific coverage and pre-incident requirements
- [ ] Legal/compliance has a documented position on ransom payment before an incident forces the decision
- [ ] Executive leadership has been briefed on realistic recovery time estimates

---
*Part of the [ransomware-defense-framework](../README.md) repository.*
