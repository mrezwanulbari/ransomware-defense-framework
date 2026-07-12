# Related Open-Source Ransomware Defense Tools

This repository focuses on architecture guidance, detection rules, governance controls, and prevention tooling built from direct practitioner experience. A note on scope: ransomware-related GitHub search results are dominated by actual malware source code and proof-of-concept ransomware repos — none of those are referenced here, deliberately. What follows are legitimate, widely-used **defensive** resources only.

## Behavioral Prevention
- **[Raccine](https://github.com/Neo23x0/Raccine)** — the open-source project that inspired this repo's [`shadow-copy-deletion-guard.ps1`](tooling/shadow-copy-guard/shadow-copy-deletion-guard.ps1). Raccine is the more mature, actively-maintained option for production Windows deployment; this repo's version is a from-scratch original implementation of the same underlying concept (kill the precursor command, don't wait for encryption), written for the specific pattern set documented in [`detection/behavioral-indicators.md`](detection/behavioral-indicators.md)

## Threat Intelligence on Ransomware Group TTPs
- **[Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix)** — tracks the specific tools different ransomware groups use across their attack lifecycle (initial access, lateral movement, exfiltration, encryption); useful for prioritizing which detection rules in [`detection/`](detection/) matter most against a specific threat actor you're concerned about
- **[RansomLook](https://github.com/RansomLook/RansomLook)** — monitors ransomware group leak sites, useful for threat intelligence on active campaigns and for checking whether your organization's data has appeared on a leak site during incident scoping

## Fleet-Wide Response (once containment is needed)
- **[Velociraptor](https://github.com/Velocidex/velociraptor)** — endpoint visibility and evidence collection at scale, the natural next step from this repo's containment guidance when responding across many hosts (see also [digital-forensics-dfir-toolkit](https://github.com/mrezwanulbari/digital-forensics-dfir-toolkit))

## Full Incident Response Process
For the broader IR process this framework's playbooks connect into (severity triage, phase tracking, executive notification), see [incident-response-playbooks](https://github.com/mrezwanulbari/incident-response-playbooks) — the [ransomware playbook there](https://github.com/mrezwanulbari/incident-response-playbooks/blob/main/playbooks/ransomware-incident-response-playbook.md) is the process layer this repository's technical controls feed into.

---

For comprehensive category coverage across the full incident response tooling landscape, see [awesome-incident-response](https://github.com/meirwah/awesome-incident-response).

*Part of the [ransomware-defense-framework](README.md) repository.*
