# Ransomware Defense Framework

This repository provides a complete ransomware defense framework designed for financial institutions, critical infrastructure, and cloud-first enterprises. It integrates detection engineering, hunting queries, Sigma/YARA rules, SOC playbooks, architecture patterns, and compliance mappings into a unified defense strategy.

The goal is simple: **prevent, detect, respond, and recover from ransomware attacks with measurable, repeatable, and defensible controls.**

---

## 📂 Repository Structure

### docs/
Conceptual and architectural documentation.

### detection/
Sigma rules, YARA rules, and KQL hunting queries.

### playbooks/
SOC response workflows for ransomware precursors and active incidents.

### architecture/
Ransomware kill chain, defense layers, and cloud ransomware strategy.

### diagrams/
Text-based architecture diagrams.

### governance/
NYCRR Part 500 and ISO 27001 ransomware control mappings.

### tooling/
Working prevention and validation tools — not just documentation:
- **backup-integrity-checker/** — validates backup freshness and hash integrity against a manifest, automating the governance checklist's backup resilience items. **Tested end-to-end**, including simulated tampering/missing-file detection.
- **shadow-copy-guard/** — behavioral prevention controls (Windows PowerShell + Linux Python) that kill processes matching shadow-copy/backup-deletion command patterns, operationalizing the top-priority indicator in `detection/behavioral-indicators.md`. Design inspired by [Raccine](https://github.com/Neo23x0/Raccine). Linux version **tested end-to-end**; Windows version written and syntax-reviewed, **not execution-tested** (no Windows environment available) — validate in a lab before production use.

### resources/
Curated pointers to legitimate open-source defensive tools (Raccine, Ransomware Tool Matrix, RansomLook, Velociraptor) — deliberately excludes the malware/POC repos that dominate ransomware-related GitHub search results. See [`related-open-source-tools.md`](resources/related-open-source-tools.md).

---

## 🎯 Purpose

This framework is designed for:
- SOC teams  
- Detection engineers  
- Cybersecurity architects  
- Cloud security teams  
- Incident response teams  

---

## 🚀 How to Use

1. Start with `docs/overview.md`  
2. Review the ransomware kill chain  
3. Deploy Sigma/YARA/KQL detections  
4. Deploy prevention tooling in `tooling/` (dry-run mode first — validate against your legitimate backup admin traffic before enforcing)  
5. Operationalize SOC playbooks  
6. Implement recovery strategy, validated by `tooling/backup-integrity-checker/`  
7. Align with NYCRR & ISO controls  
8. Follow the roadmap  

---

## 📘 Author

**Shakil Md. Rezwanul Bari**  
Cybersecurity Architect | Cloud Security | Threat Detection Engineering  
Website: shakilbari.com  
LinkedIn: linkedin.com/in/rezwanulbari  
Email: rezwanbari@gmail.com


