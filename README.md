# 🛡️ SOC Analyst Bootcamp — 20-Day Self-Study Plan

**Type:** Self-directed study | **Focus:** Blue Team / SOC Operations  
**Duration:** 20 Days | **Status:** 🟡 In Progress (Day 3/20)

---

## 🎯 Objective

To build job-ready SOC Analyst (L1/L2) skills through structured daily study covering
real-world tools, techniques, and scenarios used in Security Operations Centers.

---

## 📅 Progress Tracker

| Day | Topic | Status |
|-----|-------|--------|
| Day 1 | Windows Event Logs & Key Event IDs | ✅ Done |
| Day 2 | Logon Types, Persistence Mechanisms & MITRE ATT&CK Mapping | ✅ Done |
| Day 3 | Suspicious PowerShell & Scheduled Task Analysis | 🟡 In Progress |
| Day 4 | Network Traffic Analysis with Wireshark | ⬜ Upcoming |
| Day 5 | SIEM Basics & Log Ingestion | ⬜ Upcoming |
| Day 6 | Microsoft Sentinel — Setup & Queries | ⬜ Upcoming |
| Day 7 | Alert Triage & Escalation Workflow | ⬜ Upcoming |
| Day 8 | Phishing Email Analysis | ⬜ Upcoming |
| Day 9 | Malware Behaviour Analysis (Static) | ⬜ Upcoming |
| Day 10 | Malware Behaviour Analysis (Dynamic) | ⬜ Upcoming |
| Day 11 | Threat Intelligence & IOC Hunting | ⬜ Upcoming |
| Day 12 | Endpoint Detection & Response (EDR) | ⬜ Upcoming |
| Day 13 | Memory Forensics Basics | ⬜ Upcoming |
| Day 14 | Incident Response Lifecycle | ⬜ Upcoming |
| Day 15 | SOC Playbooks & Runbooks | ⬜ Upcoming |
| Day 16 | Active Directory Attacks & Detection | ⬜ Upcoming |
| Day 17 | Cloud Security Monitoring (Azure/AWS) | ⬜ Upcoming |
| Day 18 | CTF — TryHackMe SOC Level 1 | ⬜ Upcoming |
| Day 19 | CTF — LetsDefend Practice Alerts | ⬜ Upcoming |
| Day 20 | Final Review & Mock SOC Scenario | ⬜ Upcoming |

---

## 📚 Topics Covered

### ✅ Day 1 — Windows Event Logs & Key Event IDs
- Windows Event Log structure and log types
- Key Event IDs every SOC analyst must know

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials |
| 4672 | Special privileges assigned |
| 4688 | New process created |
| 4698 | Scheduled task created |
| 4720 | User account created |
| 4732 | User added to privileged group |
| 7045 | New service installed |

---

### ✅ Day 2 — Logon Types, Persistence & MITRE ATT&CK

**Logon Types**

| Type | Description |
|------|-------------|
| 2 | Interactive (local login) |
| 3 | Network (SMB, file share) |
| 4 | Batch (scheduled tasks) |
| 5 | Service logon |
| 7 | Unlock workstation |
| 10 | Remote interactive (RDP) |
| 11 | Cached credentials |

**Persistence Mechanisms & MITRE Mappings**

| Technique | MITRE ID |
|-----------|----------|
| Scheduled Tasks | T1053.005 |
| Registry Run Keys | T1547.001 |
| Startup Folder | T1547.001 |
| New Service Creation | T1543.003 |
| PowerShell Profile | T1546.013 |

---


## 🧰 Tools & Platforms

`Windows Event Viewer` `Wireshark` `Microsoft Sentinel` `Splunk`  
`MITRE ATT&CK Navigator` `TryHackMe` `LetsDefend` `Hack The Box`

---

## 🏆 Certifications Running Alongside

| Certification | Platform | Status |
|---------------|----------|--------|
| SOC Fundamentals | LetsDefend × HackTheBox | ✅ Completed |
| CEH | EC-Council | 🟡 In Progress |

---

## 📌 Related Projects
- [Web Application VAPT Report](https://github.com/AleenaRoseGeorge/web-application-pentest-report)
- [Cyber Forensics Internship](https://github.com/AleenaRoseGeorge/cyber-forensics-internship)
