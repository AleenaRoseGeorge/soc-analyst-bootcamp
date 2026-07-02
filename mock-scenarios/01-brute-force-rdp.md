# Scenario 01 — Brute Force RDP on Domain Controller

**Primary Tactic:** Initial Access → Credential Access → Lateral Movement  
**Severity:** CRITICAL  
**MITRE:** T1110.001 | T1021.001 | T1078

---

## Alert

```
[HIGH] Brute Force Detected
Source IP:  185.220.101.45
Target:     CORP-DC01 (Domain Controller)
Event ID:   4625 — Failed Logon
Count:      87 failed attempts in 6 minutes
Account:    administrator
Protocol:   RDP (Port 3389)
Time:       02:45 AM
```

**Severity upgrade:** HIGH → CRITICAL  
Reason: Domain Controller + confirmed Tor exit node + successful logon after failure cluster

---

## Triage Steps

| Step | Action | Finding |
|------|--------|---------|
| 1 | AbuseIPDB lookup — 185.220.101.45 | 97% abuse confidence, confirmed Tor exit node |
| 2 | Check for 4624 immediately after the 4625 cluster | Success at 02:51 AM — confirmed intrusion |
| 3 | Check Logon Type on 4624 | Type 10 (RDP) — remote session established |
| 4 | Pull subsequent 4624s from DC01 | svc_backup → CORP-FS01 at 02:53, Logon Type 3 — lateral movement |

---

## Event IDs Investigated

| Event ID | Finding |
|----------|---------|
| 4625 × 87 | Failed RDP logon — administrator account, source 185.220.101.45 |
| 4624 | Successful RDP logon at 02:51 AM — same source IP, Logon Type 10 |
| 4624 | Lateral movement — svc_backup logged into CORP-FS01 from DC01, Logon Type 3 |

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Brute Force: Password Guessing | T1110.001 |
| Remote Services: RDP | T1021.001 |
| Lateral Movement via Valid Accounts | T1078 |

---

## Containment Actions (Timestamped)

```
02:47 — Alert triggered. L1 triage initiated.
02:48 — 185.220.101.45 queried on AbuseIPDB. Confirmed Tor exit node, 97% score.
02:50 — Event ID 4624 identified. Successful RDP login as Administrator on CORP-DC01.
02:51 — Escalated to L2. Decision: observe, do not isolate.
02:53 — Lateral movement detected. svc_backup → CORP-FS01 from DC01, Logon Type 3.
02:54 — Re-escalated to L2 with new findings. Isolation approved.
02:55 — CORP-DC01 and CORP-FS01 isolated via EDR.
02:58 — Isolation confirmed. No further lateral movement detected.
```

---

## Escalation Brief

> *"Escalating a confirmed intrusion. Source IP 185.220.101.45, known Tor exit node, brute-forced CORP-DC01 via RDP — 87 failed attempts from 02:45, successful login at 02:51 as Administrator, Logon Type 10. DC01 is production domain controller. Lateral movement to FS01 confirmed via svc_backup at 02:53. Recommending isolation of DC01 and FS01. Do I have your approval?"*

---

## Lessons Learned

- Triage before escalation — enrich first, then call L2
- Re-escalate when the situation changes — outdated instructions don't apply to new facts
- Timestamps on every action; every escalation attributed
- 3 failures on a DC is not noise — asset criticality overrides low failure count
