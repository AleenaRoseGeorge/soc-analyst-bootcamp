# Scenario 05 — Privilege Escalation via Compromised Web Server

**Primary Tactic:** Credential Access → Privilege Escalation → Persistence
**Severity:** CRITICAL
**MITRE:** T1078.002 | T1021.001 | T1136.002 | T1098 | T1552

---

## Alert

```
Event ID 4720 — New account created: svc_healthmonitor
Created by:  john.matthews (IT Support — no AD admin rights)
Event ID 4732 — svc_healthmonitor added to Domain Admins
Host:        CORP-DC01
Time:        09:01 AM
```

---

## Investigation

| Check | Finding |
|-------|---------|
| 4624 for john.matthews | Source: CORP-WEB01 — Logon Type 10 (RDP) |
| john.matthews assigned workstation | CORP-JOHN-PC01 — WEB01 is NOT his machine |
| Change ticket check | None found — unauthorised action confirmed |

---

## Attack Chain

```
CORP-WEB01 compromised
    ↓ T1552 — credentials stolen from web server
john.matthews credentials used (T1078.002)
    ↓ T1021.001 — RDP pivot to DC01
CORP-DC01 accessed
    ↓ T1136.002 — backdoor domain account created
svc_healthmonitor added to Domain Admins (T1098)
```

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Valid Accounts: Domain | T1078.002 |
| Remote Services: RDP | T1021.001 |
| Create Account: Domain | T1136.002 |
| Account Manipulation | T1098 |
| Unsecured Credentials | T1552 |

---

## Containment Order — account first, device second

1. **Disable svc_healthmonitor in AD** — the account is the weapon; neutralise it first
2. Reset john.matthews password — forces attacker out of active sessions
3. Isolate CORP-WEB01 via EDR — the initial compromise point
4. Collect volatile evidence from WEB01
5. Audit full Domain Admins group — svc_healthmonitor may not be the only backdoor
6. Pull 4624 for svc_healthmonitor across all hosts — did it log into anything in the window?

> ⚠️ Do NOT delete svc_healthmonitor — disable only.
> Deletion destroys the account SID, creation timestamp, and group membership records — all forensic evidence for Legal and post-incident review.

---

## Escalation Brief

> *"Confirmed privilege escalation on CORP-DC01. IT support account john.matthews was used to RDP into the domain controller from CORP-WEB01 — not his assigned machine, no change ticket. A backdoor domain account svc_healthmonitor was created and added to Domain Admins at 09:01. WEB01 appears to be the initial compromise point. I've disabled svc_healthmonitor and reset john.matthews. Recommending isolation of WEB01 and full Domain Admins audit. Do I have your approval?"*

---

## Lessons Learned

- In identity attacks: disable the account BEFORE isolating the device
- Never DELETE malicious accounts — disable only (SID, timestamps, membership = forensic evidence)
- Always verify against change tickets before acting on AD alerts
- Logon Type 10 from a server = pivot point, not legitimate use
- One backdoor account doesn't mean it's the only one — audit the full group
