# Scenario 04 — Ransomware: Network Propagation via Shared Drive

**Primary Tactic:** Initial Access → Execution → Impact → Lateral Movement  
**Severity:** CRITICAL  
**MITRE:** T1566.001 | T1486 | T1021.002

---

## Alert

```
[HIGH] Mass File Modification
Host:      HR-MEENA-L07
Files:     2,847 changed to .locked in 4 minutes
Location:  \\CORP-FILESERVER\HR
Time:      11:38 AM
```

**User report:** "I opened an email attachment and now there's a Bitcoin message on my screen."

---

## Spread Timeline

| Host | Time | Notes |
|------|------|-------|
| HR-MEENA-L07 | 11:38 AM | Patient zero |
| FIN-SARA-L02 | 11:41 AM | |
| RND-AHMED-L09 | 11:43 AM | |

3 departments in 5 minutes = SMB propagation via shared file server (T1021.002)

---

## First 30 Seconds — the only thing that matters

> Tell Meena: *"Do not restart, do not click anything, step away from the laptop."*

Restarting destroys volatile memory — encryption keys potentially recoverable from RAM are lost forever.

> ⚠️ Screenshot Meena's screen before containment — the ransom note, the email, the screen state. Once isolated, that visual evidence is gone.

---

## Containment Order

1. Isolate HR-MEENA-L07 via EDR — stops encrypted file writes to the file server
2. Check SIEM — how many hosts are actively encrypting right now?
3. Escalate to L2 simultaneously — this is big enough that L2 needs to know now
4. Isolate FIN-SARA-L02 and RND-AHMED-L09 via EDR
5. **Take CORP-FILESERVER offline** — the spread mechanism, not just the endpoints
6. Memory dump on patient zero before anything is powered down

> ⚠️ The most commonly missed action: taking the file server offline.  
> Individual endpoint isolation is not enough when the spread vector is a shared network drive.

---

## Patient Zero Investigation

| Source | What to Find |
|--------|-------------|
| Email server logs | Malicious attachment delivered to Meena just before 11:38 |
| Attachment | File extension (.exe, .xlsm, .zip), SHA256 → VirusTotal |
| EDR process tree | Macro spawning encryptor process chain |
| Email headers | Spoofed sender domain, mismatched reply-to |
| Network/proxy logs | Outbound connections immediately after delivery |

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Phishing: Spearphishing Attachment | T1566.001 |
| Data Encrypted for Impact | T1486 |
| SMB Lateral Movement | T1021.002 |

---

## Lessons Learned

- File server offline = the containment action most analysts miss
- Containment ≠ Eradication — full network sweep before any restoration
- Check double extortion: did ransomware exfiltrate before encrypting?
- Blast Radius = Data Sensitivity × Network Reachability × Account Privilege
- Capture evidence (screen state, ransom note) before isolating — you lose it after
