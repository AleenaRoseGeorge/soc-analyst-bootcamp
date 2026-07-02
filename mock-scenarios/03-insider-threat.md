# Scenario 03 — Insider Threat: Departing Employee Data Exfiltration

**Primary Tactic:** Collection → Exfiltration
**Severity:** CRITICAL
**MITRE:** T1030 | T1567.002

---

## Alert

```
[MEDIUM] Unusual Data Transfer
User:        rajesh.kumar — R&D Department
Destination: personal.dropbox.com
Files:       47 files — 1.2 GB (.dwg, .pdf, .docx)
HR Status:   Last working day TODAY
```

**Severity upgrade:** MEDIUM → CRITICAL
Reason: Departing employee + R&D IP + .dwg AutoCAD files + incremental pattern across 5 days = premeditated trade secret theft

---

## DLP History (T1030 — Data Transfer Size Limits)

| Date | Files | Size | Notes |
|------|-------|------|-------|
| Monday | 23 | 340 MB | Below DLP threshold |
| Wednesday | 31 | 560 MB | Below DLP threshold |
| Friday (today) | 47 | 1.2 GB | Final bulk transfer |

Escalating volume, deliberate threshold evasion — this is premeditated, not accidental.

---

## Why .dwg matters

> `.dwg` = AutoCAD engineering drawings — product schematics, blueprints, core IP.
> This is not a document leak. This is potential trade secret theft. Name it explicitly in every brief.

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Data Transfer Size Limits | T1030 |
| Exfiltration to Cloud Storage | T1567.002 |

---

## Who NOT to contact

| ❌ Do NOT contact | Reason |
|------------------|--------|
| Rajesh Kumar | Tips him off — Dropbox deleted, evidence lost |
| His direct manager | Could warn him |
| HR executive who processed resignation | Could be compromised or leak it |

**Correct escalation path:** SOC L2 → Senior Legal/HR leadership → CISO only

---

## Evidence to Preserve (before 5 PM auto-revocation)

| Source | What to Collect |
|--------|----------------|
| Endpoint (RND-RAJESH-L04) | Process history, browser history, USB activity, recently accessed files |
| Active Directory | Full 30-day login history, after-hours access, folder permissions |
| DLP system | Full transfer history, previous policy violations |
| Email logs | Any forwards to personal accounts |

> Chain of custody starts at first evidence collection — timestamp everything, log who collected it and where it's stored.

---

## CISO-Level Brief (impact-first)

> *"R&D intellectual property including engineering drawings may have been exfiltrated by a departing employee over a 5-day period. Rajesh Kumar transferred .dwg AutoCAD files, PDFs, and documents totalling 2.1 GB to personal Dropbox across three sessions — Monday 340MB, Wednesday 560MB, Friday 1.2GB — deliberately staying below DLP thresholds each time. This is premeditated IP theft, not accidental data loss. Recommended immediate actions: suspend access before 5 PM auto-revocation, preserve forensic image of his endpoint, engage Legal to initiate Dropbox subpoena. Do not contact Rajesh until Legal advises."*

---

## Lessons Learned

- Incremental transfer pattern across days = T1030, premeditation = Critical
- `.dwg` = AutoCAD = trade secret territory — say this explicitly in the brief
- Chain of custody starts at first evidence collection
- Insider threat escalation path is different — Legal and CISO, not just L2
