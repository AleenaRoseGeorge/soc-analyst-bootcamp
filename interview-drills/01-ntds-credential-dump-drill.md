# Interview Drill 01 — NTDS Credential Dump on a Domain Controller

**Format:** Live SOC L1 interview-style quiz (no hints, no multiple choice)
**Topics:** Event IDs, Logon Types, credential dumping, escalation briefs
**MITRE:** T1003.003

> This is a self-graded practice transcript — my answers followed by the correction/expected answer, so mistakes are visible rather than edited out. Use it to see the *reasoning gaps*, not just the final facts.

---

## Q1 — Failed logons on a Domain Controller

```
Event ID: 4625
Source IP: 10.0.0.44 (internal)
Target Account: Administrator
Target Host: CORP-DC01
Failure Reason: Unknown username or bad password
Count: 3 failures
Logon Type: 3
Time: 06:44 AM – 06:47 AM
```

**Question:** What is Event ID 4625, what does Logon Type 3 tell you, and is this worth investigating or is it noise?

**My answer:** 4625 is failed logon, Logon Type 3 is network (shared files, mapped drives, netlogon) — okay during business hours but suspicious at 6:44 AM.

**Correction:**
- 6:44 AM is *not* the main red flag — shift workers and automated tasks run early. Time alone doesn't make this suspicious.
- The real red flag: the target is the built-in **Administrator** account on **CORP-DC01** — a Domain Controller. That account should almost never authenticate via network Logon Type 3 in a normal environment, and is typically disabled/renamed in hardened setups. 3 failures against that account on that asset is suspicious *regardless of time*.
- Logon Type 3 isn't just file shares — it covers **any** network authentication: SMB, WinRM, remote registry, scheduled tasks over the network. Don't box it in.

**Correct framing:**
- 4625 = failed logon ✓
- Type 3 = network authentication (not just file shares)
- Red flags = privileged account + Domain Controller + internal source IP
- Internal source (10.0.0.44) needs immediate investigation — legitimate admin box, or a compromised internal machine doing credential stuffing?
- 3 failures is low volume — but **target criticality** makes it high priority anyway

---

## Q2 — Successful logon, 2 minutes later

```
Event ID: 4624
Account: Administrator
Source IP: 10.0.0.44
Target Host: CORP-DC01
Logon Type: 3
Time: 06:49 AM
```

**Question:** What just happened, what's the immediate next step, and which Event ID do you check next to understand full impact?

**My answer:** Successful logon; next I'd check 4634 (logoff).

**Correction:** 4634 tells you *when the session ended*, not what happened during it — and that's the least important thing right now. You have maybe a 2-minute window before real damage happens. Pull, in priority order:

| Event ID | Why |
|----------|-----|
| **4672** | Special privileges assigned to new logon — confirms scope of access (Administrator on a DC almost always triggers this) |
| **4688** | Process creation — what did they run after login? This is your attack-chain evidence |
| **4698** | Scheduled task created — attackers often plant persistence immediately after DC access |

4634 is fine for timeline reconstruction *later*. Not your move during an active intrusion.

---

## Q3 — The ntdsutil command

```
Event ID: 4688
Time: 06:51 AM
Host: CORP-DC01
Creator Process: cmd.exe
New Process: ntdsutil.exe
Command Line: ntdsutil "ac i ntds" "ifm" "create full c:\temp\dump" q q
User: Administrator
```

**Question:** What is `ntdsutil.exe`, what is this specific command doing, and what severity do you assign?

**My answer:** Built-in AD DS command-line tool, used for metadata cleanup etc. Severity: Critical.

**Correction:** Severity call was right — but "what is ntdsutil" isn't the same as "what is this command doing," which was the actual question.

> `ntdsutil "ac i ntds" "ifm" "create full c:\temp\dump"` is **not** metadata cleanup — it's a full **NTDS.dit database dump**.
>
> NTDS.dit is the Active Directory database: every user account, every password hash, every Kerberos key in the domain. `create full c:\temp\dump` copies the entire AD database to a temp folder — almost certainly staged for exfiltration.
>
> If this succeeds, the attacker can crack every password offline, run Pass-the-Hash against any account, and own the organisation without ever logging in again.

This is not just Critical — it's a **domain-wide credential compromise**. Every password must be treated as compromised.

**MITRE:** T1003.003 — OS Credential Dumping: NTDS

---

## Q4 — The 30-second brief to L2

**Question:** Word for word, what do you tell L2 right now?

**My answer:** *(A log recitation — 4625 at 6:47, 4624 at 6:49, 4688 at 6:51, ntdsutil, NTDS.dit copied to temp.)*

**Correction:** All the facts were correct — but that's a log readout, not a brief. L2 doesn't want a list of event IDs to piece together themselves; they want impact, then a decision ask.

> **Correct brief:** *"Confirmed credential dump on CORP-DC01. Internal host 10.0.0.44 brute-forced the built-in Administrator account via network logon, got in at 06:49, and immediately ran ntdsutil to dump the full NTDS.dit to C:\temp\dump. That's every password hash in the domain. I'm rating this Critical. I need approval to isolate DC01 and 10.0.0.44, and I think we need to treat this as a full domain compromise — every credential needs to be reset. Do I have your go-ahead?"*

**The formula:** Lead with impact, not events. "Credential dump on the DC" lands harder than "4625 then 4624 then 4688."

---

## Q5 — Suspicious scheduled task

```
Event ID: 4698
Time: 11:23 PM
Host: FIN-SERVER01
Task Name: \Microsoft\Windows\UpdateHealth
Action: C:\Users\Public\svchost.exe
Created By: NT AUTHORITY\SYSTEM
```

**Question:** What is 4698, why is this entry specifically suspicious, and what MITRE technique does it map to?

**My answer:** Scheduled task created; suspicious because it can run at highest privilege, execution path points to a world-writable location, and it maps to T1053.

**Correction:** Correct technique (T1053), but the reasoning was generic. There are **3 precise red flags** in this exact entry:

1. **Malicious executable path** — `C:\Users\Public\svchost.exe`. `Users\Public` is world-writable; anyone can drop files there without admin rights. Legitimate Windows binaries never run from here. Real path is `C:\Windows\System32\svchost.exe`. This is **T1036 — Masquerading**.
2. **Task name is a lure** — `\Microsoft\Windows\UpdateHealth` is designed to look like a legitimate Windows update task so analysts skim past it. Always verify the *action*, not the name.
3. **Created by SYSTEM at 11:23 PM** — legitimate system tasks are created at install/setup time, not at night on a live production financial server. SYSTEM creating a task means something *already running as SYSTEM* planted it — i.e., there's a **prior compromise you haven't found yet**.

---

## Q6 — Finding the escalation path

**Question:** Which Event IDs do you pull to find what gave the attacker SYSTEM-level access, and what specifically are you looking for in each?

**My answer (first pass):** 7045, 4688, 4672
**My answer (second pass, after being asked to be specific):** 4688 (process created), 4648 (explicit credential logon), 4672 (special privileges assigned)

**Correction — what to actually look for in each:**

| Event ID | Look for |
|----------|---------|
| **4688** — Process Creation | Any process running as SYSTEM that shouldn't be (mimikatz.exe, psexec.exe, custom malware); the **parent process** — what spawned it; timestamp just before 11:23 PM |
| **4648** — Explicit Credential Logon | Which account's credentials were used explicitly; which process made the call; a non-admin account using explicit SYSTEM/admin creds = credential theft in action |
| **4672** — Special Privileges | Which account received `SeDebugPrivilege`, `SeTcbPrivilege`, or `SeImpersonatePrivilege` — these three together allow SYSTEM-level impersonation; timestamp matching the window before task creation |

**The chain this builds:**

```
4648 (stolen creds used) → 4672 (privileges granted) → 4688 (malicious process runs as SYSTEM) → 4698 (persistence task created)
```

That chain is the complete attack narrative for the incident ticket.

---

## Q7 — Valid account or compromise? (the trap question)

```
Event ID: 4624
Account: svc_sqlbackup
Source Host: CORP-WEB01 (web server)
Target Host: CORP-DB01 (database server)
Logon Type: 3
Time: 2:17 AM
Frequency: Every night this week at randomised times
           Mon 01:43 | Tue 03:12 | Wed 02:58 | Thu 02:17
No malware detected. No failed logins before it. Clean AV. Service account is legitimate.
```

**Question:** Malicious or benign — and how do you prove it either way?

**My answer:** Benign — the source host is an organisation server, and if malicious you'd expect a different source host and failed logons beforehand.

**Correction — this was wrong, and it's the exact trap real interviews set:**

> Clearing a service account because the source host "looks legitimate" is dangerous reasoning. Attackers love legitimate service accounts — they blend in perfectly. No failed logins because the attacker already has valid credentials. Internal source host because they've already compromised CORP-WEB01. Clean AV because they're not using malware — they're using valid credentials.

**MITRE T1078 — Valid Accounts.** One of the hardest techniques to detect precisely because everything looks legitimate.

**Actual red flags in this "clean" alert:**

- **Randomised timing** — legitimate scheduled tasks run at fixed times, not `01:43 / 03:12 / 02:58 / 02:17`. Randomisation is a deliberate technique to evade time-based detection rules.
- **Web server authenticating to a database server** — does a backup account need to originate from the web tier? Backups typically run from a dedicated backup server, not `CORP-WEB01`.
- **Pattern started this week** — if `svc_sqlbackup` is 2 years old but this behaviour started Monday, something changed Monday.

**How to prove it either way:**

| To prove benign | To prove malicious |
|------------------|---------------------|
| Check the account's documented purpose — should it run from WEB01? | Pull 4688 on WEB01 around each logon time — what process initiated it? |
| Pull task scheduler on WEB01 — registered task? | Has `svc_sqlbackup` accessed anything beyond DB01 this week? |
| Verify with the DBA team — matching backup job? | Check 4698 on WEB01 — new task created recently? |
| Check DB01 activity — legitimate backup = large read activity | Pull WEB01 compromise history — any alerts in the last 2 weeks? |

> The answer is never "it looks clean so it's fine." Always verify against documented behaviour.

---

## Scorecard

| Question | Performance |
|----------|-------------|
| 4625 + Logon Type 3 | Missed the critical-asset angle — focused on time instead |
| 4624 success follow-up | Missed 4672 / 4688 / 4698 — jumped straight to 4634 |
| ntdsutil command | Knew the tool, missed what the specific command does |
| L2 brief | Facts correct, delivery was a log recitation not an impact brief |
| 4698 scheduled task | Right technique, generic reasoning — missed the 3 specific flags |
| SYSTEM escalation chain | Right IDs (eventually), weak on what to look for inside them |
| Valid account detection | **Wrong call** — cleared malicious activity as benign |

**Pattern:** Event ID recall is fast. The gap is analytical depth — moving from "what is this event" to "what does this specific instance tell me." The valid-account question is the most common real-world L1 failure mode: attackers with legitimate credentials inside legitimate infrastructure are the hardest thing to catch, and this answer waved it through.

**Key lessons:**
- Asset criticality overrides low failure count — always check *what* was targeted before dismissing volume
- After any successful privileged logon, the priority order is 4672 → 4688 → 4698, not 4634
- Know exactly what a suspicious command does, not just what the tool is generally used for
- Escalation briefs lead with impact, not a chronological event list
- "It looks clean" is never a conclusion on its own — verify against documented behaviour every time
