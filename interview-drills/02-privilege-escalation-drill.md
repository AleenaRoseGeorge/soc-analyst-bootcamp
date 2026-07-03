Interview Drill 02 — Privilege Escalation via Compromised Web Server

Format: Live SOC L1 interview-style quiz (no hints, no multiple choice)
Topics: Account creation abuse, RDP pivoting, MITRE technique mapping, containment sequencing
MITRE: T1136.002 | T1078.002 | T1021.001 | T1098 | T1003/T1552


Self-graded practice transcript — my answers followed by the correction, so the reasoning gaps stay visible.




Q1 — Unauthorised Domain Admin creation

09:03 AM, Monday. SIEM fires:

Event ID: 4720
Time: 09:01 AM
Host: CORP-DC01
New Account: svc_healthmonitor
Created By: john.matthews
Account Type: Domain Account
Group Added: Domain Admins

Event ID: 4732 — Member added to security-enabled group
Group: Domain Admins
Member: svc_healthmonitor
Time: 09:01 AM

John Matthews is a mid-level IT support technician. His role does not include Active Directory administration.

Question: What just happened, why is this critical, and what is the first thing you verify?

My answer: A new account was created by someone who doesn't need admin privileges; critical because it's on CORP-DC01; first I'd pull up logs from my SIEM.

Correction: Right direction, wrong level of detail. "Pull up SIEM logs" isn't a first action — it's what you've been doing since the alert fired. Need to name which logs, on which host, looking for what.

Three possibilities to hold in mind:


John made an authorised change (unlikely given his role, but possible)
John's account was compromised — attacker using his credentials
John is a malicious insider


Actual first verification: Did John raise a change request/ticket for this action? Every legitimate AD change in a controlled environment leaves a paper trail. No ticket = unauthorised, regardless of who did it.

Specific logs to pull:

SourceWhat to check4624 on DC01Where did John's session come from — his real workstation or somewhere unexpected?4688 on DC01What process created the account — legitimate AD tooling (ADUC, proper PowerShell modules) vs suspicious tooling?4625 on John's workstationAny failed logins before this — sign of credential theft?John's workstation, physicallyIs he actually at his desk, or is his machine being operated remotely?


Q2 — The source host anomaly

Event ID: 4624
Account: john.matthews
Source Host: CORP-WEB01
Logon Type: 10
Time: 08:57 AM

John's assigned workstation is CORP-JOHN-PC01.

Question: What does this tell you, and how does it change your response?

My answer: Successful logon into John's account from CORP-WEB01, Logon Type 10 (RemoteInteractive) — normal for remote workers, but John works from the office.

Feedback: Correct — and connecting it to his known work pattern unprompted was good analyst instinct. Pushed further:


John authenticated from CORP-WEB01 — a web server, not a workstation
Via RDP (Type 10) — someone remotely controlled that web server and used it as a launchpad


Normal employees don't RDP into web servers to do their work — web servers don't have ADUC or admin tools installed. Two possibilities: CORP-WEB01 was already compromised and the attacker pivoted from there to impersonate John, or John himself RDP'd into it for a reason he'd struggle to explain. Either way, CORP-WEB01 just became a crime scene.

The connected picture:

CORP-WEB01 compromised (or misused)
    ↓
john.matthews credentials used from CORP-WEB01
    ↓
RDP session to CORP-DC01 at 08:57 AM
    ↓
New Domain Admin account created at 09:01 AM
    ↓
svc_healthmonitor added to Domain Admins

A privilege escalation + persistence chain: attacker compromised WEB01, found or stole John's credentials, used them to create a backdoor admin account before anyone noticed.


Q3 — MITRE mapping the chain

Question: Name as many MITRE techniques as you can for this chain.

My answer: TA006 Credential Access, T1136 Create Account, T1190, T1003, T1021, T1078

Correction:

Right:


T1136.002 — Create Account: Domain Account ✓ (svc_healthmonitor creation)
T1078 — Valid Accounts ✓ (John's credentials used to avoid detection)
T1021.001 — Remote Services: RDP ✓ (WEB01 → DC01)


Needs correction:


TA006 is a Tactic ID, not a technique. The tactic is TA0006 Credential Access — but the specific technique is T1003 (OS Credential Dumping, if a hash was stolen) or T1552 (Unsecured Credentials, if a password was found stored on WEB01). Name the technique, not just the tactic.
T1190 — Exploit Public-Facing Application — is an assumption. There's no evidence yet of how WEB01 was initially compromised. Don't map techniques you can't evidence; that's speculation in a ticket.


Missed:


T1098 — Account Manipulation — adding svc_healthmonitor to Domain Admins is a separate technique from creating the account itself.
T1078.002 — Valid Accounts: Domain Accounts — the sub-technique for John's account specifically.


Full mapped chain:

T1190 (possible, unconfirmed) — WEB01 initially compromised
        ↓
T1003 / T1552 — John's credentials stolen from WEB01
        ↓
T1078.002 — john.matthews credentials used
        ↓
T1021.001 — RDP from WEB01 to DC01
        ↓
T1136.002 — svc_healthmonitor domain account created
        ↓
T1098 — Account added to Domain Admins

Each arrow is evidence for the ticket; each technique is a detection opportunity a SIEM rule can be built around.


Q4 — Containment order

Question: L2 approves containment. Give the correct order — and one thing you must NOT do even though it seems obvious.

My answer: Isolate the device via EDR; avoid actions that destroy volatile evidence; collect evidence (screenshots); monitor for signs the threat actor noticed containment. Thing to never do: "never open the backdoor pages."

Correction: Good instinct on preserving volatile evidence — real growth from earlier in the session. But the "never open the backdoor pages" answer doesn't apply here and was dropped. The containment list was also incomplete and in the wrong order.

Correct order for this scenario:


Disable svc_healthmonitor immediately — the backdoor account is the attacker's persistence mechanism. As long as it's active, they can log back in from anywhere even after devices are isolated. Disable in AD before anything else.
Reset john.matthews's password — his credentials are compromised; disabling isn't enough, reset forces the attacker out of any active session token.
Isolate CORP-WEB01 via EDR — the initial compromise point; cut it off to stop the entry path.
Collect volatile evidence from WEB01 — running processes, active connections, memory if possible, before anything is powered down.
Audit the full Domain Admins group — were other accounts added that haven't been spotted yet? Attackers often plant multiple persistence mechanisms.
Check for other sessions from svc_healthmonitor — did it log into anything in the 4-minute window between creation and the alert firing? Pull 4624 for that account across all hosts.


The one thing you must NOT do: Delete svc_healthmonitor.


Every instinct says remove it — it's a malicious backdoor. But deleting it destroys forensic evidence: the account SID, creation timestamp, and group membership records are all evidence for Legal and post-incident review. Disable, never delete, during an active investigation.




Scorecard

QuestionPerformance4720 + 4732 identificationRight call, weak on specificsFirst verification stepToo vague — "pull SIEM logs" isn't an actionSource host anomalyStrong — connected WEB01 to John's office location unpromptedMITRE mappingRight techniques, mixed tactic/technique IDs, missed T1098Containment orderMissed disabling the backdoor account as priority oneOne thing not to doIncorrect answer

Biggest improvement: Connecting the dots between alerts faster — the WEB01 → john.matthews → DC01 chain was followed without being led. That's real L1 triage in practice.

Still needs work: Containment thinking defaults to EDR isolation first. In identity-based attacks, the account is the weapon — neutralise the account before isolating the device.

Key lessons:


"Pull the logs" is not an action — name the specific event ID, host, and what you're looking for
Logon Type 10 from a server that isn't someone's assigned machine = pivot point, not legitimate use
Distinguish MITRE tactics (TA0006) from techniques (T1003/T1552) — and don't map techniques you can't yet evidence
In identity attacks: disable the account before isolating the device
Never delete a malicious account mid-investigation — disable only, for forensic preservation
