# Phishing Detection & Response (IBM QRadar)

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|--------------|----------------|--------|
| **T1566.001** | Phishing: Spearphishing Attachment | Initial Access |
| **T1566.002** | Phishing: Spearphishing Link | Initial Access |
| **T1204.002** | User Execution: Malicious File | Execution |
| **T1539** | Steal Web Session Cookie | Credential Access |
| **T1078** | Valid Accounts (Post-Compromise) | Defense Evasion |

**Why These Techniques:**
- **T1566.001 / T1566.002**: Phishing is the #1 initial access vector — delivered via links or attachments
- **T1204.002**: Attack only succeeds when the user executes the malicious file
- **T1539**: Session cookies stolen to bypass MFA after credential theft
- **T1078**: Stolen credentials used to blend in as a legitimate user

**Detection Coverage:**
- Detects spoofed emails via SPF/DKIM/DMARC failure correlation
- Catches phishing link clicks via proxy logs
- Identifies credential submission to external phishing pages
- Detects malicious macro execution from Office applications
- Catches post-phish account takeover via impossible travel
- Does NOT detect: End-to-end encrypted email channels, image-only phishing

---

## What This Project Is About

This project focuses on detecting **real-world phishing attacks** across the full kill chain using **IBM QRadar's built-in rule engine, offense manager, log activity filters, and reference sets** — without relying on complex AQL queries.

This includes:
- **Email authentication failures** - Spoofed senders failing SPF, DKIM, DMARC
- **Malicious link clicks** - Users navigating to phishing pages via proxy logs
- **Credential harvesting** - HTTP POST data sent to suspicious external domains
- **Macro execution** - Office apps spawning shells after malicious attachment opens
- **Account takeover** - Impossible travel login confirmed after credential theft

---

## How Phishing Actually Looks in Logs

Phishing isn't a single event — it's a **chain of behaviors** across multiple log sources.

Common patterns:
- Email with failed auth → same user clicks suspicious URL 10 minutes later
- `WINWORD.EXE` spawning `powershell.exe` minutes after email delivered
- HTTP POST with 500+ bytes sent to a newly registered domain
- Successful Azure AD login from foreign country 45 minutes after credential submission

Individually, these look like noise.  
**Together, they confirm a phishing compromise.**

---

## Detection Rules

### Rule 1: Suspicious Inbound Email — Auth Failures

**Detection Logic:**  
Use QRadar's Log Activity view to filter inbound mail gateway events where SPF and DKIM both fail.

**QRadar Log Activity — Quick Filter:**
```
Log Source Type  : ProofPoint Protection Server OR Mimecast
Custom Property  : SPF_Result = 'fail' OR 'softfail'
Custom Property  : DKIM_Result = 'fail'
Source IP        : NOT in Reference Set 'Trusted_Mail_Servers'
```

**QRadar Custom Rule (Rule Wizard):**
```
Rule Name  : PHI-001 | Suspicious Email - Auth Failures

When the following events are detected:
  AND when the Log Source type is one of: Proofpoint, Mimecast
  AND when the Custom Property SPF_Result is one of: fail, softfail
  AND when the Custom Property DKIM_Result is: fail
  AND when the Source IP is NOT contained in Reference Set: Trusted_Mail_Servers

Apply on: Events
Group by: Username (Recipient)

Actions:
  - Contribute to Offense: named by Username
  - Add Username to Reference Set: Active_Phishing_Recipients (TTL: 2 hours)
  - Set Offense Severity: 7
  - Set Offense Credibility: 8
```

**What This Detects:**
- Spoofed sender domains failing email authentication
- Typosquatting attempts (m1crosoft.com, paypa1.com)
- Phishing emails impersonating trusted brands

**False Positive Scenarios:**
- Misconfigured legitimate mail servers failing SPF/DKIM
- Forwarded emails breaking DKIM signature

**Response Actions:**
1. Check if other users received the same email
2. Pull full email headers from mail gateway
3. Add sender domain to `Known_Phishing_Domains` if confirmed
4. Quarantine email across all affected mailboxes

---

### Rule 2: Phishing Link Click Detected via Proxy

**Detection Logic:**  
Filter proxy log events in QRadar Log Activity for phishing/malicious URL categories with HTTP 200 responses, correlated against users who received suspicious emails.

**QRadar Log Activity — Quick Filter:**
```
Log Source Type  : Zscaler OR Bluecoat Proxy OR Squid
URL Category     : Phishing OR Malicious OR Newly Registered Domain
HTTP Status Code : 200
Username         : contained in Reference Set 'Active_Phishing_Recipients'
```

**QRadar Custom Rule (Rule Wizard):**
```
Rule Name  : PHI-002 | Phishing Link Click

When the following events are detected:
  AND when the Log Source type is one of: Zscaler, Bluecoat, Squid
  AND when the Custom Property URL_Category is one of: Phishing, Malicious, Newly Registered Domain
  AND when the Custom Property HTTP_Response_Code is: 200
  AND when the Username is contained in Reference Set: Active_Phishing_Recipients

Apply on: Events
Group by: Username

Actions:
  - Contribute to existing Offense (from PHI-001)
  - Add Username to Reference Set: Users_Who_Clicked_Phishing (TTL: 4 hours)
  - Increase Offense Severity to: 9 (CRITICAL)
  - Notify: SOC via email notification
```

**What This Detects:**
- Users successfully reaching phishing pages
- Malicious link clicks correlated with suspicious email receipt
- Access to newly registered phishing domains

**False Positive Scenarios:**
- Newly registered but legitimate business domains
- URL categorization lag from proxy vendor

**Response Actions:**
1. Confirm URL is malicious via VirusTotal / threat intel
2. Check if user submitted data after visiting (Rule 3)
3. Add domain to `Known_Phishing_Domains` reference set
4. Notify user and manager immediately

---

### Rule 3: Credential Submission to External Site

**Detection Logic:**  
Filter proxy events for HTTP POST requests with significant bytes sent to uncategorized or phishing-classified external domains — strongest sign of credential theft.

**QRadar Log Activity — Quick Filter:**
```
Log Source Type  : Zscaler OR Bluecoat Proxy
HTTP Method      : POST
Bytes Sent       : > 100
Destination      : NOT in Reference Set 'Approved_SaaS_Domains'
URL Category     : Phishing OR Uncategorized OR Newly Registered Domain
```

**QRadar Custom Rule (Rule Wizard):**
```
Rule Name  : PHI-003 | Credential Submission to Suspicious Site

When the following events are detected:
  AND when the Log Source type is one of: Zscaler, Bluecoat Proxy
  AND when the Custom Property HTTP_Method is: POST
  AND when the Custom Property Bytes_Sent is greater than: 100
  AND when the Destination is NOT contained in Reference Set: Approved_SaaS_Domains
  AND when the Custom Property URL_Category is one of: Phishing, Uncategorized, Newly Registered

Apply on: Events
Group by: Username

Actions:
  - Contribute to existing Offense (from PHI-001 / PHI-002)
  - Add Username to Reference Set: Credential_Compromise_Suspected (TTL: 24 hours)
  - Set Offense Severity to: 10 (CRITICAL)
  - Trigger SOAR: Force password reset workflow
```

**What This Detects:**
- Credentials submitted to phishing login pages
- Form data sent to suspicious external domains
- Credential harvesting via fake portals

**False Positive Scenarios:**
- Web forms on new but legitimate sites
- New SaaS tools not yet in approved list

**Response Actions:**
- Force immediate password reset for affected user
- Revoke all active sessions via Azure AD / Okta
- Add user to `Credential_Compromise_Suspected` reference set

---

### Rule 4: Malicious Attachment — Macro Execution

**Detection Logic:**  
Use QRadar's pre-built Windows Event Log rules or create a custom rule filtering EventID 4688 where Office applications spawn scripting engines.

**QRadar Log Activity — Quick Filter:**
```
Log Source Type  : Microsoft Windows Security Event Log
Event ID         : 4688
Custom Property  : Parent_Process = WINWORD.EXE OR EXCEL.EXE OR OUTLOOK.EXE
Custom Property  : Child_Process = powershell.exe OR cmd.exe OR wscript.exe OR mshta.exe
```

**QRadar Custom Rule (Rule Wizard):**
```
Rule Name  : PHI-004 | Macro Execution from Office Application

When the following events are detected:
  AND when the Log Source type is: Microsoft Windows Security Event Log
  AND when the Event ID is: 4688
  AND when the Custom Property Parent_Process is one of:
      WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, OUTLOOK.EXE, ACRORD32.EXE
  AND when the Custom Property Child_Process is one of:
      cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe
  AND when the Username is contained in Reference Set: Active_Phishing_Recipients
      (within 2 hours)

Apply on: Events
Group by: Hostname

Actions:
  - Create new CRITICAL Offense: named by Hostname
  - Set Offense Severity to: 10
  - Notify: IR Team via email
  - Trigger SOAR: Endpoint isolation workflow
```

**What This Detects:**
- Office apps spawning PowerShell or CMD — malicious macro confirmed
- Fileless payload delivery via `mshta.exe` or `wscript.exe`
- PDF readers launching scripts after malicious file open

**False Positive Scenarios:**
- Legitimate business macros used by finance or HR teams
- IT admin scripts triggered via Office automation

**Response Actions:**
1. Isolate endpoint from network immediately
2. Kill suspicious child processes
3. Preserve forensic evidence — memory dump
4. Escalate to Incident Response

---

### Rule 5: Post-Phish Account Takeover — Impossible Travel

**Detection Logic:**  
Use QRadar's built-in Anomaly Detection rules or configure a custom rule on identity provider logs to detect successful logins from countries inconsistent with the user's normal location — correlated against credential compromise events.

**QRadar Log Activity — Quick Filter:**
```
Log Source Type  : Microsoft Azure AD OR Okta
Event ID         : 4624 OR SuccessfulSignIn
Username         : contained in Reference Set 'Credential_Compromise_Suspected'
Custom Property  : Login_Country NOT EQUAL TO 'IN'
```

**QRadar Custom Rule (Rule Wizard):**
```
Rule Name  : PHI-005 | Post-Phish Impossible Travel

Sequence Rule — detect in order:
  Event A:
    Username is contained in Reference Set: Credential_Compromise_Suspected

  THEN Event B within 60 minutes:
    AND Log Source type is one of: Microsoft Azure AD, Okta
    AND Event ID is one of: 4624, SuccessfulSignIn
    AND Custom Property Login_Country is NOT: IN

Apply on: Events
Group by: Username

Actions:
  - Create new P1 Offense: named by Username
  - Add Username to Reference Set: Confirmed_Compromise
  - Set Offense Severity to: 10 (CRITICAL)
  - Trigger SOAR: Session revocation + MFA re-enrollment
```

**What This Detects:**
- Attacker logging in with stolen credentials from a different country
- Account takeover following successful credential harvesting
- MFA bypass via stolen session cookies

**False Positive Scenarios:**
- Employees traveling internationally
- Users on VPN with foreign exit nodes

**Response Actions:**
- Revoke all active sessions immediately via SOAR
- Force MFA re-enrollment
- Add user to `Confirmed_Compromise` reference set
- Create P1 Incident

---

## Example Detection Scenario

**Timeline of Attack:**
```
09:14 AM - Phishing email arrives — From: security@m1crosoft.com
           SPF: fail | DKIM: fail | DMARC: fail
           → PHI-001 FIRES | User added to Active_Phishing_Recipients

09:17 AM - User clicks link — GET http://login-microsofft.com → HTTP 200
           → PHI-002 FIRES | Severity elevated to HIGH

09:18 AM - User submits credentials — POST 847 bytes to phishing page
           → PHI-003 FIRES | CRITICAL | Password reset triggered via SOAR

09:51 AM - Login from Moscow, Russia (user is based in India)
           → PHI-005 FIRES | Session revoked | P1 Incident created

Result: Attack fully detected and contained in 37 minutes.
```

---

## SOC Investigation Checklist

**Phase 1: Triage (5 minutes)**
- [ ] Open Offense in QRadar Offense Manager — check contributing events
- [ ] Check SPF / DKIM results in Log Activity (filter: Log Source = Mimecast/Proofpoint)
- [ ] How many users in Reference Set `Active_Phishing_Recipients`?
- [ ] Did any user submit credentials? Check `Credential_Compromise_Suspected`

**Phase 2: Scope Assessment (10 minutes)**
- [ ] Filter Log Activity — URL Category = Phishing, last 1 hour
- [ ] Check for HTTP POST events from affected users to external domains
- [ ] Review EventID 4688 for Office spawning child processes
- [ ] Check Azure AD / Okta for logins from new countries

**Phase 3: Containment (10 minutes)**
- [ ] Add phishing domain to `Known_Phishing_Domains` reference set
- [ ] Request mail gateway to retract email from all mailboxes
- [ ] Force password reset for all users in `Credential_Compromise_Suspected`
- [ ] Revoke active sessions and isolate endpoint if macro execution confirmed

**Phase 4: Escalation Decision**
- **Escalate to Tier 2 if:**
  - User reached phishing page — HTTP 200 confirmed
  - Credentials submitted — Rule PHI-003 fired
  - Macro execution on endpoint — Rule PHI-004 fired
- **Escalate to Incident Response immediately if:**
  - Impossible travel login confirmed — Rule PHI-005 fired
  - Lateral movement detected post-compromise
  - Executive or VIP account compromised

---

## Why This Detection Matters

Phishing is the **#1 initial access technique** across every threat actor category.

Detecting it early prevents:
- Mass credential theft and account takeovers
- Ransomware deployment via phishing as initial access
- Business Email Compromise (BEC) fraud
- Compliance violations (GDPR, HIPAA, PCI-DSS)
- Reputational damage from data breaches

**Real-World Impact:**
- 94% of malware is delivered via email (Verizon DBIR)
- Average time to click a phishing link: 82 seconds after delivery
- BEC caused $2.9B in losses in 2023 (FBI IC3)
- Credential theft is the entry point for 61% of all breaches

This detection is **behavior-based and cross-source** — it catches what email filters alone will miss.

---

## QRadar Reference Sets

| Reference Set Name | Type | Purpose |
|--------------------|------|---------|
| **Trusted_Mail_Servers** | IP Set | Whitelist for known legitimate SMTP relays |
| **Known_Phishing_Domains** | ALN Set | Confirmed phishing domains — used for auto-blocking |
| **Approved_SaaS_Domains** | ALN Set | Legitimate external domains allowed for POST requests |
| **Active_Phishing_Recipients** | ALN Set | Users who received a suspicious email |
| **Users_Who_Clicked_Phishing** | ALN Set | Users with proxy hit on phishing URL |
| **Credential_Compromise_Suspected** | ALN Set | Users who POSTed data to suspicious external site |
| **Confirmed_Compromise** | ALN Set | Confirmed account takeover — full IR response triggered |

---

## References

- **MITRE ATT&CK**: https://attack.mitre.org/techniques/T1566/
- **IBM QRadar Rule Wizard Guide**: https://www.ibm.com/docs/en/qsip/7.5?topic=rules-qradar
- **IBM QRadar Reference Sets**: https://www.ibm.com/docs/en/qsip/7.5?topic=sets-reference
- **CISA Phishing Guidance**: https://www.cisa.gov/topics/cyber-threats-and-advisories/phishing

---

*Detection rules built using QRadar Rule Wizard, Log Activity filters, and Reference Sets — tested against real-world phishing campaigns including BEC, credential harvesting, and macro-based initial access.*
