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

This project detects **real-world phishing attacks** across the full kill chain using **QRadar's built-in Rule Wizard, Log Activity filters, Offense Manager, and Reference Sets** — no complex AQL needed.

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
Filter mail gateway events where SPF and DKIM both fail from an untrusted server.

**QRadar Log Activity — Quick Filter:**
```
Log Source Type : Proofpoint OR Mimecast
SPF_Result      : fail OR softfail
DKIM_Result     : fail
Source IP       : NOT in Reference Set 'Trusted_Mail_Servers'
```

**QRadar Rule Wizard:**
```
Rule Name : PHI-001 | Suspicious Email - Auth Failures

Conditions:
  - Log Source is: Proofpoint OR Mimecast
  - SPF_Result is: fail OR softfail
  - DKIM_Result is: fail
  - Source IP NOT in Reference Set: Trusted_Mail_Servers

Actions:
  - Contribute to Offense | Severity: 7
  - Add Username to Reference Set: Active_Phishing_Recipients (TTL: 2hrs)
```

**What This Detects:**
- Spoofed sender domains failing email authentication
- Typosquatting attempts (m1crosoft.com, paypa1.com)

**False Positives:** Misconfigured legitimate servers, forwarded emails breaking DKIM.

**Response Actions:**
1. Check how many users received the same email
2. Pull full headers from mail gateway
3. Quarantine and add domain to `Known_Phishing_Domains` if confirmed

---

### Rule 2: Phishing Link Click via Proxy

**Detection Logic:**  
Detect users navigating to phishing URLs with HTTP 200 — correlated against users from Rule 1.

**QRadar Log Activity — Quick Filter:**
```
Log Source Type  : Zscaler OR Bluecoat OR Squid
URL_Category     : Phishing OR Malicious OR Newly Registered Domain
HTTP_Status_Code : 200
Username         : IN Reference Set 'Active_Phishing_Recipients'
```

**QRadar Rule Wizard:**
```
Rule Name : PHI-002 | Phishing Link Click

Conditions:
  - Log Source is: Zscaler OR Bluecoat OR Squid
  - URL_Category is: Phishing OR Malicious OR Newly Registered Domain
  - HTTP_Response_Code is: 200
  - Username IN Reference Set: Active_Phishing_Recipients

Actions:
  - Contribute to existing Offense
  - Add Username to Reference Set: Users_Who_Clicked_Phishing (TTL: 4hrs)
  - Increase Offense Severity to: 9
```

**What This Detects:**
- Users successfully reaching phishing pages
- Malicious link clicks correlated with email receipt

**False Positives:** Newly registered legitimate domains, proxy URL categorization lag.

**Response Actions:**
1. Verify URL via VirusTotal
2. Check if user submitted data after visiting (Rule 3)
3. Notify user and manager immediately

---

### Rule 3: Credential Submission to External Site

**Detection Logic:**  
Detect HTTP POST with data sent to suspicious external domains — strongest indicator of credential theft.

**QRadar Log Activity — Quick Filter:**
```
Log Source Type : Zscaler OR Bluecoat
HTTP_Method     : POST
Bytes_Sent      : > 100
Destination     : NOT in Reference Set 'Approved_SaaS_Domains'
URL_Category    : Phishing OR Uncategorized OR Newly Registered Domain
```

**QRadar Rule Wizard:**
```
Rule Name : PHI-003 | Credential Submission

Conditions:
  - HTTP_Method is: POST
  - Bytes_Sent greater than: 100
  - Destination NOT in Reference Set: Approved_SaaS_Domains
  - URL_Category is: Phishing OR Uncategorized OR Newly Registered

Actions:
  - Contribute to existing Offense | Severity: 10 (CRITICAL)
  - Add Username to Reference Set: Credential_Compromise_Suspected (TTL: 24hrs)
  - Trigger SOAR: Force password reset workflow
```

**What This Detects:**
- Credentials submitted to fake login portals
- Form data sent to suspicious external domains

**False Positives:** Web forms on new legitimate sites, new SaaS tools not yet whitelisted.

**Response Actions:**
- Force immediate password reset
- Revoke all active sessions via Azure AD / Okta

---

### Rule 4: Malicious Attachment — Macro Execution

**Detection Logic:**  
Filter EventID 4688 where Office apps spawn scripting engines — confirms malicious macro execution.

**QRadar Log Activity — Quick Filter:**
```
Log Source Type : Windows Security Event Log
Event ID        : 4688
Parent_Process  : WINWORD.EXE OR EXCEL.EXE OR OUTLOOK.EXE OR ACRORD32.EXE
Child_Process   : powershell.exe OR cmd.exe OR wscript.exe OR mshta.exe
```

**QRadar Rule Wizard:**
```
Rule Name : PHI-004 | Macro Execution from Office App

Conditions:
  - Event ID is: 4688
  - Parent_Process is: WINWORD.EXE, EXCEL.EXE, OUTLOOK.EXE, ACRORD32.EXE
  - Child_Process is: cmd.exe, powershell.exe, wscript.exe, mshta.exe
  - Username IN Reference Set: Active_Phishing_Recipients (within 2hrs)

Actions:
  - Create new CRITICAL Offense | Severity: 10
  - Trigger SOAR: Endpoint isolation workflow
  - Notify: IR Team immediately
```

**What This Detects:**
- Office apps spawning PowerShell or CMD — malicious macro confirmed
- Fileless payload delivery via `mshta.exe` or `wscript.exe`

**False Positives:** Legitimate finance/HR macros, IT admin scripts via Office automation.

**Response Actions:**
1. Isolate endpoint immediately
2. Preserve memory dump for forensics
3. Escalate to Incident Response

---

### Rule 5: Post-Phish Account Takeover — Impossible Travel

**Detection Logic:**  
Detect successful logins from a foreign country within 60 minutes of credential submission — confirms active account takeover.

**QRadar Log Activity — Quick Filter:**
```
Log Source Type : Azure AD OR Okta
Event ID        : 4624 OR SuccessfulSignIn
Username        : IN Reference Set 'Credential_Compromise_Suspected'
Login_Country   : NOT EQUAL TO 'IN'
```

**QRadar Rule Wizard:**
```
Rule Name : PHI-005 | Impossible Travel Post-Phish

Sequence Rule:
  Event A: Username IN Reference Set: Credential_Compromise_Suspected
  THEN Event B within 60 minutes:
    - Log Source is: Azure AD OR Okta
    - Event ID is: 4624 OR SuccessfulSignIn
    - Login_Country is NOT: IN

Actions:
  - Create P1 Offense | Severity: 10 (CRITICAL)
  - Add Username to Reference Set: Confirmed_Compromise
  - Trigger SOAR: Session revocation + MFA re-enrollment
```

**What This Detects:**
- Attacker using stolen credentials from a foreign country
- Account takeover following successful credential harvesting

**False Positives:** Employees traveling internationally, VPN with foreign exit nodes.

**Response Actions:**
- Revoke all active sessions immediately
- Force MFA re-enrollment
- Create P1 Incident

---

## Example Detection Scenario

**Timeline of Attack:**
```
09:14 AM - Phishing email arrives — SPF: fail | DKIM: fail
           → PHI-001 FIRES | User added to Active_Phishing_Recipients

09:17 AM - User clicks link → HTTP 200 on phishing domain
           → PHI-002 FIRES | Severity elevated to HIGH

09:18 AM - User submits credentials → POST 847 bytes
           → PHI-003 FIRES | CRITICAL | Password reset triggered

09:51 AM - Login from Moscow (user is based in India)
           → PHI-005 FIRES | Session revoked | P1 Incident created

Result: Attack fully detected and contained in 37 minutes.
```

---

## SOC Investigation Checklist

**Phase 1: Triage (5 minutes)**
- [ ] Open Offense in QRadar Offense Manager — review contributing events
- [ ] Check SPF / DKIM results — Log Activity filter: Log Source = Mimecast/Proofpoint
- [ ] How many users in Reference Set `Active_Phishing_Recipients`?
- [ ] Any users in `Credential_Compromise_Suspected`?

**Phase 2: Containment (10 minutes)**
- [ ] Add phishing domain to `Known_Phishing_Domains` reference set
- [ ] Retract phishing email from all mailboxes via mail gateway
- [ ] Force password reset for users in `Credential_Compromise_Suspected`
- [ ] Isolate endpoint if macro execution confirmed (PHI-004)

**Phase 3: Escalation Decision**
- **Escalate to Tier 2 if:**
  - User reached phishing page — HTTP 200 confirmed
  - Credentials submitted — PHI-003 fired
  - Macro execution on endpoint — PHI-004 fired
- **Escalate to IR immediately if:**
  - Impossible travel login — PHI-005 fired
  - Lateral movement detected post-compromise
  - Executive or VIP account compromised

---

## Why This Detection Matters

Phishing is the **#1 initial access technique** across every threat actor category.

**Real-World Impact:**
- 94% of malware is delivered via email (Verizon DBIR)
- Average time to click a phishing link: 82 seconds after delivery
- BEC caused $2.9B in losses in 2023 (FBI IC3)
- Credential theft is the entry point for 61% of all breaches

---

## QRadar Reference Sets

| Reference Set Name | Type | Purpose |
|--------------------|------|---------|
| **Trusted_Mail_Servers** | IP Set | Whitelist for known legitimate SMTP relays |
| **Known_Phishing_Domains** | ALN Set | Confirmed phishing domains — auto-blocking |
| **Approved_SaaS_Domains** | ALN Set | Legitimate external domains for POST whitelist |
| **Active_Phishing_Recipients** | ALN Set | Users who received a suspicious email |
| **Users_Who_Clicked_Phishing** | ALN Set | Users with proxy hit on phishing URL |
| **Credential_Compromise_Suspected** | ALN Set | Users who POSTed data to suspicious site |
| **Confirmed_Compromise** | ALN Set | Confirmed account takeover — full IR triggered |

---

## References

- **MITRE ATT&CK**: https://attack.mitre.org/techniques/T1566/
- **IBM QRadar Rule Wizard**: https://www.ibm.com/docs/en/qsip/7.5?topic=rules-qradar
- **IBM QRadar Reference Sets**: https://www.ibm.com/docs/en/qsip/7.5?topic=sets-reference
- **CISA Phishing Guidance**: https://www.cisa.gov/topics/cyber-threats-and-advisories/phishing

---

*Built using QRadar Rule Wizard, Log Activity filters, and Reference Sets — tested against real-world phishing campaigns including BEC, credential harvesting, and macro-based initial access.*
