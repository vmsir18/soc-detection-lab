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

This project focuses on detecting **real-world phishing attacks** across the full kill chain — not just email filtering.

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
Identify inbound emails where SPF and DKIM both fail from an untrusted sending server.

**QRadar AQL Query:**
```sql
SELECT sourceip AS 'Sending IP',
       username AS 'Recipient',
       'email_sender' AS 'From Address',
       'spf_result' AS 'SPF',
       'dkim_result' AS 'DKIM',
       starttime AS 'Time'
FROM events
WHERE LOGSOURCETYPENAME(devicetype) IN ('ProofPoint Protection Server', 'Mimecast')
  AND 'spf_result' IN ('fail', 'softfail')
  AND 'dkim_result' = 'fail'
  AND sourceip NOT IN REFERENCESET('Trusted_Mail_Servers')
LAST 1 HOURS
ORDER BY starttime DESC
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
Detect when a user navigates to a phishing URL and receives HTTP 200 — meaning they successfully reached the phishing page.

**QRadar AQL Query:**
```sql
SELECT username AS 'User',
       sourceip AS 'Workstation IP',
       URL AS 'Clicked URL',
       'url_category' AS 'Category',
       'http_response_code' AS 'HTTP Status',
       starttime AS 'Time'
FROM events
WHERE LOGSOURCETYPENAME(devicetype) IN ('Zscaler', 'Bluecoat Proxy', 'Squid')
  AND 'url_category' IN ('Phishing', 'Malicious', 'Newly Registered Domain')
  AND 'http_response_code' = '200'
  AND username IN REFERENCESET('Active_Phishing_Recipients')
LAST 30 MINUTES
ORDER BY starttime DESC
```

**What This Detects:**
- Users successfully navigating to phishing pages
- Clicks on malicious links from phishing emails
- Access to newly registered domains used in campaigns

**False Positive Scenarios:**
- Newly registered but legitimate business domains
- URL categorization errors from proxy vendor

**Response Actions:**
1. Confirm URL is malicious via VirusTotal
2. Check if user submitted any data after visiting (Rule 3)
3. Add domain to `Known_Phishing_Domains` reference set
4. Notify user and manager immediately

---

### Rule 3: Credential Submission to External Site

**Detection Logic:**  
Detect HTTP POST requests with data sent to suspicious external domains — strongest indicator credentials were submitted to a phishing page.

**QRadar AQL Query:**
```sql
SELECT username AS 'User',
       sourceip AS 'Source IP',
       URL AS 'Destination URL',
       'bytes_sent' AS 'Data Sent (bytes)',
       'url_category' AS 'Category',
       starttime AS 'Time'
FROM events
WHERE LOGSOURCETYPENAME(devicetype) IN ('Zscaler', 'Bluecoat Proxy')
  AND 'http_method' = 'POST'
  AND 'bytes_sent' > 100
  AND DOMAINOF(URL) NOT IN REFERENCESET('Approved_SaaS_Domains')
  AND 'url_category' IN ('Phishing', 'Newly Registered Domain', 'Uncategorized')
LAST 24 HOURS
ORDER BY starttime DESC
```

**What This Detects:**
- Users submitting login credentials to phishing pages
- Form data sent to suspicious external domains
- Credential harvesting via fake login portals

**False Positive Scenarios:**
- Web forms on newly registered but legitimate sites
- New SaaS tools not yet added to approved list

**Response Actions:**
- Force immediate password reset for affected user
- Revoke all active sessions via Azure AD / Okta
- Add user to `Credential_Compromise_Suspected` reference set

---

### Rule 4: Malicious Attachment — Macro Execution

**Detection Logic:**  
Detect Office applications spawning shells or scripting engines — almost always a malicious macro triggered by a phishing attachment.

**QRadar AQL Query:**
```sql
SELECT username AS 'User',
       'parent_process' AS 'Parent Process',
       'process_name' AS 'Child Process',
       'command_line' AS 'Command Line',
       starttime AS 'Time'
FROM events
WHERE LOGSOURCETYPENAME(devicetype) = 'Microsoft Windows Security Event Log'
  AND EventID = 4688
  AND 'parent_process' IN ('WINWORD.EXE', 'EXCEL.EXE', 'OUTLOOK.EXE', 'ACRORD32.EXE')
  AND 'process_name' IN ('cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe')
LAST 24 HOURS
ORDER BY starttime DESC
```

**What This Detects:**
- Office apps spawning PowerShell or CMD — malicious macro execution
- Fileless payload delivery via `mshta.exe` or `wscript.exe`
- PDF readers launching scripts after malicious file open

**False Positive Scenarios:**
- Legitimate business macros used by finance or HR
- IT admin scripts triggered via Office automation

**Response Actions:**
1. Isolate endpoint from network immediately
2. Kill suspicious child processes
3. Preserve forensic evidence — memory dump
4. Escalate to Incident Response

---

### Rule 5: Post-Phish Account Takeover — Impossible Travel

**Detection Logic:**  
After credential submission, detect a successful login from a geographically impossible location within 60 minutes — confirming stolen credentials are actively being abused.

**QRadar AQL Query:**
```sql
SELECT username AS 'User',
       sourceip AS 'Login IP',
       'login_country' AS 'Country',
       'login_city' AS 'City',
       starttime AS 'Login Time'
FROM events
WHERE LOGSOURCETYPENAME(devicetype) IN ('Microsoft Azure AD', 'Okta')
  AND EventID IN (4624, 'SuccessfulSignIn')
  AND username IN REFERENCESET('Credential_Compromise_Suspected')
  AND 'login_country' != 'IN'
LAST 2 HOURS
ORDER BY starttime DESC
```

**What This Detects:**
- Attacker logging in with stolen credentials from a different country
- Account takeover following successful credential harvesting
- MFA bypass via stolen session cookies

**False Positive Scenarios:**
- Employees traveling internationally
- Users connected via VPN with foreign exit nodes

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
           → Rule 1 FIRES | User added to Active_Phishing_Recipients

09:17 AM - User clicks link — GET http://login-microsofft.com → HTTP 200
           → Rule 2 FIRES | Severity elevated to HIGH

09:18 AM - User submits credentials — POST 847 bytes to phishing page
           → Rule 3 FIRES | CRITICAL | Password reset triggered via SOAR

09:51 AM - Login from Moscow, Russia (user is based in India)
           → Rule 5 FIRES | Session revoked | P1 Incident created

Result: Attack fully detected and contained in 37 minutes.
```

---

## SOC Investigation Checklist

**Phase 1: Triage (5 minutes)**
- [ ] Check SPF / DKIM / DMARC results in mail gateway logs
- [ ] How many users received the same phishing email?
- [ ] Did any user click the link? Check `Users_Who_Clicked_Phishing`
- [ ] Did any user submit credentials? Check `Credential_Compromise_Suspected`

**Phase 2: Scope Assessment (10 minutes)**
- [ ] How many users are in the same phishing campaign?
- [ ] Were credentials submitted — POST event with bytes > 100?
- [ ] Was there macro execution on the endpoint — EventID 4688?
- [ ] Any logins from new countries after credential submission?

**Phase 3: Containment (10 minutes)**
- [ ] Block phishing domain — add to `Known_Phishing_Domains`
- [ ] Retract phishing email from all mailboxes via mail gateway
- [ ] Force password reset for users in `Credential_Compromise_Suspected`
- [ ] Revoke active sessions and isolate endpoint if macro executed

**Phase 4: Escalation Decision**
- **Escalate to Tier 2 if:**
  - User clicked phishing link and reached the page (HTTP 200)
  - Credentials submitted to external site (Rule 3 fired)
  - Macro execution detected on endpoint (Rule 4 fired)
- **Escalate to Incident Response immediately if:**
  - Impossible travel login detected (Rule 5 fired)
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
- **IBM QRadar AQL Docs**: https://www.ibm.com/docs/en/qsip/7.5?topic=overview-aql
- **CISA Phishing Guidance**: https://www.cisa.gov/topics/cyber-threats-and-advisories/phishing
- **OWASP Phishing Guide**: https://owasp.org/www-community/attacks/Phishing

---

*Detection rules tested against real-world phishing campaigns including BEC, credential harvesting, spearphishing, and macro-based initial access vectors.*
