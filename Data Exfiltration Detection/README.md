# Sensitive Data Exfiltration Detection (Anomalous File & Network Access)

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|--------------|----------------|--------|
| **T1048** | Exfiltration Over Alternative Protocol | Exfiltration |
| **T1041** | Exfiltration Over C2 Channel | Exfiltration |
| **T1567** | Exfiltration Over Web Service | Exfiltration |
| **T1020** | Automated Exfiltration | Exfiltration |
| **T1530** | Data from Cloud Storage Object | Collection |

**Why These Techniques:**
- **T1048**: Detecting unusual outbound traffic volumes and protocols
- **T1041**: Identifying data transfers over command-and-control infrastructure
- **T1567**: Catching unauthorized uploads to cloud services (Dropbox, Google Drive, AWS S3)
- **T1020**: Automated/scripted large-scale data theft
- **T1530**: Unauthorized access and download from cloud storage

**Detection Coverage:**
-  Detects anomalous data volume transfers
-  Identifies uploads to unauthorized cloud destinations
-  Catches unusual timing patterns (after-hours exfiltration)
-  Monitors file access to sensitive directories
-  Does NOT detect: Encrypted C2 channels (without SSL inspection), physical media exfiltration (USB drives)

---

## My Detection Approach

When looking for data exfiltration, I don't assume every large upload is malicious.  

My approach is to first understand **normal data movement** in the environment and then focus on **outliers**.

I primarily look at three things:

### 1. **Volume** - Is the amount of data unusual for this user or system?
- Compare current transfer against user's 30-day baseline
- Statistical deviation detection (>3 standard deviations = anomaly)
- Absolute thresholds as safety net (e.g., >10GB in 1 hour)

### 2. **Timing** - Is the activity happening outside normal business hours?
- Transfers at 2 AM when user normally works 9-5
- Weekend activity for weekday-only users
- Holiday/vacation period transfers

### 3. **Destination** - Is the data going to a new or rarely seen external location?
- First-time destinations
- Geographically unexpected locations
- Known file-sharing services (Dropbox, WeTransfer, pastebin)
- Personal email accounts or cloud storage

**Individually these signals may not be malicious, but when they occur together, they strongly indicate possible data exfiltration.**

---

## Common False Positives 

In my experience, most alerts from this detection end up being:

-  **Legitimate cloud backups** (scheduled, expected destinations)
-  **DevOps or IT file transfers** (deployments, migrations, updates)
-  **Large software updates** (OS patches, application updates)
-  **Video conference recordings** (Zoom/Teams uploads)
-  **Legitimate business file sharing** (sending presentations, contracts)

**Because of this, these detections should always be reviewed in context rather than treated as immediate incidents.**

---

## Detection Rules

### Rule 1: Anomalous Outbound Data Volume (Baseline Deviation)

**Detection Logic:**  
Identify users transferring significantly more data than their historical baseline.

**Splunk Query:**
```splunk
index=firewall sourcetype=firewall_traffic action=allowed direction=outbound
| stats sum(bytes_out) as total_bytes by user, src_ip, dest_ip, dest_port
| eval data_mb=round(total_bytes/1024/1024, 2)
| join type=left user [
    search index=firewall sourcetype=firewall_traffic action=allowed direction=outbound earliest=-30d latest=-1d
    | stats avg(bytes_out) as baseline_avg, stdev(bytes_out) as baseline_stdev by user
]
| eval deviation=(total_bytes - baseline_avg) / baseline_stdev
| where deviation > 3 OR data_mb > 10000
| eval severity=case(
    deviation>5 OR data_mb>50000, "CRITICAL",
    deviation>3 OR data_mb>10000, "HIGH",
    1==1, "MEDIUM"
)
| eval alert_reason=case(
    deviation>3, "Statistical Anomaly (>3 StdDev)",
    data_mb>10000, "Absolute Threshold Exceeded (>10GB)",
    1==1, "Unknown"
)
| table _time, user, src_ip, dest_ip, dest_port, data_mb, baseline_avg, deviation, alert_reason, severity
| sort -data_mb
```

**What This Detects:**
- User normally transfers 100MB/day, suddenly transfers 5GB
- Accounts with no outbound history suddenly active
- Massive data transfers exceeding absolute thresholds

**Tuning Considerations:**
- Adjust deviation threshold (2-4 standard deviations)
- Set baseline period (14-30 days)
- Whitelist backup schedules and known large transfers
- Consider using `timechart` for trending analysis

**False Positive Handling:**
```splunk
| where NOT (
    dest_ip IN ("backup_server_ip_1", "backup_server_ip_2") OR
    dest_port IN (22, 3389) OR  /* SSH, RDP for IT */
    user IN ("backup_service", "devops_user")
)
```

---

### Rule 2: After-Hours Data Transfer to External Destinations

**Detection Logic:**  
Detect large outbound transfers occurring outside business hours to external IPs.

**Splunk Query:**
```splunk
index=firewall sourcetype=firewall_traffic action=allowed direction=outbound
| eval hour=strftime(_time, "%H")
| eval day_of_week=strftime(_time, "%A")
| where (hour<7 OR hour>19) OR day_of_week IN ("Saturday", "Sunday")
| lookup internal_networks.csv dest_ip OUTPUT is_internal
| where is_internal!="true"
| stats sum(bytes_out) as total_bytes, 
        dc(dest_ip) as unique_destinations,
        values(dest_ip) as destinations,
        min(_time) as first_transfer,
        max(_time) as last_transfer
        by user, src_ip
| eval data_gb=round(total_bytes/1024/1024/1024, 2)
| where data_gb > 1
| eval duration_minutes=round((last_transfer-first_transfer)/60, 0)
| eval severity=case(
    data_gb>10, "CRITICAL",
    data_gb>5, "HIGH",
    1==1, "MEDIUM"
)
| eval attack_type="After-Hours Exfiltration"
| table _time, user, src_ip, data_gb, unique_destinations, duration_minutes, attack_type, severity
```

**What This Detects:**
- Data transfers at 2 AM on weekdays
- Weekend transfers for Monday-Friday workers
- Holiday transfers during company shutdowns

**Investigation Questions:**
1. Is user on-call or working late shift legitimately?
2. Check VPN logs - was user officially logged in?
3. Review recent access - any signs of compromise?
4. Verify destinations - known business partners or suspicious?

---

### Rule 3: First-Time Destination with Large Transfer

**Detection Logic:**  
Identify large data transfers to destinations never contacted before by this user.

**Splunk Query:**
```splunk
index=firewall sourcetype=firewall_traffic action=allowed direction=outbound
| stats sum(bytes_out) as current_bytes, 
        min(_time) as first_seen, 
        max(_time) as last_seen 
        by user, dest_ip, dest_port
| join type=left user, dest_ip [
    search index=firewall sourcetype=firewall_traffic earliest=-90d latest=-1d
    | stats count as historical_connections by user, dest_ip
]
| where isnull(historical_connections)
| eval data_mb=round(current_bytes/1024/1024, 2)
| where data_mb > 100
| lookup geoip dest_ip OUTPUT Country, City
| eval severity=case(
    data_mb>5000, "CRITICAL",
    data_mb>1000, "HIGH",
    1==1, "MEDIUM"
)
| eval alert_reason="First-Time Destination + Large Transfer"
| table _time, user, dest_ip, Country, City, dest_port, data_mb, alert_reason, severity
```

**What This Detects:**
- User uploads 2GB to IP never contacted in past 90 days
- New cloud storage destinations
- Potential data staging servers

**Response Actions:**
1. Check destination reputation (VirusTotal, AbuseIPDB)
2. Verify if destination is legitimate business service
3. Review what files were transferred (if DLP/proxy logs available)
4. Contact user to confirm legitimacy

---

### Rule 4: Upload to Personal Cloud Storage Services

**Detection Logic:**  
Detect uploads to consumer file-sharing and cloud storage platforms.

**Splunk Query:**
```splunk
index=proxy sourcetype=proxy_logs method=POST
| regex url="(dropbox\.com|drive\.google\.com|onedrive\.live\.com|wetransfer\.com|mega\.nz|box\.com|icloud\.com|mediafire\.com|sendspace\.com|pastebin\.com|github\.com)"
| stats sum(bytes_sent) as upload_bytes,
        count as upload_requests,
        values(url) as cloud_services,
        values(user_agent) as user_agents
        by user, src_ip
| eval upload_mb=round(upload_bytes/1024/1024, 2)
| where upload_mb > 50
| eval severity=case(
    upload_mb>1000, "CRITICAL",
    upload_mb>500, "HIGH",
    1==1, "MEDIUM"
)
| eval attack_type="Personal Cloud Storage Upload"
| table _time, user, src_ip, upload_mb, upload_requests, cloud_services, attack_type, severity
```

**What This Detects:**
- Employees uploading company data to personal Dropbox
- GitHub repository uploads (potential code leaks)
- File sharing via WeTransfer or Mega
- Paste sites (pastebin) often used for quick data dumps

**Policy Enforcement:**
- Some organizations block these entirely
- Others allow but monitor for volume abuse
- DLP solutions can inspect content before upload

---

### Rule 5: Sensitive File Access Followed by External Transfer

**Detection Logic:**  
Correlate access to sensitive file shares with subsequent external network transfers.

**Splunk Query:**
```splunk
(index=windows EventCode=5145 ShareName="\\\\*\\Finance" OR ShareName="\\\\*\\HR" OR ShareName="\\\\*\\Executive")
| eval file_access_time=_time
| stats count as files_accessed, 
        values(RelativeTargetName) as files,
        min(_time) as access_start,
        max(_time) as access_end
        by user, src_ip
| join type=inner user, src_ip [
    search index=firewall sourcetype=firewall_traffic direction=outbound earliest=-1h
    | lookup internal_networks.csv dest_ip OUTPUT is_internal
    | where is_internal!="true"
    | stats sum(bytes_out) as exfil_bytes,
            values(dest_ip) as destinations,
            min(_time) as transfer_time
            by user, src_ip
]
| where transfer_time > access_end AND transfer_time < (access_end + 3600)
| eval exfil_mb=round(exfil_bytes/1024/1024, 2)
| eval time_gap_minutes=round((transfer_time - access_end)/60, 0)
| where exfil_mb > 10
| eval severity="CRITICAL"
| eval attack_type="Sensitive Data Access + Exfiltration"
| table _time, user, src_ip, files_accessed, exfil_mb, destinations, time_gap_minutes, attack_type, severity
```

**What This Detects:**
- User accesses Finance share, then uploads data externally within 1 hour
- Correlation between file access and network transfer
- Most reliable indicator of intentional data theft

**Key Indicators:**
- Short time gap (< 60 minutes) = likely related
- High file access count + large transfer = mass exfiltration
- Sensitive share names: Finance, HR, Executive, Legal, R&D

---

### Rule 6: DNS Tunneling Detection (Covert Exfiltration)

**Detection Logic:**  
Identify DNS queries used for data exfiltration through DNS tunneling.

**Splunk Query:**
```splunk
index=dns sourcetype=dns_logs
| eval query_length=len(query)
| where query_length > 50
| stats count as long_queries,
        avg(query_length) as avg_length,
        max(query_length) as max_length,
        dc(query) as unique_queries,
        values(query) as sample_queries
        by src_ip, user
| where long_queries > 100 OR avg_length > 60
| eval severity=case(
    long_queries>500, "CRITICAL",
    long_queries>200, "HIGH",
    1==1, "MEDIUM"
)
| eval attack_type="DNS Tunneling (Covert Exfiltration)"
| table _time, src_ip, user, long_queries, avg_length, max_length, unique_queries, attack_type, severity
```

**What This Detects:**
- Unusually long DNS queries (data encoded in subdomain)
- High frequency of DNS requests to same domain
- Common in malware C2 and stealth exfiltration

**Example of DNS Tunneling:**
```
Normal: www.example.com
Tunneling: 48f6a2b9c1d3e5f7a8b9c0d1e2f3a4b5.malicious.com
```

---

## Alert Context

This alert is generated when a user or endpoint sends an unusually large volume of data to an external destination compared to its normal behavior, especially when:

- Transfer occurs outside typical working hours (7 PM - 7 AM, weekends)  
- Data goes to previously unseen destination  
- Volume exceeds statistical baseline by 3+ standard deviations  
- Transfer to personal cloud storage services detected  
- Sensitive file access preceded the transfer  

---

## What I Check First When This Alert Fires

Before escalating, I usually answer these questions:

### 1. **Is this user expected to transfer large files?**
- Check user role (IT, DevOps, Marketing with video files = higher baseline)
- Review job function
- Look at historical transfer patterns

### 2. **Has this destination been contacted before?**
- New destination = higher risk
- Known business partner = likely legitimate
- Check destination reputation (threat intel feeds)

### 3. **Is there any recent phishing or malware alert for this user?**
- Recent phishing click?
- Endpoint detection alerts?
- Unusual login activity?
- Password reset requests?

### 4. **Is the activity part of a known business process?**
- Check with user's manager
- Review scheduled backup jobs
- Verify against change management tickets
- Ask user directly (if not suspected compromise)

**Only after answering these do I decide whether to escalate.**

---

## Investigation Playbook

### Phase 1: Initial Triage (5 minutes)

-  Check user's normal work hours and baseline data usage
-  Verify destination IP/domain reputation
-  Review timing (business hours vs after-hours)
-  Check for concurrent security alerts (phishing, malware, anomalous login)

### Phase 2: Data Analysis (10 minutes)

-  What was transferred? (if proxy/DLP logs available)
-  How much data? (compare to user baseline)
-  Duration of transfer? (quick burst vs sustained)
-  Protocol used? (HTTP, HTTPS, FTP, DNS tunneling)

### Phase 3: User Context (10 minutes)

-  Is user currently on vacation/leave?
-  Recent termination notice or resignation?
-  Access to sensitive data in job role?
-  Recent disciplinary actions or conflicts?
-  Check for insider threat indicators

### Phase 4: Escalation Decision

**Escalate to Tier 2 if:**
- Transfer to first-time destination >5GB
- After-hours transfer >1GB to external IP
- Sensitive file access + external transfer within 1 hour
- DNS tunneling pattern detected

**Escalate to Incident Response immediately if:**
- Evidence of account compromise
- Insider threat indicators present
- Ongoing exfiltration in progress
- Transfer of classified/highly sensitive data

---

## Response Actions

### Immediate Containment (If Confirmed Malicious)

1. **Block outbound connections** to identified destination IPs
2. **Suspend user account** if compromise suspected
3. **Isolate endpoint** from network if malware detected
4. **Preserve evidence** (firewall logs, proxy logs, endpoint forensics)

### Investigation

1. **Pull full network logs** for affected user (past 30 days)
2. **Review file access logs** for sensitive shares
3. **Check email** for data exfiltration via attachments
4. **Endpoint forensics** - check for staging directories, compressed archives
5. **Interview user** (if insider threat, coordinate with HR/Legal first)

### Remediation

1. **Identify what data was exfiltrated** (DLP logs, file listings)
2. **Assess impact** (PII count, financial data, trade secrets)
3. **Notify stakeholders** (Legal, Privacy, Compliance, Management)
4. **Consider breach notification** requirements (GDPR, CCPA, state laws)
5. **Implement additional controls** (DLP, USB blocking, cloud access restrictions)

---

## Sample Scenarios

### Scenario 1: Legitimate Backup (False Positive)
```
Alert: User transferred 50GB to external IP
Investigation:
- Destination: Company's backup service provider IP
- Timing: 2 AM (scheduled backup window)
- User: backup_service account
- Historical: Daily backups for past 6 months

Verdict: FALSE POSITIVE - Whitelist this backup job
```

### Scenario 2: Insider Threat (True Positive)
```
Alert: User transferred 15GB to Dropbox after hours
Investigation:
- User: Sales manager with 2-week notice submitted
- Timing: 11 PM on Friday
- Files accessed: Customer database, pricing spreadsheets
- Destination: Personal Dropbox account
- No legitimate business justification

Verdict: TRUE POSITIVE - Insider threat, data theft
Actions: Account suspended, HR/Legal notified, forensics initiated
```

### Scenario 3: Malware Exfiltration (True Positive)
```
Alert: Workstation sent 5GB via DNS tunneling
Investigation:
- User: Accounting clerk, clicked phishing link 2 hours prior
- Pattern: 10,000+ DNS queries to suspicious domain
- Endpoint: Malware detected (data stealer)
- Files: Tax documents, employee PII

Verdict: TRUE POSITIVE - Malware-based exfiltration
Actions: Endpoint isolated, malware removed, breach assessment
```

---

## Why This Detection Matters

Data exfiltration is the **ultimate goal** of most cyber attacks.

Early detection prevents:
-  Intellectual property theft
-  Customer data breaches
-  Regulatory fines (GDPR: up to €20M or 4% revenue)
-  Insider threats and espionage
-  Competitive disadvantage
-  Reputational damage

**Real-World Statistics:**
- 68% of breaches involve insider or privilege misuse (Verizon DBIR)
- Average time to detect data exfiltration: 277 days (IBM)
- Average cost per stolen record: $165 (IBM 2023)

**Behavioral detection catches exfiltration that signature-based tools miss.**

---

## References

- **MITRE ATT&CK**: https://attack.mitre.org/tactics/TA0010/
- **NIST Data Breach Response**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- **Splunk Security Essentials**: https://splunkbase.splunk.com/app/3435/
- **SANS Insider Threat Detection**: https://www.sans.org/white-papers/insider-threat-detection/

---

*Detection rules tested against real-world exfiltration scenarios including insider threats, malware, and cloud storage abuse.*
