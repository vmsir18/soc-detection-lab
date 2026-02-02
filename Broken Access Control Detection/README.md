# Broken Access Control Abuse Detection (IDOR & Authorization Bypass)

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|--------------|----------------|--------|
| **T1565.001** | Data Manipulation: Stored Data Manipulation | Impact |
| **T1190** | Exploit Public-Facing Application | Initial Access |
| **T1068** | Exploitation for Privilege Escalation | Privilege Escalation |
| **T1087** | Account Discovery | Discovery |

**Why These Techniques:**
- **T1565.001**: Broken Access Control allows unauthorized modification of data belonging to other users
- **T1190**: IDOR and authorization flaws are exploitation of web application logic vulnerabilities
- **T1068**: Authorization bypass can lead to unauthorized privilege escalation
- **T1087**: Attackers enumerate valid accounts and permissions through BAC exploitation

**Detection Coverage:**
-  Detects unauthorized data access across user boundaries
-  Identifies privilege escalation through role/permission bypass
-  Catches bulk data enumeration and harvesting
-  Monitors suspicious endpoint access patterns
-  Does NOT detect: Client-side access control bypasses (not visible in server logs)

---

## What This Project Is About

This project focuses on detecting **real-world Broken Access Control (BAC) abuse**, not theory.

The goal is to identify users who access **resources they should never be allowed to see or modify**, even though they are technically authenticated.

This includes:
- **IDOR exploitation** - Accessing data by manipulating object IDs
- **Role and privilege abuse** - Users performing actions outside their assigned permissions
- **Force browsing to restricted endpoints** - Accessing admin/privileged URLs
- **Unauthorized API actions** - Using HTTP methods or endpoints they shouldn't access

---

## How BAC Attacks Actually Look in Logs

Attackers usually don't exploit BAC in one request. They **test boundaries**.

Common patterns:
- User accesses `/api/orders/1234`, then tries `/api/orders/1235`, `/1236`, `/1237`
- Normal user calling admin-only endpoints (`/admin`, `/manage`, `/export`)
- User performing actions outside their role (delete, update, approve)
- Accessing other users' data using modified IDs

Individually, these requests may look valid.  
**Together, they reveal abuse.**

---

## How I Detect Broken Access Control

I don't look for payloads — I look for **behavior**.

### Detection Signals:
- Same user accessing **multiple object IDs** they don't own
- Sequential or predictable ID access (classic IDOR)
- Requests to **privileged endpoints** by low-privileged roles
- API methods used incorrectly (PUT/DELETE by normal users)
- Sudden access to high-value resources (PII, finance, admin data)

---

## Detection Rules

### Rule 1: Sequential Object ID Enumeration (IDOR)

**Detection Logic:**  
Identify when a single user accesses multiple sequential object IDs in a short time window, indicating IDOR enumeration.

**Splunk Query:**
```splunk
index=webapp sourcetype=api_logs
| rex field=uri "/api/(?<endpoint>\w+)/(?<object_id>\d+)"
| where isnotnull(object_id)
| sort 0 _time user object_id
| streamstats current=f last(object_id) as prev_id by user, endpoint
| eval id_diff=tonumber(object_id) - tonumber(prev_id)
| where id_diff >= 1 AND id_diff <= 10
| stats count as sequential_access, 
        min(object_id) as first_id, 
        max(object_id) as last_id, 
        values(object_id) as accessed_ids 
        by user, src_ip, endpoint
| where sequential_access > 5
| eval severity="HIGH"
| eval attack_type="IDOR - Sequential Enumeration"
| table _time, user, src_ip, endpoint, sequential_access, first_id, last_id, attack_type, severity
```

**What This Detects:**
- User accessing object IDs 1234, 1235, 1236, 1237, 1238 in sequence
- Classic IDOR enumeration pattern
- Threshold: 5+ sequential accesses within search window

**Tuning Considerations:**
- Adjust `id_diff` threshold based on your ID spacing
- Whitelist admin users and automated reporting systems
- Consider time window (use `earliest=-1h` for hourly checks)

**False Positive Scenarios:**
- Admin bulk operations and data exports
- Automated reporting systems iterating through records
- Legitimate data migration or backup tools
- Customer service tools accessing multiple accounts

**Remediation:**
- Verify user should have access to these objects
- Check if accessed data belongs to other users
- Block user account if confirmed abuse
- Force session logout and password reset

---

### Rule 2: Unauthorized Access to Privileged Endpoints

**Detection Logic:**  
Detect when normal users attempt to access admin-only or privileged endpoints.

**Splunk Query:**
```splunk
index=webapp sourcetype=api_logs
| lookup user_roles.csv user OUTPUT role
| where role!="admin" AND role!="superuser" 
| regex uri="/(admin|manage|export|config|system|internal|debug)/"
| stats count as unauthorized_attempts, 
        values(uri) as endpoints_accessed, 
        values(http_status) as status_codes 
        by user, role, src_ip
| where unauthorized_attempts > 2
| eval severity=if(unauthorized_attempts>10,"CRITICAL","HIGH")
| eval attack_type="Privilege Escalation - Endpoint Access"
| table _time, user, role, src_ip, unauthorized_attempts, endpoints_accessed, status_codes, attack_type, severity
```

**What This Detects:**
- Standard users trying to access `/admin/*` paths
- Role violations and privilege boundary testing
- Force browsing to restricted resources
- Privilege escalation attempts

**Tuning Considerations:**
- Customize endpoint regex based on your application structure
- Create lookup table `user_roles.csv` mapping users to roles
- Adjust threshold based on environment (2-5 attempts)

**False Positive Scenarios:**
- Users clicking on accidentally exposed admin links
- Mobile apps or browser extensions making unexpected requests
- Legitimate role changes not yet reflected in lookup table

**Response Actions:**
1. Verify user's actual role and permissions
2. Check if endpoints returned data (200 OK) or blocked (403 Forbidden)
3. Review recent role changes or privilege grants
4. If 200 OK responses → CRITICAL (successful bypass, escalate immediately)
5. If 403 responses → Monitor for continued attempts

---

### Rule 3: Bulk Access to Other Users' Resources

**Detection Logic:**  
Identify users accessing resources belonging to many different user accounts.

**Splunk Query:**
```splunk
index=webapp sourcetype=api_logs
| rex field=uri "user_id=(?<target_user>\w+)"
| rex field=uri "account_id=(?<target_account>\w+)"
| eval target=coalesce(target_user, target_account)
| where isnotnull(target) AND user!=target
| stats dc(target) as unique_users_accessed, 
        count as total_accesses,
        values(target) as users_accessed,
        values(uri) as endpoints
        by user, src_ip
| where unique_users_accessed > 10 AND total_accesses > 20
| eval severity="CRITICAL"
| eval attack_type="IDOR - Bulk Data Harvesting"
| table _time, user, src_ip, unique_users_accessed, total_accesses, attack_type, severity
```

**What This Detects:**
- User "alice" accessing data for bob, charlie, david, eve, frank (10+ different users)
- Mass data harvesting through IDOR
- Successful exploitation leading to bulk exposure
- Data scraping for competitive intelligence or resale

**Tuning Considerations:**
- Threshold of 10 unique users can be adjusted (5-20 depending on application)
- Whitelist customer service accounts with legitimate access
- Consider user role (support staff may access multiple accounts legitimately)

**Investigation Steps:**
1. Confirm user's job function - should they access multiple accounts?
2. Check if accessed accounts are related (family members, business accounts)
3. Verify if data was only viewed or also modified/exported
4. Look for data exfiltration attempts (downloads, API exports)
5. Check for recent vulnerability reports or security advisories

---

### Rule 4: Unauthorized HTTP Methods on Resources

**Detection Logic:**  
Detect users performing destructive or modifying operations (DELETE/PUT/PATCH) on resources they shouldn't control.

**Splunk Query:**
```splunk
index=webapp sourcetype=api_logs method IN ("DELETE", "PUT", "PATCH", "POST")
| rex field=uri "/api/(?<resource_type>\w+)/(?<resource_id>\w+)"
| lookup user_permissions.csv user, resource_type OUTPUT allowed_methods
| eval is_allowed=if(match(allowed_methods, method), "yes", "no")
| where is_allowed="no"
| stats count as unauthorized_modifications, 
        values(method) as methods_used, 
        values(uri) as resources_targeted,
        values(http_status) as responses
        by user, src_ip, resource_type
| where unauthorized_modifications > 3
| eval severity=if(match(methods_used, "DELETE"),"CRITICAL","HIGH")
| eval attack_type="Authorization Bypass - Unauthorized Modification"
| table _time, user, src_ip, resource_type, unauthorized_modifications, methods_used, resources_targeted, responses, attack_type, severity
```

**What This Detects:**
- Read-only users performing DELETE operations
- Standard users modifying admin-controlled resources
- Users deleting data they don't own
- Authorization bypass through HTTP method manipulation

**Tuning Considerations:**
- Create `user_permissions.csv` lookup defining allowed methods per role
- Track HTTP response codes (200/204 = successful bypass, 403 = blocked)
- Focus on destructive methods (DELETE) as higher severity

**Response Actions:**
- If 200/204 responses → Data was modified/deleted (CRITICAL incident)
- Review audit logs for what data was changed
- Restore deleted data from backups if applicable
- Disable user account immediately if confirmed malicious

---

### Rule 5: Cross-User Data Access Pattern

**Detection Logic:**  
Identify when a user accesses their own data normally, then suddenly switches to accessing other users' data.

**Splunk Query:**
```splunk
index=webapp sourcetype=api_logs
| rex field=uri "user_id=(?<target_user>\w+)"
| where isnotnull(target_user)
| eval is_self_access=if(user==target_user, 1, 0)
| stats sum(is_self_access) as self_access_count,
        sum(eval(if(is_self_access==0,1,0))) as other_access_count,
        dc(target_user) as unique_targets,
        values(target_user) as targets
        by user, src_ip
| where other_access_count > 5 AND unique_targets > 3
| eval access_ratio=round(other_access_count/(self_access_count+other_access_count)*100, 2)
| where access_ratio > 50
| eval severity="HIGH"
| eval attack_type="IDOR - Cross-User Access"
| table _time, user, src_ip, self_access_count, other_access_count, unique_targets, access_ratio, attack_type, severity
```

**What This Detects:**
- Users who normally access only their data suddenly accessing others'
- Shift in behavior indicating exploitation
- Account compromise or malicious insider

**Key Metric:**
- `access_ratio` > 50% = More than half of accesses are to other users' data

---

## Example Detection Scenario

**Timeline of Attack:**
```
10:45 AM - User "john.doe" logs in successfully
10:46 AM - Accesses own order: /api/orders/5432 (normal)
10:47 AM - Accesses own profile: /api/users/john.doe (normal)
10:48 AM - Tests IDOR: /api/orders/5433 (belongs to another user)
10:48 AM - Returns 200 OK with data (vulnerability confirmed)
10:49 AM - Enumeration begins: /api/orders/5434, 5435, 5436, 5437...
10:50 AM - Accessed 15 different orders in 2 minutes
10:51 AM - Attempts admin endpoint: /admin/export
```

**Alert Triggered:**  
"Broken Access Control Abuse - IDOR Sequential Enumeration"

**SOC Investigation Flow:**

1. ✅ **Confirm user role and expected access**
   - User: john.doe
   - Role: Standard Customer
   - Should only access own orders (order 5432)

2. ✅ **Check ownership of accessed objects**
   - Orders 5433-5447 belong to different customers
   - Unauthorized cross-user data access confirmed

3. ✅ **Look for sequential or bulk access patterns**
   - 15 sequential order IDs accessed in 2 minutes
   - Classic IDOR enumeration pattern

4. ✅ **Identify sensitive data exposure**
   - Order data contains: customer names, addresses, purchase history
   - PII exposure confirmed

5. ✅ **Escalate to AppSec**
   - Severity: HIGH (data exposure, no modification detected)
   - Immediate: Block user account
   - Short-term: Fix IDOR vulnerability in /api/orders endpoint
   - Long-term: Implement proper authorization checks

---

## SOC Investigation Checklist

When this alert fires, investigate in this order:

**Phase 1: Triage (5 minutes)**
- [ ] Check user's assigned role
- [ ] Verify if user should have access to these resources
- [ ] Review HTTP response codes (200 = successful access, 403 = blocked)
- [ ] Check for similar alerts for this user in past 7 days

**Phase 2: Scope Assessment (10 minutes)**
- [ ] How many unique objects/users were accessed?
- [ ] What type of data was exposed (PII, financial, admin)?
- [ ] Were any modifications made (PUT/DELETE/PATCH requests)?
- [ ] Check for data exfiltration (downloads, exports, API calls)

**Phase 3: User Context (10 minutes)**
- [ ] Is this a known user or potential compromised account?
- [ ] Any recent phishing alerts for this user?
- [ ] Check for concurrent sessions from multiple IPs
- [ ] Review recent password changes or MFA modifications

**Phase 4: Escalation Decision**
- **Escalate to Tier 2 if:**
  - Data was modified or deleted
  - PII or financial data exposed
  - Admin endpoints accessed successfully
  - 50+ objects accessed
- **Escalate to AppSec immediately if:**
  - Ongoing exploitation detected
  - Vulnerability not yet patched
  - Mass data harvesting in progress

---

## Why This Detection Matters

Broken Access Control is **#1 on OWASP Top 10 2021** and one of the most exploited web vulnerabilities.

Detecting it early prevents:
- ✅ Mass data exposure and privacy violations
- ✅ Privilege escalation and unauthorized admin access
- ✅ Business logic abuse and fraud
- ✅ Compliance violations (GDPR, HIPAA, PCI-DSS)
- ✅ Reputational damage from data breaches

**Real-World Impact:**
- Average cost of data breach: $4.45M (IBM 2023)
- 94% of organizations experienced BAC incidents (Verizon DBIR)
- IDOR vulnerabilities present in 71% of web applications tested

This detection is **high-signal and low-noise** when behavior-based thresholds are properly tuned to your environment.

---

## Sample Log Entries

**Normal Behavior:**
```
2026-02-01 10:45:23 user=john.doe src_ip=192.168.1.100 uri=/api/orders/5432 method=GET status=200
2026-02-01 10:46:15 user=john.doe src_ip=192.168.1.100 uri=/api/users/john.doe method=GET status=200
```

**IDOR Attack Pattern:**
```
2026-02-01 10:48:10 user=john.doe src_ip=192.168.1.100 uri=/api/orders/5433 method=GET status=200
2026-02-01 10:48:12 user=john.doe src_ip=192.168.1.100 uri=/api/orders/5434 method=GET status=200
2026-02-01 10:48:14 user=john.doe src_ip=192.168.1.100 uri=/api/orders/5435 method=GET status=200
2026-02-01 10:48:16 user=john.doe src_ip=192.168.1.100 uri=/api/orders/5436 method=GET status=200
[15 more sequential requests in 2 minutes...]
```

**Privilege Escalation Attempt:**
```
2026-02-01 10:51:05 user=john.doe src_ip=192.168.1.100 uri=/admin/export method=GET status=403
2026-02-01 10:51:10 user=john.doe src_ip=192.168.1.100 uri=/admin/users method=GET status=403
2026-02-01 10:51:15 user=john.doe src_ip=192.168.1.100 uri=/manage/settings method=GET status=403
```

---

## References

- **MITRE ATT&CK**: https://attack.mitre.org/techniques/T1190/
- **OWASP Top 10 2021 - A01**: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- **OWASP IDOR Guide**: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- **Splunk SPL Documentation**: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/

---

*Detection rules tested against real-world IDOR patterns from bug bounty research and SOC operations.*
