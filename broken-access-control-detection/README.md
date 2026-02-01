# Broken Access Control Abuse Detection (IDOR & Authorization Bypass)

## What This Project Is About

This project focuses on detecting **real-world Broken Access Control (BAC) abuse**, not theory.
The goal is to identify users who access **resources they should never be allowed to see or modify**, even though they are technically authenticated.

This includes:
- IDOR exploitation
- Role and privilege abuse
- Force browsing to restricted endpoints
- Unauthorized API actions

---

## How BAC Attacks Actually Look in Logs

Attackers usually don’t exploit BAC in one request.
They **test boundaries**.

Common patterns:
- User accesses `/api/orders/1234`, then tries `/api/orders/1235`, `/1236`, `/1237`
- Normal user calling admin-only endpoints (`/admin`, `/manage`, `/export`)
- User performing actions outside their role (delete, update, approve)
- Accessing other users’ data using modified IDs

Individually, these requests may look valid.  
**Together, they reveal abuse.**

---

## How I Detect Broken Access Control

I don’t look for payloads — I look for **behavior**.

### Detection Signals:
- Same user accessing **multiple object IDs** they don’t own
- Sequential or predictable ID access (classic IDOR)
- Requests to **privileged endpoints** by low-privileged roles
- API methods used incorrectly (PUT/DELETE by normal users)
- Sudden access to high-value resources (PII, finance, admin data)

---

## Example Detection Scenario

A normal user account:
- Successfully logs in
- Accesses their own data (normal)
- Then starts requesting **other users’ records** by changing object IDs
- Volume increases in a short time window

This triggers a **Broken Access Control Abuse alert**.

---

## SOC Investigation Flow

1. Confirm user role and expected access
2. Check ownership of accessed objects
3. Look for sequential or bulk access patterns
4. Identify sensitive data exposure
5. Escalate to AppSec if confirmed

---

## Why This Detection Matters

Broken Access Control is **one of the most exploited web vulnerabilities**.
Detecting it early prevents:
- Mass data exposure
- Privilege escalation
- Business logic abuse
- Compliance violations

This detection is **high-signal and low-noise** when behavior-based.

