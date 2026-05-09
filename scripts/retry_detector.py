#!/usr/bin/env python3
"""
retry_detector.py — Retry Detector (Hook: agent-retry-detector.py)

Analyses specialist-agent conclusions for *premature surrender* patterns.
When a specialist gives up too early (e.g. "blocked by WAF", "seems secure"),
the detector flags the conclusion, suggests bypass strategies based on the
vulnerability class and defence mechanism encountered, and generates a
structured retry prompt for the coordinator to re-deploy the agent.

Usage:
    python retry_detector.py
    python -m mastermind_bug_bounty.scripts.retry_detector
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Surrender pattern database
# ---------------------------------------------------------------------------

SURRENDER_PATTERNS: list[dict] = [
    # --- WAF / CDN defence ---
    {"pattern": r"waf\s+detected", "category": "waf", "severity": "high"},
    {"pattern": r"blocked\s+by\s+(?:the\s+)?waf", "category": "waf", "severity": "high"},
    {"pattern": r"protected\s+by\s+(?:a\s+)?waf", "category": "waf", "severity": "high"},
    {"pattern": r"cloudflare", "category": "cdn", "severity": "medium"},
    {"pattern": r"akamai", "category": "cdn", "severity": "medium"},
    {"pattern": r"imperva", "category": "cdn", "severity": "medium"},
    {"pattern": r"incapsula", "category": "cdn", "severity": "medium"},
    {"pattern": r"sucuri", "category": "cdn", "severity": "medium"},
    {"pattern": r"fastly", "category": "cdn", "severity": "low"},
    # --- Negative assertions ---
    {"pattern": r"no\s+vulnerability\s+found", "category": "negative_assertion", "severity": "high"},
    {"pattern": r"appears?\s+(?:to\s+be\s+)?secure", "category": "negative_assertion", "severity": "high"},
    {"pattern": r"seems\s+(?:to\s+be\s+)?safe", "category": "negative_assertion", "severity": "high"},
    {"pattern": r"nothing\s+(?:interesting|suspicious)\s+found", "category": "negative_assertion", "severity": "high"},
    {"pattern": r"(?:not\s+vulnerable|non-vulnerable)", "category": "negative_assertion", "severity": "high"},
    # --- Access control blocks ---
    {"pattern": r"403\s+forbidden", "category": "access_control", "severity": "medium"},
    {"pattern": r"401\s+unauthorized", "category": "access_control", "severity": "medium"},
    {"pattern": r"access\s+denied", "category": "access_control", "severity": "medium"},
    {"pattern": r"forbidden", "category": "access_control", "severity": "low"},
    # --- Explicit surrender ---
    {"pattern": r"gave\s+up", "category": "surrender", "severity": "critical"},
    {"pattern": r"unable\s+to\s+(?:bypass|exploit|proceed|continue)", "category": "surrender", "severity": "critical"},
    {"pattern": r"could\s+not\s+(?:bypass|exploit|find|identify)", "category": "surrender", "severity": "critical"},
    {"pattern": r"(?:stopped|halted)\s+(?:testing|scanning)", "category": "surrender", "severity": "critical"},
    {"pattern": r"(?:protection|defence)\s+detected", "category": "surrender", "severity": "high"},
    # --- Rate-limit / blocking ---
    {"pattern": r"rate[-\s]?limit(?:ed|ing)", "category": "rate_limit", "severity": "medium"},
    {"pattern": r"too\s+many\s+requests", "category": "rate_limit", "severity": "medium"},
    {"pattern": r"blocked", "category": "generic_block", "severity": "low"},
]


# ---------------------------------------------------------------------------
# Bypass strategy database
# ---------------------------------------------------------------------------

BYPASS_TECHNIQUES: dict[str, dict[str, list[str]]] = {
    "sql_injection": {
        "waf": [
            "Use COMMENT obfuscation: /*!50000SELECT*/ instead of SELECT",
            "Apply case-randomisation: SeLeCt, UnIoN",
            "Encode payloads with Unicode normalisation: %C0%A0 for spaces",
            "Use stacked queries with time-delay: '; WAITFOR DELAY '0:0:5'--",
            "Try HTTP parameter pollution: id=1&id=UNION SELECT *",
            "Switch to JSON/content-type bypass: Content-Type: application/json",
            "Employ tamper scripts: space2comment, charencode, randomcase",
        ],
        "cdn": [
            "Target origin IP directly (bypass CDN) — resolve via Shodan/Censys",
            "Use old DNS history (SecurityTrails) to find unprotected origin",
            "Test via IPv6 if CDN only covers IPv4",
        ],
        "access_control": [
            "Try alternative HTTP methods: POST, PUT, PATCH instead of GET",
            "Add override headers: X-HTTP-Method-Override, X-Original-URL",
            "Use path traversal variants: ./admin, admin../, %2e%2e%2f",
            "Test with different Content-Type headers to bypass route guards",
        ],
        "rate_limit": [
            "Rotate source IP via proxy pool (Burp Collaborator, socks5)",
            "Use delay jitter: random sleeps between 2–7 seconds",
            "Distribute across multiple agent instances with staggered starts",
        ],
        "generic_block": [
            "Change User-Agent to Googlebot or custom benign string",
            "Add forwarded-for headers: X-Forwarded-For: 127.0.0.1",
            "Use HTTP/1.0 or HTTP/2 protocol switching",
            "Try alternate paths that reach the same endpoint",
        ],
    },
    "xss": {
        "waf": [
            "Use polyglot payloads: jaVasCript:/*-/*\u0060/*\u0060/*'/*\u0022/**/(/* */oNcliCk=alert() )",
            "Apply HTML entity encoding: &#x3C;script&#x3E;",
            "Use JavaScript template literals: ${alert(1)}",
            "Try SVG-based vectors: <svg onload=alert(1)>",
            "Use event handlers: onpointerenter, ontoggle, onfocus",
            "Bypass via MIME sniffing: Content-Type: text/plain with XSS payload",
        ],
        "cdn": [
            "Check if CDN caches static JS — inject into cached resource",
            "Test on dev/staging subdomain not behind CDN",
        ],
        "access_control": [
            "Try parameter reflection in error pages (often unfiltered)",
            "Use open redirect as XSS vector: /redirect?url=javascript:alert(1)",
        ],
        "rate_limit": [
            "Batch payload tests with single request using multiple parameters",
            "Use cache-poisoning to persist XSS without repeated requests",
        ],
        "generic_block": [
            "Try non-script vectors: <img src=x onerror=alert(1)>",
            "Use data URIs: data:text/html,<script>alert(1)</script>",
        ],
    },
    "ssrf": {
        "waf": [
            "Use DNS rebinding: alternate A records between 127.0.0.1 and benign",
            "Apply URL encoding: %32%31%37%2e%30%2e%30%2e%31",
            "Use IPv6 localhost: [::1], [::ffff:127.0.0.1]",
            "Try protocol smuggling: gopher://, dict://, file://",
            "Bypass via 302 redirect from externally controlled server",
        ],
        "cdn": [
            "Access origin management interfaces on port 8080/8443",
            "Use CDN edge server as SSRF trampoline",
        ],
        "access_control": [
            "Try DNS-based exfil even if HTTP is blocked",
            "Use IDN homograph attacks for whitelist bypass",
        ],
        "generic_block": [
            "Test with decimal IP: http://2130706433/ (127.0.0.1)",
            "Use octal IP: http://0177.0.0.01/",
        ],
    },
    "lfi": {
        "waf": [
            "Double encoding: %252fetc%252fpasswd",
            "Unicode traversal: ..%c0%af..%c0%afetc/passwd",
            "Null-byte truncation (PHP < 5.3.4): /etc/passwd%00.jpg",
        ],
        "access_control": [
            "Try PHP wrappers: php://filter/convert.base64-encode/resource=/etc/passwd",
            "Use data:// wrapper: data://text/plain,<?php system('id'); ?>",
        ],
        "generic_block": [
            "Test for path truncation: ./././././etc/passwd",
            "Try absolute paths with different prefixes: C:\\windows\\win.ini",
        ],
    },
    "rce": {
        "waf": [
            "Use command substitution: $(command) or `command`",
            "Apply concatenation: c'a't /e't'c/pa's's'wd",
            "Use wildcards: /???/??t /???/p??s??",
            "Try backticks in unexpected contexts",
        ],
        "access_control": [
            "Upload web shell with double extension: shell.jpg.php",
            "Use XXE or SSTI as stepping stone to RCE",
        ],
        "generic_block": [
            "Test for deserialization chains leading to RCE",
            "Try template injection: {{7*7}} → 49 indicates SSTI/RCE path",
        ],
    },
    "idor": {
        "waf": [
            "Rarely blocked by WAF; focus on UUID prediction or reference manipulation",
        ],
        "access_control": [
            "Try GUID/UUID manipulation: sequential UUIDs often exposed",
            "Test with other users' JWT tokens if horizontal escalation suspected",
            "Use bulk ID enumeration: /api/users?id[]=1&id[]=2&id[]=3",
        ],
        "generic_block": [
            "Replace numeric IDs with email/usernames if API supports it",
            "Test GraphQL queries for over-fetching of other users' data",
        ],
    },
    "default": {
        "waf": [
            "Change User-Agent to mimic legitimate browser",
            "Use HTTP/1.0 and remove unusual headers",
            "Add X-Forwarded-For: 127.0.0.1 to appear internal",
            "Try Content-Type switching: application/x-www-form-urlencoded vs JSON",
        ],
        "cdn": [
            "Discover origin IP via Shodan / Censys / DNS history",
            "Test IPv6 endpoints if CDN only protects IPv4",
            "Use old SSL certificate transparency logs to find origin",
        ],
        "access_control": [
            "Try alternative HTTP verbs: POST, PUT, PATCH, OPTIONS",
            "Use method override headers: X-HTTP-Method-Override",
            "Access via API gateway if web UI is restricted",
        ],
        "rate_limit": [
            "Implement exponential backoff with jitter",
            "Rotate exit nodes via proxy mesh",
            "Distribute requests across multiple sessions",
        ],
        "generic_block": [
            "Test at different times of day (maintenance windows may relax controls)",
            "Try mobile app API endpoints (often less protected than web)",
            "Check for debug/staging endpoints: /debug, /test, /staging",
            "Use case variation and Unicode normalisation in paths",
        ],
    },
}


def _normalise_class(finding_class: str) -> str:
    """Map free-text class labels to canonical keys."""
    class_lower: str = finding_class.lower().strip()
    mapping: dict[str, str] = {
        "sql injection": "sql_injection",
        "sqli": "sql_injection",
        "sql_injection": "sql_injection",
        "xss": "xss",
        "cross-site scripting": "xss",
        "reflected xss": "xss",
        "stored xss": "xss",
        "dom xss": "xss",
        "ssrf": "ssrf",
        "server-side request forgery": "ssrf",
        "lfi": "lfi",
        "local file inclusion": "lfi",
        "path traversal": "lfi",
        "rce": "rce",
        "remote code execution": "rce",
        "command injection": "rce",
        "idor": "idor",
        "insecure direct object reference": "idor",
    }
    return mapping.get(class_lower, "default")


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def detect_premature_surrender(conclusion: str) -> dict:
    """Pattern-match a specialist-agent conclusion against surrender phrases.

    Args:
        conclusion: Free-text conclusion from the agent.

    Returns:
        A dict::

            {
                "surrender_detected": bool,
                "matched_patterns": list[dict],
                "primary_category": str,
                "max_severity": str,
            }
    """
    text_lower: str = conclusion.lower()
    matched: list[dict] = []

    for entry in SURRENDER_PATTERNS:
        regex: re.Pattern = re.compile(entry["pattern"], re.IGNORECASE)
        if regex.search(text_lower):
            matched.append({
                "pattern": entry["pattern"],
                "category": entry["category"],
                "severity": entry["severity"],
            })

    surrender_detected: bool = len(matched) > 0

    # Determine primary category and max severity
    primary_category: str = ""
    max_severity: str = ""
    severity_rank: dict[str, int] = {
        "critical": 4, "high": 3, "medium": 2, "low": 1,
    }
    if matched:
        categories: dict[str, int] = {}
        for m in matched:
            cat: str = m["category"]
            categories[cat] = categories.get(cat, 0) + 1
            sev_rank: int = severity_rank.get(m["severity"], 0)
            if sev_rank > severity_rank.get(max_severity, 0):
                max_severity = m["severity"]
        primary_category = max(categories, key=categories.get)

    return {
        "surrender_detected": surrender_detected,
        "matched_patterns": matched,
        "primary_category": primary_category,
        "max_severity": max_severity,
    }


# ---------------------------------------------------------------------------
# Bypass suggestion engine
# ---------------------------------------------------------------------------

def generate_bypass_suggestions(
    finding_class: str,
    defense_type: str,
) -> list[str]:
    """Return bypass strategies based on vulnerability class and defence.

    Args:
        finding_class: The vulnerability class being tested.
        defense_type: The defence mechanism detected
                      (e.g. ``waf``, ``cdn``, ``access_control``).

    Returns:
        A list of actionable bypass suggestion strings.
    """
    canonical_class: str = _normalise_class(finding_class)
    class_strategies: dict[str, list[str]] = BYPASS_TECHNIQUES.get(
        canonical_class, BYPASS_TECHNIQUES["default"]
    )

    # Try defence-specific, fall back to generic_block, then default
    suggestions: list[str] = class_strategies.get(defense_type, [])
    if not suggestions:
        suggestions = class_strategies.get("generic_block", [])
    if not suggestions:
        suggestions = BYPASS_TECHNIQUES["default"].get(defense_type, [])
    if not suggestions:
        suggestions = BYPASS_TECHNIQUES["default"]["generic_block"]

    return suggestions


# ---------------------------------------------------------------------------
# Retry prompt builder
# ---------------------------------------------------------------------------

def create_retry_prompt(
    original_task: str,
    conclusion: str,
    suggestions: list[str],
) -> str:
    """Format a retry prompt for the agent that surrendered prematurely.

    Args:
        original_task: The task originally assigned to the agent.
        conclusion: The agent's premature conclusion.
        suggestions: List of bypass suggestions from :func:`generate_bypass_suggestions`.

    Returns:
        A markdown-formatted prompt string ready to send to the agent.
    """
    now: str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    prompt_lines: list[str] = [
        "# RETRY: Premature Surrender Detected",
        "",
        f"**Detection time**: {now}",
        "",
        "## Original Task",
        f"> {original_task}",
        "",
        "## Agent Conclusion (FLAGGED)",
        f"> {conclusion}",
        "",
        "> **WARNING**: This conclusion contains premature surrender language. "
        "The hunt must continue. Detection alone is never sufficient — "
        "impact must be demonstrated.",
        "",
        "## Bypass Strategies to Attempt",
    ]

    for idx, suggestion in enumerate(suggestions, 1):
        prompt_lines.append(f"{idx}. {suggestion}")

    prompt_lines.extend([
        "",
        "## Retry Instructions",
        "1. Select the most promising bypass strategy from the list above.",
        "2. Apply it systematically with documented HTTP requests/responses.",
        "3. If one fails, move to the next — do not stop after a single attempt.",
        "4. Report *impact* not just detection. Show what data or access "
        "was obtained.",
        "5. If ALL strategies fail, document exactly *why* each failed "
        "with request/response evidence.",
        "",
        "**You are not done until impact is demonstrated or every strategy "
        "is exhaustively attempted with proof.**",
        "",
    ])

    return "\n".join(prompt_lines)


# ---------------------------------------------------------------------------
# Main entry-point
# ---------------------------------------------------------------------------

def retry_detector(
    agent_id: str,
    conclusion: str,
    finding_class: str = "",
) -> dict:
    """Analyse a specialist-agent conclusion for premature surrender.

    Args:
        agent_id: ID of the agent whose conclusion is being analysed.
        conclusion: The agent's conclusion text.
        finding_class: The vulnerability class the agent was testing.

    Returns:
        A dict::

            {
                "surrender_detected": bool,
                "matched_patterns": list[dict],
                "primary_category": str,
                "max_severity": str,
                "bypass_suggestions": list[str],
                "retry_prompt": str,
                "should_retry": bool,
            }
    """
    detection: dict = detect_premature_surrender(conclusion)

    bypass_suggestions: list[str] = []
    retry_prompt: str = ""
    should_retry: bool = False

    if detection["surrender_detected"]:
        defense_type: str = detection["primary_category"]
        bypass_suggestions = generate_bypass_suggestions(
            finding_class or "unknown",
            defense_type,
        )
        should_retry = True

        # Build a synthetic original_task for the retry prompt
        original_task: str = (
            f"Test target for {finding_class} vulnerabilities"
            if finding_class
            else "Execute assigned security test"
        )
        retry_prompt = create_retry_prompt(original_task, conclusion, bypass_suggestions)

    return {
        "surrender_detected": detection["surrender_detected"],
        "matched_patterns": detection["matched_patterns"],
        "primary_category": detection["primary_category"],
        "max_severity": detection["max_severity"],
        "bypass_suggestions": bypass_suggestions,
        "retry_prompt": retry_prompt,
        "should_retry": should_retry,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    """Run demo scenarios against the retry detector."""
    print("=== Retry Detector Demo ===\n")

    scenarios: list[dict] = [
        {
            "agent_id": "sqli_specialist_1",
            "finding_class": "sql_injection",
            "conclusion": (
                "The target appears to be protected by a WAF (Cloudflare). "
                "All SQL injection payloads were blocked. No vulnerability found. "
                "The application seems secure against SQL injection attacks."
            ),
        },
        {
            "agent_id": "xss_specialist_2",
            "finding_class": "xss",
            "conclusion": (
                "Found reflected XSS in the search parameter. "
                "<script>alert(document.cookie)</script> executes successfully. "
                "No WAF interference detected."
            ),
        },
        {
            "agent_id": "recon_specialist_3",
            "finding_class": "ssrf",
            "conclusion": (
                "Gave up after 403 Forbidden responses on all endpoints. "
                "Unable to identify any SSRF vectors. Access denied on every attempt. "
                "Could not bypass the Akamai edge protection."
            ),
        },
    ]

    for scenario in scenarios:
        result: dict = retry_detector(
            scenario["agent_id"],
            scenario["conclusion"],
            scenario["finding_class"],
        )
        status: str = "SURRENDER" if result["surrender_detected"] else "CLEAN"
        print(f"[{status}] {scenario['agent_id']} — {scenario['finding_class']}")
        if result["surrender_detected"]:
            print(f"  Matched {len(result['matched_patterns'])} patterns")
            print(f"  Primary category: {result['primary_category']}")
            print(f"  Max severity: {result['max_severity']}")
            print(f"  Bypass suggestions: {len(result['bypass_suggestions'])}")
            print(f"  Retry prompt length: {len(result['retry_prompt'])} chars")
            # Show first 2 suggestions
            for s in result["bypass_suggestions"][:2]:
                print(f"    - {s[:80]}...")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
