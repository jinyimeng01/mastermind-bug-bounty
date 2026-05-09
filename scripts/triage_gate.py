#!/usr/bin/env python3
"""
triage_gate.py — Triage Gate (Hook: bug-triage-gate.py)

Validates vulnerability findings before they are promoted to the POC chain.
Enforces the **hard gate**: a finding must demonstrate *impact*, not merely
detection.  Without proof of exploitable impact, the finding is rejected
and returned for deeper testing.

Usage:
    python triage_gate.py
    python -m mastermind_bug_bounty.scripts.triage_gate
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_CONFIDENCE_THRESHOLD: float = 0.70
REQUIRED_EVIDENCE_TYPES: list[str] = ["screenshot", "video", "curl_command", "http_response"]


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _has_target(finding: dict) -> bool:
    """Ensure the finding references a concrete URL or endpoint."""
    target: Any = finding.get("target_url") or finding.get("target_host") or finding.get("endpoint")
    return bool(target and isinstance(target, str) and len(target) > 0)


def _has_vuln_class(finding: dict) -> bool:
    """Ensure a vulnerability class has been identified."""
    vclass: Any = finding.get("vulnerability_class") or finding.get("finding_class")
    return bool(vclass and isinstance(vclass, str) and len(vclass) > 0)


def _has_detection_evidence(finding: dict) -> bool:
    """Check that some form of detection evidence exists."""
    evidence: Any = finding.get("evidence") or finding.get("detection_evidence")
    if isinstance(evidence, str) and len(evidence) > 10:
        return True
    if isinstance(evidence, list) and len(evidence) > 0:
        return True
    if isinstance(evidence, dict) and evidence:
        return True
    # Also accept POC steps as evidence
    poc: Any = finding.get("poc_steps")
    if isinstance(poc, list) and len(poc) > 0:
        return True
    return False


def check_impact_demonstrated(finding: dict) -> bool:
    """HARD GATE: require proof of *impact*, not just detection.

    A finding passes only when it proves the vulnerability can be
    *exploited* to produce a tangible security outcome (data exposure,
    privilege escalation, RCE demonstration, etc.).

    Impact indicators checked:
        - ``impact_description`` key exists and is non-empty
        - ``impact_demonstrated`` flag is explicitly ``True``
        - ``proof_of_impact`` field with concrete exploit output
        - ``severity`` rated high/critical AND evidence supports it
        - Affected data / functionality explicitly described

    Args:
        finding: The raw finding dict.

    Returns:
        ``True`` if exploitable impact has been demonstrated.
    """
    # Direct impact-demonstrated flag
    if finding.get("impact_demonstrated") is True:
        return True

    # Impact description with substance
    impact_desc: Any = finding.get("impact_description") or finding.get("impact")
    if isinstance(impact_desc, str) and len(impact_desc) > 20:
        return True

    # Proof of impact
    proof: Any = finding.get("proof_of_impact") or finding.get("proof")
    if isinstance(proof, str) and len(proof) > 10:
        return True
    if isinstance(proof, list) and len(proof) > 0:
        return True

    # Severity-based heuristic: high/critical findings need impact
    severity: str = str(finding.get("severity", "")).lower()
    if severity in {"high", "critical", "severe"}:
        # For high/critical, require at least a described impact
        if isinstance(impact_desc, str) and len(impact_desc) > 10:
            return True
        if isinstance(proof, (str, list)) and proof:
            return True

    # Data-affected field
    data_affected: Any = finding.get("data_exposed") or finding.get("affected_resource")
    if data_affected:
        return True

    return False


# ---------------------------------------------------------------------------
# Validation orchestrator
# ---------------------------------------------------------------------------

def validate_finding(finding: dict) -> dict:
    """Run all validation checks against a finding.

    Checks (in order):
        1. Has target URL/endpoint
        2. Has vulnerability class identified
        3. Has detection evidence
        4. **Has impact demonstrated** (hard gate)
        5. Confidence score >= threshold (default 0.7)

    Args:
        finding: Raw finding dict from a specialist agent.

    Returns:
        A dict::

            {
                "valid": bool,
                "checks": {
                    "has_target": bool,
                    "has_vulnerability_class": bool,
                    "has_detection_evidence": bool,
                    "impact_demonstrated": bool,
                    "confidence_passed": bool,
                },
                "confidence": float,
                "threshold": float,
                "reasons": list[str],
            }
    """
    confidence: float = float(finding.get("confidence", 0.0))
    threshold: float = float(
        finding.get("confidence_threshold", DEFAULT_CONFIDENCE_THRESHOLD)
    )

    checks: dict[str, bool] = {
        "has_target": _has_target(finding),
        "has_vulnerability_class": _has_vuln_class(finding),
        "has_detection_evidence": _has_detection_evidence(finding),
        "impact_demonstrated": check_impact_demonstrated(finding),
        "confidence_passed": confidence >= threshold,
    }

    reasons: list[str] = []
    if not checks["has_target"]:
        reasons.append("Missing target URL or endpoint.")
    if not checks["has_vulnerability_class"]:
        reasons.append("Vulnerability class not identified.")
    if not checks["has_detection_evidence"]:
        reasons.append("Insufficient detection evidence.")
    if not checks["impact_demonstrated"]:
        reasons.append(
            "IMPACT NOT DEMONSTRATED — detection alone is insufficient. "
            "Provide proof of exploitable impact (data exposure, "
            "privilege escalation, RCE demo, etc.)."
        )
    if not checks["confidence_passed"]:
        reasons.append(
            f"Confidence score {confidence:.2f} below threshold {threshold:.2f}."
        )

    valid: bool = all(checks.values())

    return {
        "valid": valid,
        "checks": checks,
        "confidence": confidence,
        "threshold": threshold,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Triage report
# ---------------------------------------------------------------------------

def generate_triage_report(finding: dict, approved: bool) -> dict:
    """Generate a structured triage decision with reasoning.

    Args:
        finding: The raw finding dict.
        approved: Whether the triage gate approved the finding.

    Returns:
        A dict::

            {
                "decision": "approved" | "rejected",
                "timestamp": ISO-8601 string,
                "finding_class": str,
                "target": str,
                "confidence": float,
                "reasoning": str,
                "next_action": str,
            }
    """
    now: str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    finding_class: str = str(
        finding.get("vulnerability_class") or finding.get("finding_class", "unknown")
    )
    target: str = str(
        finding.get("target_url") or finding.get("target_host") or finding.get("endpoint", "unknown")
    )
    confidence: float = float(finding.get("confidence", 0.0))

    if approved:
        reasoning: str = (
            f"Finding '{finding_class}' against {target} passed all triage checks. "
            f"Impact demonstrated with confidence {confidence:.2f}. Proceeding to POC chain."
        )
        next_action: str = "Trigger POC chain: request proof-of-concept evidence."
    else:
        reasoning = (
            f"Finding '{finding_class}' against {target} FAILED triage. "
            "Requires impact demonstration before promotion."
        )
        next_action = "Return to specialist agent for deeper exploitation and impact proof."

    return {
        "decision": "approved" if approved else "rejected",
        "timestamp": now,
        "finding_class": finding_class,
        "target": target,
        "confidence": confidence,
        "reasoning": reasoning,
        "next_action": next_action,
    }


# ---------------------------------------------------------------------------
# POC chain trigger
# ---------------------------------------------------------------------------

def trigger_poc_chain(finding: dict) -> dict:
    """If a finding is approved, generate the POC evidence chain.

    Args:
        finding: The approved finding dict.

    Returns:
        A dict::

            {
                "poc_steps": list[str],
                "proof_required": list[str],
                "report_template": str,
                "caido_recording_required": bool,
            }
    """
    finding_class: str = str(
        finding.get("vulnerability_class") or finding.get("finding_class", "unknown")
    )
    target: str = str(
        finding.get("target_url") or finding.get("target_host") or finding.get("endpoint", "unknown")
    )

    # Default POC steps
    poc_steps: list[str] = [
        f"1. Re-confirm the vulnerability: reproduce {finding_class} against {target}",
        "2. Document the exact request/response pair that triggers the issue",
        "3. Escalate to demonstrate maximum impact (e.g., extract data, escalate privileges)",
        "4. Capture video or screenshot of the full exploitation chain",
        "5. Test on a secondary endpoint to confirm reach",
        "6. Document remediation bypass attempts if any",
    ]

    # Customise steps based on vulnerability class
    class_lower: str = finding_class.lower()
    if "sql" in class_lower or "injection" in class_lower:
        poc_steps[2] = "3. Use SQLMap or manual UNION/payload to extract schema/data"
    elif "xss" in class_lower:
        poc_steps[2] = "3. Demonstrate cookie theft, keylogging, or DOM manipulation"
    elif "ssrf" in class_lower:
        poc_steps[2] = "3. Probe internal services; map accessible network ranges"
    elif "lfi" in class_lower or "path traversal" in class_lower:
        poc_steps[2] = "3. Read sensitive files (/etc/passwd, application config)"
    elif "rce" in class_lower:
        poc_steps[2] = "3. Execute benign command (id, whoami) and capture output"
    elif "idor" in class_lower:
        poc_steps[2] = "3. Access other users' resources by modifying object references"

    # Determine if Caido recording is required
    caido_required: bool = "rce" in class_lower or "ssrf" in class_lower or "sqli" in class_lower

    report_template: str = f"""# Vulnerability Report: {finding_class}

## Target
{target}

## Classification
{finding_class}

## Summary
[Executive summary of the vulnerability and its impact]

## Steps to Reproduce
[Numbered reproduction steps]

## Impact
[Detailed impact description]

## Evidence
[Screenshots, videos, curl commands]

## Remediation
[Recommended fixes]

## References
[CVEs, OWASP links, etc.]
"""

    return {
        "poc_steps": poc_steps,
        "proof_required": ["screenshot", "video", "curl_command"],
        "report_template": report_template,
        "caido_recording_required": caido_required,
    }


# ---------------------------------------------------------------------------
# Main triage gate
# ---------------------------------------------------------------------------

def triage_gate(finding: dict) -> dict:
    """Main triage gate entry-point.

    Validates a finding and returns a complete triage decision including
    the POC chain (if approved) or rejection reasons (if failed).

    Args:
        finding: Raw finding dict from a specialist agent.

    Returns:
        A dict::

            {
                "approved": bool,
                "triage_report": dict,
                "poc_chain": dict | None,
                "validation": dict,
            }
    """
    validation: dict = validate_finding(finding)
    approved: bool = validation["valid"]

    triage_report: dict = generate_triage_report(finding, approved)
    poc_chain: dict | None = trigger_poc_chain(finding) if approved else None

    return {
        "approved": approved,
        "triage_report": triage_report,
        "poc_chain": poc_chain,
        "validation": validation,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    """Run demo triage against sample findings."""
    print("=== Triage Gate Demo ===\n")

    # --- Finding 1: detection only (should fail) ---
    detection_only: dict = {
        "target_url": "https://example.com/search",
        "vulnerability_class": "sql_injection",
        "evidence": "Single quote causes error message",
        "confidence": 0.85,
        "severity": "high",
        # No impact_description, no proof_of_impact
    }

    result1: dict = triage_gate(detection_only)
    print(f"[Finding 1] Detection-only SQLi — approved={result1['approved']}")
    print(f"  Reasons: {result1['validation']['reasons']}")
    print(f"  Report: {json.dumps(result1['triage_report'], indent=2)}\n")

    # --- Finding 2: full impact demonstrated (should pass) ---
    full_impact: dict = {
        "target_url": "https://example.com/api/users",
        "vulnerability_class": "sql_injection",
        "evidence": "UNION SELECT payload returns 5 columns; database() reveals 'prod_db'",
        "impact_description": "Successfully extracted full user table containing "
                             "12,340 email/password hash records via time-based blind SQLi.",
        "proof_of_impact": [
            "SELECT COUNT(*) FROM users → 12340",
            "SELECT email,password_hash FROM users LIMIT 5 → [redacted]",
            "Database user: 'db_admin@%'",
        ],
        "confidence": 0.92,
        "severity": "critical",
        "impact_demonstrated": True,
    }

    result2: dict = triage_gate(full_impact)
    print(f"[Finding 2] Full-impact SQLi — approved={result2['approved']}")
    print(f"  POC steps: {result2['poc_chain']['poc_steps'][:2]}")
    print(f"  Caido required: {result2['poc_chain']['caido_recording_required']}\n")

    # --- Finding 3: low confidence (should fail) ---
    low_confidence: dict = {
        "target_url": "https://example.com/contact",
        "vulnerability_class": "xss",
        "evidence": "<script>alert(1)</script> reflected in response body",
        "impact_description": "XSS confirmed via reflected payload in search parameter",
        "proof_of_impact": "alert(1) executes; cookie accessible via document.cookie",
        "confidence": 0.55,
        "severity": "medium",
    }

    result3: dict = triage_gate(low_confidence)
    print(f"[Finding 3] Low-confidence XSS — approved={result3['approved']}")
    print(f"  Reasons: {result3['validation']['reasons']}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
