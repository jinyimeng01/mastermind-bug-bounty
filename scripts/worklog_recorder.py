#!/usr/bin/env python3
"""
worklog_recorder.py — Worklog Recorder (Hook: hunt-learning.py)

Records every tool call, finding, agent spawn, and agent conclusion
to a JSONL worklog and an Obsidian-style human-readable vault.  Provides
a unified ``record()`` entry-point that auto-detects the entry type and
persists to both outputs.

JSONL schema::

    {
        "timestamp":   "ISO-8601",
        "session_id":  "uuid",
        "agent_id":    "coordinator|specialist_name",
        "entry_type":  "tool_call|finding|agent_spawn|agent_conclusion|scan|skill_invocation",
        "tool_name":   "optional",
        "inputs":      {},
        "outputs":     {},
        "finding_class": "optional",
        "confidence":  "optional",
        "target_host": "optional",
        "data":        {}   # type-specific payload
    }

Usage:
    python worklog_recorder.py
    python -m mastermind_bug_bounty.scripts.worklog_recorder
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
WORKLOG_FILE: str = "worklog.jsonl"
VAULT_DIR: str = "vault"
WORKLOG_VAULT_FILE: str = "worklog.md"
SESSION_ID: str = str(uuid.uuid4())[:8]

ENTRY_TYPES: set[str] = {
    "tool_call",
    "finding",
    "agent_spawn",
    "agent_conclusion",
    "scan",
    "skill_invocation",
}


# ---------------------------------------------------------------------------
# Timestamp helper
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ensure_dir(path: str | Path) -> None:
    """Create parent directories if they don't exist."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# JSONL I/O
# ---------------------------------------------------------------------------

def write_jsonl_entry(entry: dict, log_path: str) -> None:
    """Append a single JSONL entry to *log_path*.

    Creates the file (and parent directories) if they do not exist.
    Each entry is written as one compact JSON line with a trailing newline.

    Args:
        entry: The fully-formed entry dict.
        log_path: Absolute or relative path to the ``.jsonl`` file.
    """
    _ensure_dir(log_path)
    try:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":"), ensure_ascii=False) + "\n")
    except (PermissionError, OSError) as exc:
        # Non-fatal: print to stderr so the hunt isn't killed by a log failure
        print(f"[worklog_recorder] WARNING: failed to write JSONL: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Obsidian vault I/O
# ---------------------------------------------------------------------------

def _format_obsidian_block(entry: dict) -> str:
    """Render a single entry as an Obsidian-flavoured markdown block.

    Returns a multi-line string with front-matter-style metadata and
    a collapsible body.
    """
    ts: str = entry.get("timestamp", _now_iso())
    agent_id: str = entry.get("agent_id", "coordinator")
    entry_type: str = entry.get("entry_type", "unknown")
    data: dict = entry.get("data", {})

    # Header line
    lines: list[str] = [
        f"## [{ts}] {entry_type.upper()} — `{agent_id}`",
        "",
    ]

    # Metadata table
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| **Timestamp** | {ts} |")
    lines.append(f"| **Agent** | {agent_id} |")
    lines.append(f"| **Session** | {entry.get('session_id', 'N/A')} |")

    # Type-specific rendering
    if entry_type == "tool_call":
        lines.append(f"| **Tool** | `{data.get('tool_name', 'N/A')}` |")
        lines.append(f"| **Target** | {data.get('target_host', 'N/A')} |")

    elif entry_type == "finding":
        lines.append(f"| **Class** | {data.get('finding_class', 'N/A')} |")
        lines.append(f"| **Confidence** | {data.get('confidence', 'N/A')} |")
        lines.append(f"| **Target** | {data.get('target_host', 'N/A')} |")
        lines.append(f"| **Severity** | {data.get('severity', 'N/A')} |")

    elif entry_type == "agent_spawn":
        lines.append(f"| **Type** | {data.get('agent_type', 'N/A')} |")
        lines.append(f"| **Task** | {data.get('task', 'N/A')[:80]} |")
        lines.append(f"| **Parent** | {data.get('parent_id', 'N/A')} |")

    elif entry_type == "agent_conclusion":
        lines.append(f"| **Success** | {data.get('success', 'N/A')} |")
        status: str = "completed" if data.get("success") else "failed"
        lines.append(f"| **Status** | {status} |")

    lines.append("")

    # Collapsible details
    lines.append("<details>")
    lines.append("<summary>Raw data</summary>")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(data, indent=2, ensure_ascii=False))
    lines.append("```")
    lines.append("</details>")
    lines.append("")
    lines.append("---")
    lines.append("")

    return "\n".join(lines)


def write_obsidian_entry(entry: dict, vault_path: str) -> None:
    """Append a human-readable entry to the Obsidian worklog vault.

    Args:
        entry: The fully-formed entry dict.
        vault_path: Path to the Obsidian ``.md`` file (usually inside
                    ``hunt-data/vault/worklog.md``).
    """
    _ensure_dir(vault_path)
    block: str = _format_obsidian_block(entry)
    try:
        with open(vault_path, "a", encoding="utf-8") as fh:
            fh.write(block + "\n")
    except (PermissionError, OSError) as exc:
        print(f"[worklog_recorder] WARNING: failed to write vault: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Structured log builders
# ---------------------------------------------------------------------------

def log_tool_call(
    tool_name: str,
    inputs: dict,
    outputs: dict,
    agent_id: str = "coordinator",
) -> dict:
    """Log a single tool invocation.

    Args:
        tool_name: Name of the tool (e.g. ``nmap``, ``sqlmap``).
        inputs: Tool arguments / input parameters.
        outputs: Tool stdout / parsed results.
        agent_id: ID of the agent that invoked the tool.

    Returns:
        The constructed entry dict (not yet persisted).
    """
    return {
        "timestamp": _now_iso(),
        "session_id": SESSION_ID,
        "agent_id": agent_id,
        "entry_type": "tool_call",
        "data": {
            "tool_name": tool_name,
            "inputs": inputs,
            "outputs": outputs,
            "target_host": _extract_host(inputs),
        },
    }


def log_finding(finding: dict, agent_id: str = "coordinator") -> dict:
    """Log a validated (or pre-triage) vulnerability finding.

    Args:
        finding: Finding dict with keys such as ``target_url``,
                 ``vulnerability_class``, ``confidence``, ``evidence``.
        agent_id: ID of the agent that reported the finding.

    Returns:
        The constructed entry dict.
    """
    return {
        "timestamp": _now_iso(),
        "session_id": SESSION_ID,
        "agent_id": agent_id,
        "entry_type": "finding",
        "data": {
            "finding_class": finding.get("vulnerability_class") or finding.get("finding_class", "unknown"),
            "target_host": (
                finding.get("target_url")
                or finding.get("target_host")
                or finding.get("endpoint", "unknown")
            ),
            "confidence": finding.get("confidence", 0.0),
            "severity": finding.get("severity", "unknown"),
            "evidence": finding.get("evidence", ""),
            "impact_description": finding.get("impact_description", ""),
            "proof_of_impact": finding.get("proof_of_impact", ""),
        },
    }


def log_agent_spawn(
    agent_type: str,
    task: str,
    parent_id: str,
) -> dict:
    """Log the creation of a specialist sub-agent.

    Args:
        agent_type: Specialist type (e.g. ``sqli_specialist``).
        task: Description of the task assigned.
        parent_id: ID of the parent agent (usually ``coordinator``).

    Returns:
        The constructed entry dict.
    """
    agent_id: str = f"{agent_type}_{uuid.uuid4().hex[:6]}"
    return {
        "timestamp": _now_iso(),
        "session_id": SESSION_ID,
        "agent_id": agent_id,
        "entry_type": "agent_spawn",
        "data": {
            "agent_type": agent_type,
            "task": task,
            "parent_id": parent_id,
        },
    }


def log_agent_conclusion(
    agent_id: str,
    conclusion: str,
    success: bool,
) -> dict:
    """Log the completion (or failure) of a specialist agent.

    Args:
        agent_id: ID of the agent that finished.
        conclusion: Summary text of the agent's findings or failure reason.
        success: Whether the agent completed its task successfully.

    Returns:
        The constructed entry dict.
    """
    return {
        "timestamp": _now_iso(),
        "session_id": SESSION_ID,
        "agent_id": agent_id,
        "entry_type": "agent_conclusion",
        "data": {
            "conclusion": conclusion,
            "success": success,
        },
    }


# ---------------------------------------------------------------------------
# Unified entry-point
# ---------------------------------------------------------------------------

def record(
    entry_type: str,
    data: dict,
    hunt_dir: str,
    agent_id: str = "coordinator",
) -> dict:
    """Unified recording function — persist to both JSONL and Obsidian vault.

    Auto-validates *entry_type* and normalises the payload before writing.

    Args:
        entry_type: One of ``tool_call``, ``finding``, ``agent_spawn``,
                    ``agent_conclusion``, ``scan``, ``skill_invocation``.
        data: Type-specific payload dict.
        hunt_dir: Root hunt-data directory.
        agent_id: ID of the recording agent.

    Returns:
        The final entry dict that was persisted.

    Raises:
        ValueError: If *entry_type* is not recognised.
    """
    entry_type = entry_type.lower().strip()
    if entry_type not in ENTRY_TYPES:
        raise ValueError(
            f"Unknown entry_type '{entry_type}'. Must be one of: {sorted(ENTRY_TYPES)}"
        )

    entry: dict = {
        "timestamp": _now_iso(),
        "session_id": SESSION_ID,
        "agent_id": agent_id,
        "entry_type": entry_type,
        "data": data,
    }

    hunt_path: Path = Path(hunt_dir)
    jsonl_path: str = str(hunt_path / WORKLOG_FILE)
    vault_path: str = str(hunt_path / VAULT_DIR / WORKLOG_VAULT_FILE)

    write_jsonl_entry(entry, jsonl_path)
    write_obsidian_entry(entry, vault_path)

    return entry


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _extract_host(inputs: dict) -> str:
    """Best-effort extraction of a hostname from tool inputs."""
    for key in ("host", "url", "target", "domain", "u", "-u", "target_host"):
        val: Any = inputs.get(key)
        if val:
            return str(val).split("://")[-1].split("/")[0]
    return ""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    """Run a demo that exercises all entry types."""
    demo_dir: str = "/tmp/mastermind_demo_worklog"
    os.makedirs(f"{demo_dir}/vault", exist_ok=True)

    print("=== Worklog Recorder Demo ===\n")

    # 1. Tool call
    tc: dict = record(
        entry_type="tool_call",
        data={
            "tool_name": "nmap",
            "inputs": {"host": "example.com", "ports": "80,443"},
            "outputs": {"open_ports": [80, 443]},
            "target_host": "example.com",
        },
        hunt_dir=demo_dir,
        agent_id="coordinator",
    )
    print(f"[1] Tool call logged: {tc['data']['tool_name']}")

    # 2. Finding
    finding: dict = record(
        entry_type="finding",
        data={
            "finding_class": "sql_injection",
            "target_host": "https://example.com/search",
            "confidence": 0.85,
            "severity": "high",
            "evidence": "UNION-based payload returns 3 columns; database() = 'prod'",
            "impact_description": "Can extract full user table via blind SQLi",
        },
        hunt_dir=demo_dir,
        agent_id="sqli_specialist",
    )
    print(f"[2] Finding logged: {finding['data']['finding_class']} @ {finding['data']['target_host']}")

    # 3. Agent spawn
    spawn: dict = record(
        entry_type="agent_spawn",
        data={
            "agent_type": "xss_specialist",
            "task": "Test all input vectors on https://example.com for reflected XSS",
            "parent_id": "coordinator",
        },
        hunt_dir=demo_dir,
        agent_id="xss_specialist_a1b2c3",
    )
    print(f"[3] Agent spawned: {spawn['data']['agent_type']}")

    # 4. Agent conclusion
    conclusion: dict = record(
        entry_type="agent_conclusion",
        data={
            "conclusion": "Found reflected XSS in /search?q= parameter. "
                          "Payload <script>alert(1)</script> executes.",
            "success": True,
        },
        hunt_dir=demo_dir,
        agent_id="xss_specialist_a1b2c3",
    )
    print(f"[4] Agent concluded: success={conclusion['data']['success']}")

    # Show file paths
    print(f"\nFiles written:")
    print(f"  JSONL:  {demo_dir}/{WORKLOG_FILE}")
    print(f"  Vault:  {demo_dir}/{VAULT_DIR}/{WORKLOG_VAULT_FILE}")

    # Show tail of JSONL
    print(f"\n--- JSONL tail ---")
    with open(f"{demo_dir}/{WORKLOG_FILE}") as fh:
        for line in fh:
            pass
        print(line.strip()[:200] + "...")

    return 0


if __name__ == "__main__":
    sys.exit(main())
