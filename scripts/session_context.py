#!/usr/bin/env python3
"""
session_context.py — Context Injector (Hook: session-start.py)

Loads and composes the full session context for the Mastermind coordinator
at the start of each session. Gathers hunt metadata, recent worklog entries,
active agent statuses, and the previous session's handoff document.

Standard hunt directory structure:
    hunt-data/
        ledger.json         # Hunt metadata and status
        worklog.jsonl       # All tool calls and findings
        handoff.md          # Previous session handoff
        vault/              # Obsidian-style notes

Usage:
    python session_context.py /path/to/hunt-data
    python -m mastermind_bug_bounty.scripts.session_context /path/to/hunt-data
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LEDGER_FILE: str = "ledger.json"
WORKLOG_FILE: str = "worklog.jsonl"
HANDOFF_FILE: str = "handoff.md"
VAULT_DIR: str = "vault"
DEFAULT_RECENT_MINUTES: int = 30


# ---------------------------------------------------------------------------
# File I/O helpers
# ---------------------------------------------------------------------------

def _read_json(path: str | Path) -> dict:
    """Read a JSON file, return empty dict on error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return {}


def _read_lines(path: str | Path) -> list[str]:
    """Read file lines, return empty list on error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.readlines()
    except (FileNotFoundError, PermissionError):
        return []


def _read_text(path: str | Path) -> str:
    """Read a text file, return empty string on error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except (FileNotFoundError, PermissionError):
        return ""


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def load_hunt_ledger(ledger_path: str) -> dict:
    """Load the active hunt's ledger JSON.

    Args:
        ledger_path: Absolute or relative path to ``ledger.json``.

    Returns:
        The parsed ledger as a dict. Returns an empty dict if the file
        cannot be found or parsed.
    """
    return _read_json(ledger_path)


def load_worklog_recent(worklog_path: str, minutes: int = DEFAULT_RECENT_MINUTES) -> list[dict]:
    """Return worklog entries from the last *minutes* minutes.

    Args:
        worklog_path: Path to ``worklog.jsonl``.
        minutes: Look-back window in minutes (default 30).

    Returns:
        A list of worklog entry dicts within the time window, newest first.
    """
    lines: list[str] = _read_lines(worklog_path)
    cutoff: datetime = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    recent: list[dict] = []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry: dict = json.loads(line)
        except json.JSONDecodeError:
            continue

        ts_raw: str | None = entry.get("timestamp")
        if not ts_raw:
            continue

        try:
            # Parse ISO-8601; handle trailing 'Z' and offset formats
            ts_raw = ts_raw.replace("Z", "+00:00")
            ts: datetime = datetime.fromisoformat(ts_raw)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue

        if ts >= cutoff:
            recent.append(entry)

    # Newest first
    recent.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return recent


def _collect_agent_statuses(recent_entries: list[dict]) -> dict[str, dict]:
    """Derive agent statuses from recent worklog entries.

    Returns a mapping of ``agent_id -> {status, last_activity, task}``.
    """
    statuses: dict[str, dict] = {}
    for entry in recent_entries:
        agent_id: str = entry.get("agent_id", "coordinator")
        entry_type: str = entry.get("entry_type", "")
        ts: str = entry.get("timestamp", "")

        if agent_id not in statuses:
            statuses[agent_id] = {
                "status": "idle",
                "last_activity": ts,
                "task": "",
                "entries": [],
            }

        statuses[agent_id]["last_activity"] = ts
        statuses[agent_id]["entries"].append(entry)

        if entry_type == "agent_spawn":
            statuses[agent_id]["status"] = "active"
            statuses[agent_id]["task"] = entry.get("data", {}).get("task", "")
        elif entry_type == "agent_conclusion":
            statuses[agent_id]["status"] = (
                "completed" if entry.get("data", {}).get("success", False) else "failed"
            )
        elif entry_type == "tool_call":
            statuses[agent_id]["status"] = "working"
    return statuses


def _load_handoff(hunt_dir: str) -> dict[str, str]:
    """Load the most recent handoff document if it exists."""
    handoff_path: Path = Path(hunt_dir) / HANDOFF_FILE
    if handoff_path.exists():
        return {
            "exists": True,
            "content": _read_text(handoff_path),
            "path": str(handoff_path),
        }
    # Also check vault/ for timestamped handoffs
    vault: Path = Path(hunt_dir) / VAULT_DIR
    if vault.is_dir():
        handoffs: list[Path] = sorted(
            vault.glob("handoff_*.md"), reverse=True
        )
        if handoffs:
            return {
                "exists": True,
                "content": _read_text(handoffs[0]),
                "path": str(handoffs[0]),
            }
    return {"exists": False, "content": "", "path": ""}


# ---------------------------------------------------------------------------
# Main composition
# ---------------------------------------------------------------------------

def inject_session_context(hunt_dir: str) -> dict:
    """Compose the full session context for the Mastermind coordinator.

    The context dict contains:
        - **hunt_metadata** — target, scope, start date, status
        - **recent_findings** — worklog entries from last 30 min
        - **active_agents** — agent_id -> status mapping
        - **handoff** — previous session handoff document if available
        - **session_start** — ISO-8601 timestamp of this context injection

    Args:
        hunt_dir: Path to the hunt-data directory.

    Returns:
        A nested dict representing the full session context.
    """
    hunt_dir_path: Path = Path(hunt_dir)

    ledger: dict = load_hunt_ledger(hunt_dir_path / LEDGER_FILE)
    worklog_path: str = str(hunt_dir_path / WORKLOG_FILE)
    recent_entries: list[dict] = load_worklog_recent(worklog_path)

    # Filter to findings only
    recent_findings: list[dict] = [
        e for e in recent_entries
        if e.get("entry_type") == "finding"
    ]

    active_agents: dict = _collect_agent_statuses(recent_entries)
    handoff: dict = _load_handoff(hunt_dir)

    context: dict = {
        "session_start": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "hunt_metadata": {
            "target": ledger.get("target", "unknown"),
            "scope": ledger.get("scope", []),
            "start_date": ledger.get("start_date", ""),
            "status": ledger.get("status", "unknown"),
            "depth": ledger.get("depth", "standard"),
            "ledger_version": ledger.get("version", "1.0"),
        },
        "recent_findings": {
            "window_minutes": DEFAULT_RECENT_MINUTES,
            "count": len(recent_findings),
            "findings": recent_findings[:10],  # Cap at 10
        },
        "active_agents": {
            agent_id: {
                "status": info["status"],
                "last_activity": info["last_activity"],
                "task": info["task"],
            }
            for agent_id, info in active_agents.items()
        },
        "handoff": handoff,
        "stats": {
            "total_recent_entries": len(recent_entries),
            "total_active_agents": len(active_agents),
        },
    }
    return context


def format_context_for_agent(context: dict) -> str:
    """Format the session context as a human-readable string for AI consumption.

    Produces a structured markdown-like text block that can be injected
    directly into a system prompt or user message.

    Args:
        context: The dict returned by :func:`inject_session_context`.

    Returns:
        A formatted multi-line string.
    """
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("MASTermind Bug Bounty — Session Context")
    lines.append(f"Session Start: {context['session_start']}")
    lines.append("=" * 60)

    # Hunt metadata
    meta: dict = context.get("hunt_metadata", {})
    lines.append("")
    lines.append("## Hunt Metadata")
    lines.append(f"- Target: {meta.get('target', 'unknown')}")
    scope: list = meta.get("scope", [])
    if scope:
        lines.append(f"- Scope: {', '.join(str(s) for s in scope)}")
    lines.append(f"- Status: {meta.get('status', 'unknown')}")
    lines.append(f"- Depth: {meta.get('depth', 'standard')}")
    lines.append(f"- Started: {meta.get('start_date', 'N/A')}")

    # Recent findings
    rf: dict = context.get("recent_findings", {})
    lines.append("")
    lines.append(f"## Recent Findings (last {rf.get('window_minutes', 30)} min)")
    findings: list[dict] = rf.get("findings", [])
    if not findings:
        lines.append("_No findings in the recent window._")
    for f in findings:
        data: dict = f.get("data", {})
        lines.append(f"- [{data.get('finding_class', 'unknown')}] "
                     f"{data.get('target_host', 'unknown')} — "
                     f"confidence: {data.get('confidence', 'N/A')}")
        evidence: str = data.get("evidence", "")
        if evidence:
            lines.append(f"  Evidence: {evidence[:120]}")

    # Active agents
    agents: dict = context.get("active_agents", {})
    lines.append("")
    lines.append("## Active Agents")
    if not agents:
        lines.append("_No active agents._")
    for agent_id, info in agents.items():
        lines.append(f"- {agent_id}: {info['status']} "
                     f"(last activity: {info['last_activity']})")
        if info.get("task"):
            lines.append(f"  Task: {info['task'][:100]}")

    # Stats
    stats: dict = context.get("stats", {})
    lines.append("")
    lines.append("## Session Statistics")
    lines.append(f"- Total recent entries: {stats.get('total_recent_entries', 0)}")
    lines.append(f"- Active agents: {stats.get('total_active_agents', 0)}")

    # Handoff
    handoff: dict = context.get("handoff", {})
    if handoff.get("exists"):
        lines.append("")
        lines.append("## Previous Session Handoff")
        lines.append(f"_Loaded from: {handoff.get('path', 'unknown')}_")
        content: str = handoff.get("content", "")
        if content:
            # Include up to 800 chars to avoid flooding context
            lines.append(content[:800])
            if len(content) > 800:
                lines.append("...(truncated)")

    lines.append("")
    lines.append("=" * 60)
    lines.append("End of Session Context")
    lines.append("=" * 60)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    """CLI entry-point."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <hunt-dir>")
        return 1

    hunt_dir: str = sys.argv[1]
    if not os.path.isdir(hunt_dir):
        print(f"[ERROR] Directory not found: {hunt_dir}")
        return 1

    context: dict = inject_session_context(hunt_dir)
    formatted: str = format_context_for_agent(context)
    print(formatted)
    return 0


if __name__ == "__main__":
    # Example: generate demo context if no args
    if len(sys.argv) == 1:
        print("[INFO] No hunt-dir provided; generating demo context...\n")
        # Create a minimal demo directory structure in memory
        demo_dir: str = "/tmp/mastermind_demo_hunt"
        os.makedirs(f"{demo_dir}/vault", exist_ok=True)

        # Write a demo ledger
        with open(f"{demo_dir}/ledger.json", "w") as f:
            json.dump({
                "target": "https://demo.example.com",
                "scope": ["*.example.com"],
                "start_date": "2025-01-15T10:00:00Z",
                "status": "active",
                "depth": "aggressive",
                "version": "1.0",
            }, f, indent=2)

        # Write a demo worklog
        with open(f"{demo_dir}/worklog.jsonl", "w") as f:
            now: datetime = datetime.now(timezone.utc)
            for i in range(5):
                ts: str = (now - timedelta(minutes=i * 5)).isoformat().replace("+00:00", "Z")
                entry = {
                    "timestamp": ts,
                    "session_id": f"demo-session-{i}",
                    "agent_id": "coordinator" if i < 2 else "sql_injection_specialist",
                    "entry_type": "finding" if i == 1 else "tool_call",
                    "tool_name": "nmap" if i == 0 else "sqlmap",
                    "target_host": "https://demo.example.com",
                    "data": {
                        "finding_class": "sql_injection" if i == 1 else "",
                        "confidence": 0.85 if i == 1 else 0.0,
                        "evidence": "UNION-based injection detected in parameter 'id'" if i == 1 else "",
                    },
                }
                f.write(json.dumps(entry) + "\n")

        context = inject_session_context(demo_dir)
        print(format_context_for_agent(context))
    else:
        sys.exit(main())
