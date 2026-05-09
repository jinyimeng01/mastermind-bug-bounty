#!/usr/bin/env python3
"""
handoff_saver.py — Handoff Saver (Hook: hunt-handoff.py)

Serialises the full state of an in-progress bug-bounty hunt into an
Obsidian-compatible markdown handoff document.  The handoff is designed
to be read by the coordinator at the start of the *next* session to
maintain continuity across restarts.

Features:
    - YAML frontmatter with session metadata
    - Executive summary with hunt statistics
    - Active-targets table with status
    - In-progress and completed findings
    - Agent status dashboard
    - Tool-call statistics
    - Next-steps checklist
    - Blockers and dependencies section

Usage:
    python handoff_saver.py /path/to/hunt-data ["custom instructions"]
    python -m mastermind_bug_bounty.scripts.handoff_saver /path/to/hunt-data
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LEDGER_FILE: str = "ledger.json"
WORKLOG_FILE: str = "worklog.jsonl"
VAULT_DIR: str = "vault"
HANDOFF_PREFIX: str = "handoff"
HANDOFF_EXTENSION: str = ".md"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_json(path: str | Path) -> dict:
    """Read JSON file, return empty dict on error."""
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


def _slugify(text: str) -> str:
    """Convert text to a filesystem-safe slug."""
    return re.sub(r"[^\w\-]", "_", text.lower())[:50]


# ---------------------------------------------------------------------------
# State collection
# ---------------------------------------------------------------------------

def _collect_worklog_entries(worklog_path: str) -> list[dict]:
    """Parse the JSONL worklog into a list of entry dicts."""
    lines: list[str] = _read_lines(worklog_path)
    entries: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry: dict = json.loads(line)
            entries.append(entry)
        except json.JSONDecodeError:
            continue
    return entries


def _summarise_targets(entries: list[dict]) -> dict[str, dict]:
    """Derive per-target status from worklog entries.

    Returns::

        {
            "example.com": {
                "status": "in_progress",
                "findings": 3,
                "last_activity": "ISO timestamp",
                "tools_used": ["nmap", "sqlmap"],
            },
            ...
        }
    """
    targets: dict[str, dict] = {}
    for entry in entries:
        data: dict = entry.get("data", {})
        host: str = data.get("target_host", "")
        if not host:
            continue

        if host not in targets:
            targets[host] = {
                "status": "pending",
                "findings": 0,
                "last_activity": entry.get("timestamp", ""),
                "tools_used": set(),
            }

        targets[host]["last_activity"] = entry.get("timestamp", "")
        entry_type: str = entry.get("entry_type", "")

        if entry_type == "finding":
            targets[host]["findings"] += 1
            targets[host]["status"] = "active"
        elif entry_type == "tool_call":
            tool: str = data.get("tool_name", "")
            if tool:
                targets[host]["tools_used"].add(tool)
            if targets[host]["status"] == "pending":
                targets[host]["status"] = "in_progress"

    # Convert sets to sorted lists
    for host in targets:
        targets[host]["tools_used"] = sorted(targets[host]["tools_used"])

    return targets


def _summarise_agents(entries: list[dict]) -> dict[str, dict]:
    """Derive agent statuses from worklog entries."""
    agents: dict[str, dict] = {}
    for entry in entries:
        agent_id: str = entry.get("agent_id", "coordinator")
        entry_type: str = entry.get("entry_type", "")
        ts: str = entry.get("timestamp", "")
        data: dict = entry.get("data", {})

        if agent_id not in agents:
            agents[agent_id] = {
                "status": "idle",
                "spawned": False,
                "concluded": False,
                "task": "",
                "last_activity": ts,
                "entry_count": 0,
            }

        agents[agent_id]["last_activity"] = ts
        agents[agent_id]["entry_count"] += 1

        if entry_type == "agent_spawn":
            agents[agent_id]["status"] = "active"
            agents[agent_id]["spawned"] = True
            agents[agent_id]["task"] = data.get("task", "")
        elif entry_type == "agent_conclusion":
            agents[agent_id]["status"] = (
                "completed" if data.get("success", False) else "failed"
            )
            agents[agent_id]["concluded"] = True
            agents[agent_id]["conclusion"] = data.get("conclusion", "")
        elif entry_type == "tool_call" and agents[agent_id]["status"] == "idle":
            agents[agent_id]["status"] = "working"

    return agents


def _summarise_findings(entries: list[dict]) -> dict[str, list[dict]]:
    """Separate findings into in-progress and completed."""
    in_progress: list[dict] = []
    completed: list[dict] = []

    for entry in entries:
        if entry.get("entry_type") != "finding":
            continue
        data: dict = entry.get("data", {})
        finding: dict = {
            "timestamp": entry.get("timestamp", ""),
            "agent_id": entry.get("agent_id", ""),
            "finding_class": data.get("finding_class", "unknown"),
            "target_host": data.get("target_host", "unknown"),
            "confidence": data.get("confidence", 0.0),
            "severity": data.get("severity", "unknown"),
            "evidence": data.get("evidence", ""),
            "impact_description": data.get("impact_description", ""),
        }

        # A finding is "completed" if it has impact demonstrated
        if data.get("impact_description") or data.get("proof_of_impact"):
            completed.append(finding)
        else:
            in_progress.append(finding)

    return {"in_progress": in_progress, "completed": completed}


def _tool_statistics(entries: list[dict]) -> dict[str, Any]:
    """Aggregate tool-call statistics."""
    tool_counts: dict[str, int] = {}
    total_calls: int = 0
    for entry in entries:
        if entry.get("entry_type") == "tool_call":
            total_calls += 1
            tool: str = entry.get("data", {}).get("tool_name", "unknown")
            tool_counts[tool] = tool_counts.get(tool, 0) + 1

    return {
        "total_tool_calls": total_calls,
        "unique_tools": len(tool_counts),
        "tool_breakdown": dict(sorted(tool_counts.items(), key=lambda x: -x[1])),
    }


# ---------------------------------------------------------------------------
# Main state serializer
# ---------------------------------------------------------------------------

def serialize_hunt_state(hunt_dir: str) -> dict:
    """Collect the full hunt state for handoff generation.

    Args:
        hunt_dir: Path to the hunt-data directory.

    Returns:
        A nested dict containing all hunt state needed for the handoff.
    """
    hunt_path: Path = Path(hunt_dir)
    ledger: dict = _read_json(hunt_path / LEDGER_FILE)
    worklog_path: str = str(hunt_path / WORKLOG_FILE)
    entries: list[dict] = _collect_worklog_entries(worklog_path)

    targets: dict[str, dict] = _summarise_targets(entries)
    agents: dict[str, dict] = _summarise_agents(entries)
    findings: dict[str, list[dict]] = _summarise_findings(entries)
    tool_stats: dict[str, Any] = _tool_statistics(entries)

    return {
        "timestamp": _now_iso(),
        "hunt_metadata": {
            "target": ledger.get("target", "unknown"),
            "scope": ledger.get("scope", []),
            "start_date": ledger.get("start_date", ""),
            "status": ledger.get("status", "unknown"),
            "depth": ledger.get("depth", "standard"),
        },
        "targets": targets,
        "agents": agents,
        "findings": findings,
        "tool_statistics": tool_stats,
        "total_worklog_entries": len(entries),
    }


# ---------------------------------------------------------------------------
# Handoff document generator
# ---------------------------------------------------------------------------

def generate_handoff_document(state: dict) -> str:
    """Format the hunt state as an Obsidian-compatible markdown document.

    Args:
        state: The dict returned by :func:`serialize_hunt_state`.

    Returns:
        A complete markdown string with YAML frontmatter.
    """
    now: str = state["timestamp"]
    meta: dict = state["hunt_metadata"]
    targets: dict[str, dict] = state.get("targets", {})
    agents: dict[str, dict] = state.get("agents", {})
    findings: dict[str, list[dict]] = state.get("findings", {})
    tool_stats: dict[str, Any] = state.get("tool_statistics", {})

    # YAML frontmatter
    lines: list[str] = [
        "---",
        f"session_date: {now}",
        f"agent: mastermind-coordinator",
        f"target: {meta.get('target', 'unknown')}",
        f"status: {meta.get('status', 'unknown')}",
        f"depth: {meta.get('depth', 'standard')}",
        f"total_entries: {state.get('total_worklog_entries', 0)}",
        "---",
        "",
    ]

    # Title
    lines.append(f"# Hunt Handoff — {meta.get('target', 'unknown')}")
    lines.append(f"*Generated: {now}*")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Target**: {meta.get('target', 'unknown')}")
    scope: list = meta.get("scope", [])
    if scope:
        lines.append(f"- **Scope**: {', '.join(str(s) for s in scope)}")
    lines.append(f"- **Status**: {meta.get('status', 'unknown')}")
    lines.append(f"- **Depth**: {meta.get('depth', 'standard')}")
    lines.append(f"- **Worklog entries**: {state.get('total_worklog_entries', 0)}")
    lines.append(f"- **Active targets**: {len(targets)}")
    lines.append(f"- **Active agents**: {sum(1 for a in agents.values() if a['status'] in ('active', 'working'))}")
    lines.append(f"- **Findings in progress**: {len(findings.get('in_progress', []))}")
    lines.append(f"- **Findings completed**: {len(findings.get('completed', []))}")
    lines.append(f"- **Total tool calls**: {tool_stats.get('total_tool_calls', 0)}")
    lines.append("")

    # Active Targets Table
    lines.append("## Active Targets")
    lines.append("")
    if targets:
        lines.append("| Target | Status | Findings | Last Activity | Tools Used |")
        lines.append("|--------|--------|----------|---------------|------------|")
        for host, info in sorted(targets.items()):
            tools: str = ", ".join(f"`{t}`" for t in info.get("tools_used", []))
            lines.append(
                f"| `{host}` | {info['status']} | {info['findings']} | "
                f"{info['last_activity'][:19] if info['last_activity'] else 'N/A'} | {tools} |"
            )
    else:
        lines.append("_No targets have been scanned yet._")
    lines.append("")

    # Findings in Progress
    lines.append("## Findings in Progress")
    lines.append("")
    in_progress: list[dict] = findings.get("in_progress", [])
    if in_progress:
        for f in in_progress:
            lines.append(f"### [{f['finding_class']}] {f['target_host']}")
            lines.append(f"- **Confidence**: {f['confidence']:.2f}")
            lines.append(f"- **Severity**: {f['severity']}")
            lines.append(f"- **Agent**: {f['agent_id']}")
            lines.append(f"- **Detected**: {f['timestamp'][:19] if f['timestamp'] else 'N/A'}")
            if f.get("evidence"):
                lines.append(f"- **Evidence**: {f['evidence'][:120]}")
            lines.append("")
    else:
        lines.append("_No findings currently in progress._")
    lines.append("")

    # Completed Findings
    lines.append("## Completed Findings")
    lines.append("")
    completed: list[dict] = findings.get("completed", [])
    if completed:
        for f in completed:
            lines.append(f"### [{f['finding_class']}] {f['target_host']} — COMPLETE")
            lines.append(f"- **Confidence**: {f['confidence']:.2f}")
            lines.append(f"- **Severity**: {f['severity']}")
            lines.append(f"- **Impact**: {f.get('impact_description', 'N/A')[:150]}")
            lines.append("")
    else:
        lines.append("_No completed findings yet._")
    lines.append("")

    # Agent Status Dashboard
    lines.append("## Agent Status Dashboard")
    lines.append("")
    if agents:
        lines.append("| Agent | Status | Task | Entries | Last Activity |")
        lines.append("|-------|--------|------|---------|---------------|")
        for agent_id, info in sorted(agents.items()):
            task: str = info.get("task", "")[:40]
            lines.append(
                f"| `{agent_id}` | {info['status']} | {task} | "
                f"{info['entry_count']} | "
                f"{info['last_activity'][:19] if info['last_activity'] else 'N/A'} |"
            )
    else:
        lines.append("_No agent activity recorded._")
    lines.append("")

    # Tool Statistics
    lines.append("## Tool Call Statistics")
    lines.append("")
    lines.append(f"- **Total calls**: {tool_stats.get('total_tool_calls', 0)}")
    lines.append(f"- **Unique tools**: {tool_stats.get('unique_tools', 0)}")
    breakdown: dict[str, int] = tool_stats.get("tool_breakdown", {})
    if breakdown:
        lines.append("- **Breakdown**:")
        for tool, count in list(breakdown.items())[:10]:
            lines.append(f"  - `{tool}`: {count}")
    lines.append("")

    # Next Steps Checklist
    lines.append("## Next Steps")
    lines.append("")
    lines.append("- [ ] Review findings in progress and assign follow-up agents")
    lines.append("- [ ] Escalate high-confidence findings to POC chain")
    lines.append("- [ ] Complete triage for all pending findings")
    lines.append("- [ ] Rotate to untested targets in scope")
    lines.append("- [ ] Update ledger with any scope changes")
    lines.append("")

    # Blockers
    lines.append("## Blockers and Dependencies")
    lines.append("")
    lines.append("_Document any blockers encountered during this session:_")
    lines.append("")
    lines.append("- None recorded")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_handoff(hunt_dir: str, custom_instructions: str = "") -> str:
    """Serialize hunt state and save to the vault.

    Args:
        hunt_dir: Path to the hunt-data directory.
        custom_instructions: Optional user-provided notes to append.

    Returns:
        The absolute path of the saved handoff file.
    """
    state: dict = serialize_hunt_state(hunt_dir)
    document: str = generate_handoff_document(state)

    if custom_instructions:
        document += (
            "\n## Custom Instructions\n\n"
            f"> {custom_instructions}\n\n"
        )

    # Generate filename
    now: str = state["timestamp"].replace(":", "-").replace("+", "plus")
    filename: str = f"{HANDOFF_PREFIX}_{now}{HANDOFF_EXTENSION}"

    vault_path: Path = Path(hunt_dir) / VAULT_DIR
    vault_path.mkdir(parents=True, exist_ok=True)

    file_path: Path = vault_path / filename
    try:
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(document)
    except (PermissionError, OSError) as exc:
        print(f"[handoff_saver] ERROR: cannot write handoff: {exc}", file=sys.stderr)
        raise

    # Also update the latest symlink / copy
    latest_path: Path = vault_path / f"{HANDOFF_PREFIX}_latest{HANDOFF_EXTENSION}"
    try:
        if latest_path.exists() or latest_path.is_symlink():
            latest_path.unlink()
        latest_path.symlink_to(filename)
    except (OSError, PermissionError):
        # Fallback: copy instead of symlink
        try:
            import shutil
            shutil.copy2(str(file_path), str(latest_path))
        except Exception:
            pass

    return str(file_path)


def load_handoff(hunt_dir: str) -> dict:
    """Load the most recent handoff document.

    Args:
        hunt_dir: Path to the hunt-data directory.

    Returns:
        A dict with ``content`` (markdown string), ``path``, and ``timestamp``.
        Returns an empty-content dict if no handoff exists.
    """
    vault_path: Path = Path(hunt_dir) / VAULT_DIR
    if not vault_path.is_dir():
        return {"content": "", "path": "", "timestamp": ""}

    # Try the symlink first
    latest: Path = vault_path / f"{HANDOFF_PREFIX}_latest{HANDOFF_EXTENSION}"
    if latest.exists():
        try:
            with open(latest, "r", encoding="utf-8") as fh:
                content: str = fh.read()
            return {"content": content, "path": str(latest), "timestamp": _now_iso()}
        except (PermissionError, OSError):
            pass

    # Fallback: find most recent by filename sort
    handoffs: list[Path] = sorted(
        vault_path.glob(f"{HANDOFF_PREFIX}_*{HANDOFF_EXTENSION}"),
        reverse=True,
    )
    if handoffs:
        try:
            with open(handoffs[0], "r", encoding="utf-8") as fh:
                content = fh.read()
            return {"content": content, "path": str(handoffs[0]), "timestamp": _now_iso()}
        except (PermissionError, OSError):
            pass

    return {"content": "", "path": "", "timestamp": ""}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    """CLI: save or load a handoff."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <hunt-dir> [custom-instructions]")
        return 1

    hunt_dir: str = sys.argv[1]
    os.makedirs(hunt_dir, exist_ok=True)

    custom: str = sys.argv[2] if len(sys.argv) > 2 else ""

    # If hunt dir is empty, seed it with demo data
    if not (Path(hunt_dir) / "ledger.json").exists():
        print("[INFO] No ledger found; seeding demo data...")
        os.makedirs(f"{hunt_dir}/vault", exist_ok=True)

        with open(f"{hunt_dir}/ledger.json", "w") as f:
            json.dump({
                "target": "https://demo.example.com",
                "scope": ["*.example.com"],
                "start_date": "2025-01-15T10:00:00Z",
                "status": "active",
                "depth": "aggressive",
            }, f, indent=2)

        with open(f"{hunt_dir}/worklog.jsonl", "w") as f:
            entries: list[dict] = [
                {
                    "timestamp": "2025-01-15T12:00:00Z",
                    "session_id": "demo-s1",
                    "agent_id": "coordinator",
                    "entry_type": "tool_call",
                    "data": {
                        "tool_name": "nmap",
                        "inputs": {"host": "demo.example.com"},
                        "outputs": {"open_ports": [80, 443, 8080]},
                        "target_host": "demo.example.com",
                    },
                },
                {
                    "timestamp": "2025-01-15T12:05:00Z",
                    "session_id": "demo-s1",
                    "agent_id": "sqli_specialist_a1b2c3",
                    "entry_type": "finding",
                    "data": {
                        "finding_class": "sql_injection",
                        "target_host": "https://demo.example.com/api/users",
                        "confidence": 0.88,
                        "severity": "critical",
                        "evidence": "UNION SELECT returns full schema",
                        "impact_description": "Extracted 12,340 user records including password hashes",
                    },
                },
                {
                    "timestamp": "2025-01-15T12:10:00Z",
                    "session_id": "demo-s1",
                    "agent_id": "xss_specialist_d4e5f6",
                    "entry_type": "agent_spawn",
                    "data": {
                        "agent_type": "xss_specialist",
                        "task": "Test all input vectors for reflected XSS",
                        "parent_id": "coordinator",
                    },
                },
                {
                    "timestamp": "2025-01-15T12:15:00Z",
                    "session_id": "demo-s1",
                    "agent_id": "xss_specialist_d4e5f6",
                    "entry_type": "agent_conclusion",
                    "data": {
                        "conclusion": "Found reflected XSS in /search parameter",
                        "success": True,
                    },
                },
                {
                    "timestamp": "2025-01-15T12:20:00Z",
                    "session_id": "demo-s1",
                    "agent_id": "coordinator",
                    "entry_type": "finding",
                    "data": {
                        "finding_class": "xss",
                        "target_host": "https://demo.example.com/search",
                        "confidence": 0.75,
                        "severity": "medium",
                        "evidence": "<script>alert(1)</script> reflected",
                    },
                },
            ]
            for e in entries:
                f.write(json.dumps(e) + "\n")

    # Save handoff
    handoff_path: str = save_handoff(hunt_dir, custom)
    print(f"[OK] Handoff saved to: {handoff_path}")

    # Show preview
    loaded: dict = load_handoff(hunt_dir)
    preview: str = loaded.get("content", "")[:600]
    print(f"\n--- Preview ---\n{preview}\n...")

    return 0


if __name__ == "__main__":
    sys.exit(main())
