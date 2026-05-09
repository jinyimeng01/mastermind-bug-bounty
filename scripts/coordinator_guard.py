#!/usr/bin/env python3
"""
coordinator_guard.py — Coordinator Guard (Hook: mastermind-guard.py)

Intercepts coordinator tool calls and enforces operational policies:
    1. Rate limiting — no more than *threshold* requests to the same host
       within the tracking window.
    2. Delegation enforcement — warn (nudge) when the coordinator attempts
       to perform specialist work directly instead of delegating to an agent.

Rate-limit tracking is backed by an in-memory ring buffer that can be
serialized to JSON for persistence across short restarts.

Usage:
    python coordinator_guard.py
    python -m mastermind_bug_bounty.scripts.coordinator_guard
"""

from __future__ import annotations

import json
import os
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Default policy constants
# ---------------------------------------------------------------------------
DEFAULT_RATE_THRESHOLD: int = 3
DEFAULT_WINDOW_SECONDS: int = 60
COORDINATOR_TOOL_ALLOWLIST: set[str] = {
    # Tools the coordinator is *allowed* to run directly
    "web_search",
    "read_file",
    "shell",
    "write_file",
    "edit_file",
    "list_files",
    "search_files",
}

SPECIALIST_TOOL_NAMES: set[str] = {
    # Tools that should trigger a delegation nudge
    "nmap",
    "ffuf",
    "gobuster",
    "sqlmap",
    "nikto",
    "burp_scan",
    "zap_scan",
    "caido_capture",
    " nuclei",
    "dalfox",
    "commix",
    "xsstrike",
    "wpscan",
    "amass",
    "subfinder",
    "httpx",
    "katana",
    "hakrawler",
    "gau",
    "waybackurls",
    "dnsrecon",
    "theHarvester",
}


# ---------------------------------------------------------------------------
# In-memory rate-limit store
# ---------------------------------------------------------------------------

class RateLimitStore:
    """Ring-buffer backed request-history store.

    Keeps the most recent *max_entries* tool-call records in memory.
    Entries older than *window_seconds* are ignored at query time.
    """

    def __init__(self, max_entries: int = 500, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> None:
        self._history: deque[dict] = deque(maxlen=max_entries)
        self._window_seconds: int = window_seconds

    # ------------------------------------------------------------------
    # Persistence (optional JSON backing)
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path, **kwargs: Any) -> "RateLimitStore":
        """Load history from a JSON file.

        Args:
            path: Path to the JSON backing file.
            **kwargs: forwarded to the constructor.

        Returns:
            A :class:`RateLimitStore` populated from disk.
        """
        store: RateLimitStore = cls(**kwargs)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data: list[dict] = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            return store

        now: float = datetime.now(timezone.utc).timestamp()
        cutoff: float = now - store._window_seconds
        for entry in data:
            ts: float | None = entry.get("ts")
            if ts and ts >= cutoff:
                store._history.append(entry)
        return store

    def save(self, path: str | Path) -> None:
        """Serialize the current history buffer to JSON."""
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(list(self._history), fh, indent=2)
        except (PermissionError, OSError):
            pass

    # ------------------------------------------------------------------
    # Core ops
    # ------------------------------------------------------------------

    def record(self, host: str, tool_name: str) -> None:
        """Append a new request record."""
        self._history.append({
            "ts": datetime.now(timezone.utc).timestamp(),
            "host": host,
            "tool": tool_name,
        })

    def count_host(self, host: str) -> int:
        """Count requests to *host* inside the sliding window."""
        now: float = datetime.now(timezone.utc).timestamp()
        cutoff: float = now - self._window_seconds
        return sum(
            1 for e in self._history
            if e["host"] == host and e["ts"] >= cutoff
        )

    def list_recent(self, host: str) -> list[dict]:
        """Return recent request records for *host* (newest first)."""
        now: float = datetime.now(timezone.utc).timestamp()
        cutoff: float = now - self._window_seconds
        return [
            e for e in reversed(self._history)
            if e["host"] == host and e["ts"] >= cutoff
        ]


# ---------------------------------------------------------------------------
# Policy checks
# ---------------------------------------------------------------------------

def check_rate_limit(
    host: str,
    request_history: list[dict],
    threshold: int = DEFAULT_RATE_THRESHOLD,
) -> dict:
    """Check whether the number of requests to *host* exceeds the threshold.

    Args:
        host: The target host (e.g. ``example.com``).
        request_history: A list of ``{"ts": float, "host": str, "tool": str}`` dicts.
                         May be the raw list from :meth:`RateLimitStore.list_recent`.
        threshold: Maximum allowed requests within the window (default 3).

    Returns:
        A dict with keys ``violation`` (bool), ``count``, ``threshold``,
        ``host``, and ``recent_tools``.
    """
    count: int = len(request_history)
    recent_tools: list[str] = [e.get("tool", "unknown") for e in request_history]

    return {
        "violation": count > threshold,
        "count": count,
        "threshold": threshold,
        "host": host,
        "recent_tools": recent_tools,
    }


def check_delegation_violation(tool_name: str, tool_type: str = "") -> dict:
    """Warn if the coordinator is running a specialist tool directly.

    Args:
        tool_name: The tool being invoked.
        tool_type: Optional category hint (e.g. ``scanner``, ``exploitation``).

    Returns:
        A dict with ``violation`` (bool), ``tool_name``, and ``reason``.
    """
    violation: bool = False
    reason: str = ""

    normalized: str = tool_name.strip().lower()

    if normalized in {t.strip().lower() for t in SPECIALIST_TOOL_NAMES}:
        violation = True
        reason = (
            f"Tool '{tool_name}' is classified as a specialist tool. "
            "The coordinator should delegate this to a specialist agent "
            "rather than running it directly."
        )
    elif tool_type and tool_type.lower() in {"scanner", "exploitation", "fuzzer"}:
        violation = True
        reason = (
            f"Tool type '{tool_type}' suggests specialist work. "
            "Consider delegating to an appropriate specialist agent."
        )

    return {
        "violation": violation,
        "tool_name": tool_name,
        "tool_type": tool_type,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Nudge generation
# ---------------------------------------------------------------------------

def generate_nudge(violation_type: str, details: dict) -> str:
    """Generate a human-readable warning / nudge for the coordinator.

    Args:
        violation_type: One of ``rate_limit`` or ``delegation``.
        details: Dict returned by the corresponding check function.

    Returns:
        A markdown-formatted warning string.
    """
    if violation_type == "rate_limit":
        return (
            f"**RATE LIMIT WARNING**: `{details['count']}` requests to "
            f"`{details['host']}` (limit: `{details['threshold']}`).\n\n"
            "*Recent tools used:* " + ", ".join(
                f"`{t}`" for t in details.get("recent_tools", [])
            ) + "\n\n"
            "**Suggested action**: Slow down, rotate user-agents, "
            "or delegate to a specialist agent with rate-limit awareness."
        )

    if violation_type == "delegation":
        return (
            f"**DELEGATION NUDGE**: `{details['tool_name']}` is a specialist tool.\n\n"
            f"_Reason_: {details.get('reason', '')}\n\n"
            "**Suggested action**: Spawn the appropriate specialist agent "
            "(e.g. `recon_specialist`, `sqli_specialist`) instead of "
            "running this tool directly."
        )

    return f"**UNKNOWN VIOLATION** (`{violation_type}`): {json.dumps(details, indent=2)}"


# ---------------------------------------------------------------------------
# Main guard function
# ---------------------------------------------------------------------------

def guard_check(tool_call: dict, history: list[dict]) -> dict:
    """Evaluate a single tool call against all guard policies.

    This is the primary entry-point used by the coordinator before
    executing (or allowing) any tool invocation.

    Args:
        tool_call: A dict describing the proposed tool call::

            {
                "tool_name": str,
                "host": str,          # target host
                "tool_type": str,     # optional: scanner, exploitation, etc.
                "args": dict,         # optional: tool arguments
            }

        history: Raw request-history list for rate-limit checks.
                 Can be obtained via ``RateLimitStore.list_recent(host)``.

    Returns:
        A dict with keys::

            {
                "allowed": bool,              # False if hard violation
                "warning": str | None,        # severity message
                "nudge": str | None,          # human-readable guidance
                "delegation_prompt": str | None,  # ready-to-use delegation prompt
            }
    """
    tool_name: str = tool_call.get("tool_name", "")
    host: str = tool_call.get("host", "")
    tool_type: str = tool_call.get("tool_type", "")

    result: dict = {
        "allowed": True,
        "warning": None,
        "nudge": None,
        "delegation_prompt": None,
    }

    # --- 1. Rate-limit check ---
    if host:
        rate_check: dict = check_rate_limit(host, history)
        if rate_check["violation"]:
            result["allowed"] = False
            result["warning"] = (
                f"RATE LIMIT EXCEEDED for {host}: "
                f"{rate_check['count']}/{rate_check['threshold']}"
            )
            result["nudge"] = generate_nudge("rate_limit", rate_check)

    # --- 2. Delegation check ---
    deleg_check: dict = check_delegation_violation(tool_name, tool_type)
    if deleg_check["violation"]:
        # Delegation is a soft violation: warn but still allow
        result["warning"] = (
            (result["warning"] + "\n" if result["warning"] else "")
            + f"DELEGATION VIOLATION: {tool_name}"
        )
        result["nudge"] = generate_nudge("delegation", deleg_check)
        result["delegation_prompt"] = (
            f"Spawn a specialist agent to run `{tool_name}` against `{host}`. "
            f"Reason: {deleg_check.get('reason', '')}"
        )

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_host_from_args(args: dict) -> str:
    """Best-effort host extraction from common tool argument keys."""
    for key in ("host", "url", "target", "domain", "u", "-u"):
        val: Any = args.get(key)
        if val:
            return str(val).split("://")[-1].split("/")[0]
    return ""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    """Run an interactive demo of the guard."""
    store: RateLimitStore = RateLimitStore()

    # Simulate some history
    for i in range(4):
        store.record("example.com", "nmap")

    print("=== Coordinator Guard Demo ===\n")

    tool_call: dict = {
        "tool_name": "sqlmap",
        "host": "example.com",
        "tool_type": "exploitation",
        "args": {"-u": "http://example.com/search?q=test"},
    }

    history: list[dict] = store.list_recent("example.com")
    result: dict = guard_check(tool_call, history)

    print(f"Tool call: {json.dumps(tool_call, indent=2)}")
    print(f"\nGuard result:\n{json.dumps(result, indent=2)}")
    print(f"\n--- Nudge ---\n{result.get('nudge', 'None')}")

    # Demonstrate rate-limit bypass
    print("\n=== Rate-limit bypass after cooling ===\n")
    # In real usage we'd wait; for demo we clear history
    store._history.clear()
    result2: dict = guard_check(tool_call, store.list_recent("example.com"))
    print(f"After clearing history — allowed: {result2['allowed']}")
    print(f"Nudge: {result2.get('nudge')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
