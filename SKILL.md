---
name: mastermind-bug-bounty
description: >
  Autonomous bug bounty orchestration skill based on the Mastermind Hooks Architecture
  from trace37 labs. Maps 6 Claude Code hooks (Context Injector, Coordinator Guard,
  Triage Gate, Worklog Recorder, Retry Detector, Handoff Saver) to Kimi workflow patterns.
  Enforces session lifecycle management, pre-tool gating, post-tool learning,
  retry logic, state handoff, and HackerOne-grade output quality. Triggers on any
  bug bounty, vulnerability assessment, security testing, PoC generation, or
  WAF bypass task.
---

# Mastermind Bug Bounty — Autonomous Offensive Security Orchestration

## Skill Overview

This skill recreates the **Mastermind Hooks Architecture** (6 Claude Code hooks) as
executable Kimi workflow patterns. It provides world-class offensive security
automation with persistent memory, triage gates, and session continuity.
    - mastermind-guard (coordinator-guard)
    - bug-triage-gate (triage-gate)
    - hunt-learning (worklog-recorder)
    - agent-retry-detector (retry-detector)
    - hunt-handoff (handoff-saver)
```

---

## 1. Architecture Overview

This skill implements the **Mastermind Hooks Architecture** from trace37 labs as a set of Kimi-executable workflow patterns. The architecture divides a bug bounty session into 6 gated lifecycle hooks, each enforcing specific checks, outputs, and decision trees.

### Lifecycle Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MASTERMIND BUG BOUNTY LIFECYCLE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   SESSION START          PRE-TOOL              TOOL              POST-TOOL  │
│   ─────────────          ────────              ────              ─────────  │
│                                                                             │
│   ┌──────────┐      ┌──────────┐           ┌────────┐       ┌──────────┐  │
│   │ Context  │      │ Coordinator│          │ Caido  │       │ Worklog  │  │
│   │ Injector │  →   │ Guard    │  ──────→  │ Nuclei │  ───→ │ Recorder │  │
│   │          │      │ (soft)   │           │ Agent  │       │          │  │
│   └──────────┘      └──────────┘           └────────┘       └──────────┘  │
│        │                  │                      │                 │       │
│        │             ┌──────────┐                │          ┌──────────┐   │
│        │             │ Triage   │                │          │ Retry    │   │
│        │             │ Gate     │                │          │ Detector │   │
│        │             │ (hard)   │                │          │          │   │
│        │             └──────────┘                │          └──────────┘   │
│        │                  │                      │                 │       │
│        ▼                  ▼                      ▼                 ▼       │
│   ┌──────────────────────────────────────────────────────────────────┐     │
│   │                         HANDOFF (on /compact or end)             │     │
│   │  Serialize: targets + findings + agent status + next steps       │     │
│   │  Output: Obsidian handoff document for next session              │     │
│   └──────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Hook Type Reference

| Hook | Type | File | Gate Type | Action |
|------|------|------|-----------|--------|
| 1. session-start | SESSION | `.hooks/session-start.py` | N/A | Context injection |
| 2. mastermind-guard | PRE-TOOL | `.hooks/mastermind-guard.py` | SOFT WARN | Nudge, don't block |
| 3. bug-triage-gate | PRE-TOOL | `.hooks/bug-triage-gate.py` | HARD GATE | Block or approve |
| 4. hunt-learning | POST-TOOL | `.hooks/hunt-learning.py` | WRITE-ONLY | Append log |
| 5. agent-retry-detector | POST-TOOL | `.hooks/agent-retry-detector.py` | WRITE-ONLY | Retry + log |
| 6. hunt-handoff | COMPACT | `.hooks/hunt-handoff.py` | WRITE-ONLY | Serialize state |

---

## 2. Hook 1: Context Injector — Session-Start Checklist

**Type**: SESSION | **Trigger**: PreSession / Resume / Compaction

### 2.1 When It Fires

Run this checklist at the **beginning of every bug bounty task** — whether a new session, a resumed session after interruption, or a compaction event. This replaces the `session-start.py` hook.

### 2.2 Mandatory Session-Start Checklist

Execute in strict order. Do not skip steps.

```
□ 1. LOAD HUNT LEDGER
     └─> Read /mnt/agents/data/hunt-ledger.jsonl (or equivalent)
     └─> Extract: active targets, scope, in-scope domains, program rules
     └─> If file not found: create new ledger with timestamp and session_id

□ 2. LOAD ACTIVE HUNT STATE
     └─> Check for existing active hunt in ledger
     └─> If ACTIVE: read full hunt state (targets, findings-in-progress, agent assignments)
     └─> If NO ACTIVE hunt: start new hunt entry, prompt user for target/scope

□ 3. LOAD OBSIDIAN VAULT HANDOFF
     └─> Check /mnt/agents/data/obsidian/handoff.md for handoff from previous session
     └─> If handoff exists: extract agent status, pending tasks, next steps
     └─> Mark handoff as CONSUMED after reading

□ 4. INJECT LAST 30 MINUTES OF WORKLOG
     └─> Read /mnt/agents/data/worklog.jsonl (last 30 min by timestamp)
     └─> Summarize: tools called, agents spawned, findings status, errors encountered
     └─> Present summary to user for context confirmation

□ 5. SET SESSION MARKER
     └─> Write session_start entry to worklog with timestamp and session_id
     └─> Format: {"event": "session_start", "type": "new|resume|compaction",
         "session_id": "<uuid>", "timestamp": "<ISO8601>", "hunt_id": "<active_hunt>"}

□ 6. CONFIRM CONTEXT WITH USER
     └─> Display: active target(s), hunt status, last action taken
     └─> Ask: "Resume hunt on <target>? [Y/n/change target]"
```

### 2.3 Decision Tree: Session Type

```
                    SESSION START
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
        NEW           RESUME      COMPACTION
        ───           ──────      ──────────
          │              │             │
          ▼              ▼             ▼
    ┌──────────┐   ┌──────────┐  ┌──────────┐
    │ Create   │   │ Load     │  │ Load     │
    │ new hunt │   │ hunt     │  │ compacted│
    │ ledger   │   │ state    │  │ context  │
    │ entry    │   │ + handoff│  │ only     │
    └────┬─────┘   └────┬─────┘  └────┬─────┘
         │              │             │
         └──────────────┼─────────────┘
                        ▼
                 ┌──────────┐
                 │ Inject   │
                 │ 30-min   │
                 │ worklog  │
                 └────┬─────┘
                      ▼
                 ┌──────────┐
                 │ Set      │
                 │ session  │
                 │ marker   │
                 └────┬─────┘
                      ▼
                 ┌──────────┐
                 │ Confirm  │
                 │ with user│
                 └──────────┘
```

### 2.4 Outputs to Produce

| Output | Format | Destination | Required |
|--------|--------|-------------|----------|
| Session start record | JSON | `worklog.jsonl` append | YES |
| Context summary | Markdown | Display to user | YES |
| Handoff consumed flag | Boolean | Update `handoff.md` header | If handoff exists |
| Hunt state loaded | In-memory | Session context | YES |

### 2.5 Worklog Entry Format (Session Start)

```json
{
  "timestamp": "2025-01-15T09:00:00Z",
  "session_id": "sess_abc123",
  "event": "session_start",
  "session_type": "resume",
  "hunt_id": "hunt_20250114_x",
  "target": "example.com",
  "context_injected": {
    "worklog_entries_last_30min": 12,
    "handoff_consumed": true,
    "active_findings": 2,
    "pending_agents": 1
  }
}
```

---

## 3. Hook 2: Coordinator Guard — Pre-Tool Delegation Rules

**Type**: PRE-TOOL | **Trigger**: Before every tool call | **Gate**: SOFT WARN

### 3.1 When It Fires

Before **every tool call** during a bug bounty session. This replaces `mastermind-guard.py`. This is a SOFT gate — it warns and nudges but **does not block** execution.

### 3.2 Guard Checks (Run in Order)

#### Check 1: Host Rate-Limiting (3-Request Rule)

```
COUNT requests to same host in last 5 minutes
    │
    ├─── >= 6 requests ──► HARD WARNING: "Rate limit risk. Rotate agents or pause."
    │
    ├─── 4-5 requests ───► MEDIUM WARNING: "Approaching threshold. Consider rotating."
    │
    ├─── 3 requests ─────► SOFT NUDGE: "3 requests to <host>. Delegate to specialist?"
    │
    └─── < 3 requests ───► PASS
```

#### Check 2: Skill File Reading Without Delegation

```
IF reading a specialist SKILL.md (e.g., xss-hunter, ssli-digger, ssrf-probe)
    AND no specialist agent has been spawned for that skill
        │
        ├─── First occurrence ──► SOFT NUDGE: "Reading <skill>. Spawn specialist agent?"
        │
        ├─── Second occurrence ► MEDIUM WARNING: "Coordinator bypassing delegation.
        │                            Spawn <skill> specialist."
        │
        └─── Third+ occurrence  ► HARD WARNING: "Anti-pattern detected.
                                     Coordinator should not replace specialists."
```

#### Check 3: Tool Appropriateness for Coordinator Role

```
IF coordinator attempts:
    - Direct exploitation (not reconnaissance)
    - Payload generation without specialist
    - Report writing without triage approval
        │
        └───► HARD WARNING: "Coordinator role violation.
              Delegate to appropriate specialist agent."
```

### 3.3 Warning Levels

| Level | Action | Visual Prefix | Next Step |
|-------|--------|---------------|-----------|
| SOFT NUDGE | Suggest, don't block | `[NUDGE]` | Log nudge, continue if overridden |
| MEDIUM WARNING | Strong recommendation | `[WARN]` | Log warning, suggest alternative |
| HARD WARNING | Critical alert | `[ALERT]` | Log alert, require explicit override to continue |

### 3.4 Delegation Prompt Template

When a guard check triggers, use this format:

```
[GUARD: <check_name> | Level: <level>]

Observation: <what triggered the guard>

Recommendation: <specific action>

Options:
  [1] Delegate to specialist: "@<specialist-agent> <task>"
  [2] Continue with override (log reason)
  [3] Pause and reassess strategy

Worklog: Guard event will be recorded regardless of choice.
```

### 3.5 Outputs to Produce

| Output | Format | Destination | Required |
|--------|--------|-------------|----------|
| Guard event | JSON | `worklog.jsonl` append | YES |
| Warning/nudge message | Text | Display to user | If triggered |
| Override reason | Text | Log if user overrides | If overridden |

### 3.6 Worklog Entry Format (Guard Event)

```json
{
  "timestamp": "2025-01-15T09:05:00Z",
  "session_id": "sess_abc123",
  "event": "guard_trigger",
  "hook": "mastermind-guard",
  "check": "host_rate_limiting",
  "level": "soft_nudge",
  "target_host": "api.example.com",
  "request_count_last_5min": 3,
  "action_taken": "delegated_to_recon_agent",
  "overridden": false
}
```

---

## 4. Hook 3: Bug Triage Gate — Multi-Stage Triage Workflow

**Type**: PRE-TOOL | **Trigger**: Before reporting any finding | **Gate**: HARD GATE

### 4.1 When It Fires

Before **any finding is promoted to reportable status**. A finding must pass the triage gate before PoC generation, manual proof capture, H1 report drafting, or Caido recording can begin. This replaces `bug-triage-gate.py`. This is a HARD gate — it **blocks** execution until the finding is approved.

### 4.2 Triage Stages (Sequential, Must Pass All)

```
FINDING DETECTED
       │
       ▼
┌──────────────┐
│  STAGE 1     │  ► Automated Detection Validation
│  Automated   │
│  Validation  │
└──────┬───────┘
       │
       ├── FAIL ──► Discard or re-run scan
       │
       └── PASS ──► ▼
              ┌──────────────┐
              │  STAGE 2     │  ► Manual Verification
              │  Manual      │     Confirm vulnerability exists
              │  Verification│     and is not a false positive
              └──────┬───────┘
                     │
                     ├── FAIL ──► Log false positive, update rules
                     │
                     └── PASS ──► ▼
                            ┌──────────────┐
                            │  STAGE 3     │  ► Impact Assessment
                            │  Impact      │     Demonstrate real-world impact
                            │  Assessment  │     (data exfil, privilege escalation,
                            └──────┬───────┘      account takeover, etc.)
                                   │
                                   ├── FAIL ──► Downgrade severity or discard
                                   │
                                   └── PASS ──► ▼
                                          ┌──────────────┐
                                          │  STAGE 4     │  ► Confidence Threshold
                                          │  Confidence  │     >= 80% confidence
                                          │  Threshold   │     required for approval
                                          └──────┬───────┘
                                                 │
                                                 ├── FAIL ──► Return to Stage 2
                                                 │
                                                 └── PASS ──► ▼
                                                        ┌──────────────┐
                                                        │   APPROVED   │
                                                        │  ► Trigger   │
                                                        │    full chain│
                                                        └──────────────┘
```

### 4.3 Stage 1: Automated Detection Validation

**Objective**: Confirm the automated tool result is not a false positive from scanning artifacts.

```
□ Re-run the detection test at least once
□ Verify the vulnerability exists on a different endpoint or parameter
□ Check if the result is consistent across multiple requests
□ Confirm no WAF evasion artifacts are triggering false positives
□ Validate against known-good baselines if available
```

**Pass Criteria**: Detection is reproducible on at least 2 distinct requests.

### 4.4 Stage 2: Manual Verification

**Objective**: Human-level confirmation that the vulnerability is real and exploitable.

```
□ Manually craft a minimal request that triggers the vulnerability
□ Verify the response contains expected indicators of the vulnerability
□ Test with benign input to confirm baseline behavior
□ Test with malicious input to confirm deviation
□ Document: endpoint, parameter, payload, expected vs actual response
□ Screenshot or terminal capture as proof
```

**Pass Criteria**: Manual reproduction succeeds with clear evidence.

### 4.5 Stage 3: Impact Assessment

**Objective**: Demonstrate real-world security impact beyond mere detection.

```
□ Identify the specific impact category:
    ├── Data Exfiltration
    ├── Authentication Bypass
    ├── Privilege Escalation
    ├── Account Takeover
    ├── Remote Code Execution
    ├── Stored/Reflected XSS with demonstrated impact
    ├── SQL Injection with data extraction
    ├── SSRF accessing internal resources
    ├── CORS misconfiguration with credential theft
    ├── OAuth flow manipulation
    ├── Prototype Pollution → RCE chain
    └── Other: ___________________

□ Quantify impact where possible (data accessible, systems reachable)
□ Identify affected users/systems scope
□ Determine if authentication is required (higher impact if unauthenticated)
□ Assess CVSS components: AV, AC, PR, UI, S, C, I, A
```

**Pass Criteria**: At least one concrete impact demonstrated (not theoretical).

### 4.6 Stage 4: Confidence Threshold

**Objective**: Ensure sufficient confidence before triggering the reporting pipeline.

```
□ Calculate confidence score (0-100%):
    ├── Reproducibility:     ___/25 (reliable reproduction?)
    ├── Impact clarity:      ___/25 (clear impact demonstrated?)
    ├── Scope confirmation:  ___/25 (in-scope target?)
    ├── Uniqueness check:    ___/25 (not duplicate of known finding?)
    └── TOTAL:               ___/100

□ REQUIREMENT: Score >= 80% to pass

□ If score < 80%:
    ├── 60-79%: Return to Stage 2 (improve verification)
    ├── 40-59%: Return to Stage 1 (re-run detection)
    └── < 40%:  Reject finding, log as "insufficient evidence"
```

### 4.7 Approved Finding: Full Chain Trigger

Once a finding passes all 4 stages, **automatically trigger** in order:

```
TRIAGE APPROVED
       │
       ├──► 1. PoC GENERATION
       │      └─> Generate minimal, reproducible proof-of-concept
       │      └─> Include: exact request, payload, step-by-step reproduction
       │      └─> Output: PoC document (Markdown)
       │
       ├──► 2. MANUAL PROOF CAPTURE
       │      └─> Screenshot or terminal capture showing exploitation
       │      └─> Annotate: where to look, what proves the vulnerability
       │      └─> Output: Proof files (PNG/MP4/TXT)
       │
       ├──► 3. HACKERONE REPORT DRAFT
       │      └─> Draft full HackerOne report from template
       │      └─> Include: Title, Summary, Steps to Reproduce, Impact, PoC
       │      └─> Output: H1 report draft (Markdown)
       │
       └──► 4. CAIDO RECORDING
              └─> Record the full request/response chain in Caido
              └─> Tag: finding ID, severity, status
              └─> Export: Caido collection for attachment
```

### 4.8 Outputs to Produce

| Output | Format | Destination | Required |
|--------|--------|-------------|----------|
| Triage decision record | JSON | `worklog.jsonl` append | YES |
| Stage completion log | JSON | `worklog.jsonl` append | Per stage |
| PoC document | Markdown | `findings/<id>/poc.md` | On approval |
| Proof files | PNG/MP4/TXT | `findings/<id>/proof/` | On approval |
| H1 report draft | Markdown | `findings/<id>/h1-report.md` | On approval |
| Caido export | Caido format | `findings/<id>/caido-export/` | On approval |

### 4.9 Worklog Entry Format (Triage Gate)

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "session_id": "sess_abc123",
  "event": "triage_gate",
  "hook": "bug-triage-gate",
  "finding_id": "find_001",
  "vulnerability_type": "SQL Injection",
  "target": "https://example.com/api/search",
  "stages": {
    "stage1_automated_validation": "pass",
    "stage2_manual_verification": "pass",
    "stage3_impact_assessment": "pass",
    "stage4_confidence": 85
  },
  "decision": "approved",
  "confidence_score": 85,
  "severity": "high",
  "impact": "unauthenticated_data_exfiltration",
  "chain_triggered": ["poc_generation", "manual_proof", "h1_draft", "caido_record"]
}
```

---

## 5. Hook 4: Worklog Recorder — Mandatory Action Logging

**Type**: POST-TOOL | **Trigger**: After every tool call | **Pattern**: WRITE-ONLY append

### 5.1 When It Fires

After **every tool call** — scans, Caido requests, agent spawns, skill invocations, findings, errors, guard triggers, triage events, handoffs. This replaces `hunt-learning.py`. This is **strictly write-only**: append-only, never read during normal operation.

### 5.2 Mandatory Logging Rules

Every tool call MUST produce a worklog entry. No exceptions.

```
LOG EVERY:
  □ Tool call (any tool)
  □ Agent spawn / delegation
  □ Agent conclusion / result
  □ Finding detection
  □ Triage gate event
  □ Guard trigger
  □ Session start / end
  □ Handoff save / load
  □ Error or failure
  □ User override of guard/triage
  □ Retry event

NEVER SKIP:
  □ Errors (log the error, don't hide it)
  □ Negative results ("no vulnerability found" is data)
  □ User cancellations
  □ Tool timeouts
```

### 5.3 Dual-Channel Logging

Every event is logged to **both** channels simultaneously:

#### Channel A: Machine-Readable (JSONL)

- **File**: `worklog.jsonl` (newline-delimited JSON)
- **Format**: Single-line JSON per event
- **Purpose**: Machine parsing, automated analysis, state reconstruction
- **Rule**: Append only, never modify existing lines

#### Channel B: Human-Readable (Obsidian Worklog)

- **File**: `obsidian/worklog.md` (Markdown with frontmatter)
- **Format**: Timestamped Markdown entries with headers
- **Purpose**: Human review, session handoff, context injection
- **Rule**: Append new sections, never delete old content

### 5.4 JSONL Entry Schema

Every JSONL entry MUST include:

```json
{
  "timestamp": "<ISO8601>",
  "session_id": "<uuid>",
  "event": "<event_type>",
  "hook": "<hook_name>",
  "agent_id": "<agent_id or 'coordinator'>",
  "tool": "<tool_name>",
  "target": "<target_host_or_url>",
  "status": "success|failure|blocked|warning",
  "duration_ms": 0,
  "details": {},
  "metadata": {
    "finding_id": null,
    "severity": null,
    "confidence": null
  }
}
```

### 5.5 Obsidian Worklog Entry Format

```markdown
---
timestamp: 2025-01-15T10:30:00Z
session_id: sess_abc123
event: tool_call
agent: coordinator
tool: nuclei_scan
---

## 10:30:00 — nuclei_scan on example.com

**Status**: ✅ success
**Duration**: 4500ms
**Target**: https://example.com

### Input
```yaml
target: https://example.com
templates: [cves, vulnerabilities, exposed-panels]
rate_limit: 150
```

### Output Summary
- Templates executed: 47
- Findings: 2 (INFO: 1, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)
- Errors: 0

### Related
- Finding: find_002 (CORS Misconfiguration, MEDIUM)
- Agent: coordinator → delegated to cors-probe specialist
```

### 5.6 Event Types Registry

| Event Type | Description | Required Fields in `details` |
|-----------|-------------|------------------------------|
| `session_start` | New session begins | `session_type`, `hunt_id` |
| `session_end` | Session ends | `reason`, `handoff_saved` |
| `tool_call` | Any tool executed | `tool`, `input_summary` |
| `agent_spawn` | Specialist agent created | `agent_type`, `task` |
| `agent_result` | Agent returns conclusion | `conclusion`, `findings_count` |
| `finding_detected` | New vulnerability found | `finding_id`, `type`, `severity` |
| `triage_gate` | Triage decision made | `decision`, `confidence_score` |
| `guard_trigger` | Coordinator guard fired | `check`, `level`, `action_taken` |
| `handoff_save` | Handoff document written | `hunt_id`, `next_steps` |
| `handoff_load` | Handoff document consumed | `hunt_id`, `handoff_age_hours` |
| `retry_event` | Agent retry initiated | `original_agent`, `retry_reason` |
| `error` | Any error or failure | `error_type`, `message` |

### 5.7 Outputs to Produce

| Output | Format | Destination | Required |
|--------|--------|-------------|----------|
| JSONL entry | JSON (1 line) | `worklog.jsonl` append | YES |
| Markdown entry | Markdown | `obsidian/worklog.md` append | YES |
| Session summary | Markdown | Display to user | On request |

---

## 6. Hook 5: Retry Detector — Premature Surrender Detection

**Type**: POST-TOOL | **Trigger**: After every agent response | **Pattern**: WRITE-ONLY append + retry signal

### 6.1 When It Fires

After **every specialist agent response**. Pattern-matches agent conclusions for premature surrender phrases and anti-patterns. This replaces `agent-retry-detector.py`. When triggered, sends the agent back with bypass suggestions and logs the event.

### 6.2 Premature Surrender Patterns

Match agent conclusion text against these pattern categories:

#### Pattern Category A: Defeatist Language

```
TRIGGER PHRASES (case-insensitive):
  - "WAF detected" / "blocked by WAF" / "WAF is blocking"
  - "appears secure" / "seems secure" / "looks secure"
  - "no vulnerability found" (after < 5 attempts)
  - "cannot bypass" / "unable to bypass"
  - "protection is in place" / "protected by"
  - "gave up" / "stopping here" / "aborting"
  - "too difficult" / "not feasible"
  - "rate limited, stopping"
  - "requires manual testing" (without specific reason)
  - "out of scope" (without verification)
```

#### Pattern Category B: Insufficient Effort

```
TRIGGER CONDITIONS:
  - Agent returned after < 3 tool calls
  - Agent returned with no findings and no detailed reasoning
  - Agent returned with generic conclusion (copy-paste pattern)
  - Agent skipped standard methodology steps
  - Agent did not test all in-scope parameters/endpoints
```

#### Pattern Category C: Bypassable Obstacles

```
TRIGGER CONDITIONS:
  - "Captcha detected" → but no attempt to bypass or route around
  - "Rate limited" → but no attempt to throttle or distribute
  - "Token required" → but no attempt to extract or replay
  - "CSRF token" → but no attempt to harvest or bypass
  - "Cloudflare" → but no attempt with cloudflare-bypass techniques
  - "403 Forbidden" → but no attempt with 403-bypass techniques
  - "CORS blocked" → but no attempt with CORS misconfiguration testing
```

### 6.3 Retry Decision Tree

```
AGENT RETURNS CONCLUSION
           │
           ▼
    ┌──────────────┐
    │ Pattern      │
    │ Match?       │
    └──────┬───────┘
           │
     ┌─────┴─────┐
     ▼           ▼
   YES          NO
     │           │
     ▼           ▼
┌──────────┐  ┌──────────┐
│ RETRY    │  │ ACCEPT   │
│          │  │          │
│ Log +    │  │ Log +    │
│ Retry    │  │ Continue │
└────┬─────┘  └──────────┘
     │
     ▼
┌──────────────────────────────────────────┐
│  RETRY STRATEGY SELECTION                │
│                                          │
│  Based on pattern category:              │
│                                          │
│  A: Defeatist    → Inject bypass         │
│     Language       technique references  │
│                                          │
│  B: Insufficient → Expand scope,         │
│     Effort         more tool calls       │
│                                          │
│  C: Bypassable   → Specific bypass       │
│     Obstacles      instructions          │
└──────────────────────────────────────────┘
```

### 6.4 Retry Injection Messages

When retrying, prepend specific bypass guidance based on the surrender pattern:

#### For WAF-Related Surrender:

```
[RETRY: WAF Bypass Required]

Previous conclusion cited WAF blocking. Before giving up:

1. Try alternative payloads from references/waf-bypass-payloads.md
2. Rotate User-Agent and headers (see references/header-rotation.md)
3. Use encoding: URL, double-URL, HTML entity, Unicode normalization
4. Attempt via different HTTP methods (POST, PUT, PATCH)
5. Try parameter pollution: ?id=1&id=<payload>
6. Use chunked transfer encoding if supported
7. Test via HTTP/1.0 or HTTP/2 protocol switching
8. Attempt path normalization: //admin/../test

DO NOT return until at least 3 distinct bypass techniques have been attempted.
```

#### For "Appears Secure" Surrender:

```
[RETRY: Insufficient Testing Depth]

Previous conclusion was "appears secure" after minimal testing. Required:

1. Test ALL parameters (URL, body, headers, cookies)
2. Test ALL HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS)
3. Test with authentication both present and absent
4. Test edge cases: null bytes, oversized input, Unicode, emoji
5. Test chained vulnerabilities (e.g., XSS → CSRF → ATO)
6. Review references/<vuln-type>-methodology.md for missed vectors

Minimum 10 distinct test vectors required before concluding "secure".
```

#### For Bypassable Obstacles:

```
[RETRY: <Obstacle Type> Bypass Required]

Previous conclusion cited <obstacle> without bypass attempts.

1. See references/<obstacle>-bypass.md for specific techniques
2. Try at least 3 documented bypass methods
3. If all fail, document each attempt with evidence
4. Only then may you conclude the obstacle is blocking
```

### 6.5 Retry Limits

```
MAX_RETRIES_PER_AGENT = 3

Retry 1: Full retry with bypass instructions
Retry 2: Expanded scope with additional techniques
Retry 3: Final attempt with all remaining techniques

After 3 retries: Accept conclusion, log as "max retries reached",
                 flag for manual review in handoff document.
```

### 6.6 Outputs to Produce

| Output | Format | Destination | Required |
|--------|--------|-------------|----------|
| Retry event log | JSON | `worklog.jsonl` append | YES |
| Retry instruction | Text | Send to agent | On trigger |
| Surrender pattern log | JSON | `worklog.jsonl` append | On trigger |
| Max retry flag | Boolean | Handoff document | If max reached |

### 6.7 Worklog Entry Format (Retry Event)

```json
{
  "timestamp": "2025-01-15T11:00:00Z",
  "session_id": "sess_abc123",
  "event": "retry_event",
  "hook": "agent-retry-detector",
  "original_agent": "xss-hunter-001",
  "retry_count": 1,
  "max_retries": 3,
  "trigger_pattern": "WAF detected",
  "pattern_category": "defeatist_language",
  "retry_strategy": "waf_bypass",
  "bypass_instructions_sent": [
    "url_encoding",
    "header_rotation",
    "parameter_pollution"
  ],
  "original_conclusion": "WAF is blocking all XSS payloads",
  "status": "retrying"
}
```

---

## 7. Hook 6: Handoff Saver — State Serialization

**Type**: COMPACT | **Trigger**: `/compact` with custom instructions, or session end | **Pattern**: WRITE-ONLY

### 7.1 When It Fires

On **session end** (explicit or implicit), or when `/compact` is invoked with custom instructions. Serializes the full hunt state for the next session. This replaces `hunt-handoff.py`.

### 7.2 Serialization Checklist

```
□ 1. COLLECT ACTIVE TARGETS
     └─> List all in-scope targets being tested
     └─> Include: URL, current test phase, last-tested endpoint

□ 2. COLLECT FINDINGS IN PROGRESS
     └─> For each finding: ID, type, severity, triage stage, next action
     └─> Flag findings awaiting triage approval
     └─> Flag findings with PoC pending

□ 3. COLLECT AGENT STATUS
     └─> For each active agent: ID, type, current task, last output, retry count
     └─> Mark completed agents
     └─> Flag agents that hit max retries

□ 4. COLLECT NEXT STEPS
     └─> Priority-ordered list of next actions
     └─> Include: target, test type, estimated effort

□ 5. CAPTURE CUSTOM INSTRUCTIONS
     └─> Any user-provided context for next session
     └─> New targets, scope changes, program-specific notes

□ 6. SERIALIZE TO OBSIDIAN
     └─> Write to: obsidian/handoff.md
     └─> Include all collected state + timestamp + session_id

□ 7. MARK HANDOFF READY
     └─> Update header: status: READY (not CONSUMED)
```

### 7.3 Handoff Document Template

```markdown
---
type: hunt-handoff
status: READY
session_id: sess_abc123
hunt_id: hunt_20250114_x
created_at: 2025-01-15T12:00:00Z
previous_session_duration: 3h24m
---

# Hunt Handoff: example.com Bug Bounty

## Active Targets

| Target | Phase | Last Tested | Notes |
|--------|-------|-------------|-------|
| https://example.com/api | Authentication testing | /api/v1/login | OAuth flow in progress |
| https://admin.example.com | Reconnaissance | /admin/dashboard | Admin panel discovered |

## Findings In Progress

### find_001 — SQL Injection (HIGH)
- **Status**: Triage approved, PoC generated
- **Next**: Manual proof capture, H1 report draft
- **Location**: /api/search?q=

### find_002 — CORS Misconfiguration (MEDIUM)
- **Status**: Stage 3 (impact assessment)
- **Next**: Demonstrate credential theft impact
- **Location**: /api/user (Origin header reflection)

## Agent Status

| Agent ID | Type | Status | Task | Retries |
|----------|------|--------|------|---------|
| sql-digger-001 | SQL Injection | COMPLETED | Found 1 SQLi | 0 |
| cors-probe-001 | CORS Testing | ACTIVE | Impact assessment | 0 |
| xss-hunter-001 | XSS Testing | RETRYING | WAF bypass attempts | 1/3 |

## Next Steps (Priority Order)

1. [HIGH] Complete manual proof capture for find_001
2. [HIGH] Draft H1 report for find_001
3. [MEDIUM] Complete impact assessment for find_002
4. [MEDIUM] Continue xss-hunter-001 retry (WAF bypass)
5. [LOW] Begin recon on admin.example.com
6. [LOW] Test OAuth flow for authorization issues

## Custom Instructions for Next Session

- Focus on authenticated attack surface first
- New scope addition: *.example.com (wildcard confirmed in program rules)
- Program rewards up to $5000 for RCE, $2000 for SQLi
- Avoid automated scanners on /api/v1/payments (rate limit sensitive)
```

### 7.4 Handoff Lifecycle States

```
┌─────────┐     Session loads      ┌──────────┐
│  READY  │ ──────────────────────►│ CONSUMED │
│ (saved) │     Context Injector   │ (loaded) │
└─────────┘                        └──────────┘
                                          │
                                          │ Session ends
                                          ▼
                                    ┌──────────┐
                                    │  READY   │
                                    │ (saved)  │
                                    └──────────┘
```

### 7.5 Outputs to Produce

| Output | Format | Destination | Required |
|--------|--------|-------------|----------|
| Handoff document | Markdown | `obsidian/handoff.md` | YES |
| Handoff event log | JSON | `worklog.jsonl` append | YES |
| Session end record | JSON | `worklog.jsonl` append | YES |

### 7.6 Worklog Entry Format (Handoff)

```json
{
  "timestamp": "2025-01-15T12:00:00Z",
  "session_id": "sess_abc123",
  "event": "handoff_save",
  "hook": "hunt-handoff",
  "hunt_id": "hunt_20250114_x",
  "targets_count": 2,
  "findings_in_progress": 2,
  "active_agents": 3,
  "session_duration_minutes": 204,
  "next_steps_count": 6,
  "handoff_file": "obsidian/handoff.md",
  "status": "ready_for_next_session"
}
```

---

## 8. Session Lifecycle Summary

### Complete Lifecycle Checklist

```
[SESSION START]
  □ Run Context Injector checklist (Hook 1)
  □ Confirm context with user
  □ Set session marker in worklog

[PRE-TOOL]
  □ Run Coordinator Guard checks (Hook 2)
    ├── Host rate-limiting check
    ├── Skill file reading check
    └── Tool appropriateness check
  □ Run Bug Triage Gate if reporting finding (Hook 3)
    ├── Stage 1: Automated validation
    ├── Stage 2: Manual verification
    ├── Stage 3: Impact assessment
    └── Stage 4: Confidence threshold

[TOOL EXECUTES]
  □ Execute tool (Caido, Nuclei, Agent, etc.)
  □ Capture raw output

[POST-TOOL]
  □ Run Worklog Recorder (Hook 4)
    ├── Write JSONL entry
    └── Write Obsidian entry
  □ Run Retry Detector on agent responses (Hook 5)
    ├── Pattern-match conclusion
    ├── Retry if premature surrender detected
    └── Log retry event

[REPEAT PRE-TOOL → TOOL → POST-TOOL for each action]

[SESSION END / COMPACT]
  □ Run Handoff Saver (Hook 6)
    ├── Collect targets, findings, agents, next steps
    ├── Write Obsidian handoff document
    └── Log handoff event
  □ Write session end record to worklog
```

---

## 9. Reference Files

Detailed methodologies are maintained in the `references/` directory:

| File | Description | Used By |
|------|-------------|---------|
| `references/session-management.md` | Detailed session lifecycle management | Hook 1, Hook 6 |
| `references/coordinator-guard-rules.md` | Complete guard rules and thresholds | Hook 2 |
| `references/triage-methodology.md` | Full 4-stage triage process with examples | Hook 3 |
| `references/worklog-format-spec.md` | JSONL and Markdown format specifications | Hook 4 |
| `references/retry-patterns.md` | Complete premature surrender pattern library | Hook 5 |
| `references/waf-bypass-payloads.md` | WAF evasion payloads by category | Hook 5 |
| `references/header-rotation.md` | HTTP header rotation strategies | Hook 5 |
| `references/vulnerability-classes.md` | All supported vulnerability types | All hooks |
| `references/hackerone-report-template.md` | H1 report format and best practices | Hook 3 (Stage 4) |
| `references/cvss-scoring-guide.md` | CVSS v3.1 scoring methodology | Hook 3 (Stage 3) |
| `references/agent-specialists.md` | Specialist agent types and capabilities | Hook 2, Hook 5 |
| `references/bypass-techniques/403-bypass.md` | 403 Forbidden bypass methods | Hook 5 |
| `references/bypass-techniques/cloudflare-bypass.md` | Cloudflare-specific techniques | Hook 5 |
| `references/bypass-techniques/cors-bypass.md` | CORS misconfiguration exploitation | Hook 5 |
| `references/bypass-techniques/rate-limit-bypass.md` | Rate limit evasion strategies | Hook 5 |

---

## 10. Scripts and Automation

Automation tools are maintained in the `scripts/` directory:

| Script | Description | Trigger |
|--------|-------------|---------|
| `scripts/session-init.sh` | Initialize new session, load context | Session start |
| `scripts/worklog-append.py` | Append entry to JSONL and Markdown worklogs | Every tool call |
| `scripts/guard-check.py` | Run coordinator guard checks | Pre-tool |
| `scripts/triage-gate.py` | Execute 4-stage triage workflow | Pre-report |
| `scripts/retry-detector.py` | Pattern-match agent conclusions | Post-agent |
| `scripts/handoff-save.py` | Serialize hunt state to Obsidian | Session end |
| `scripts/worklog-query.py` | Query worklog by time/agent/event | Context injection |
| `scripts/ledger-update.py` | Update hunt ledger entries | Various |

---

## 11. Output Quality Standards

### 11.1 HackerOne Report Requirements

All reports drafted through Hook 3 (Triage Gate) Stage 4 MUST meet these standards:

```
□ TITLE FORMAT
  └─> "<Vulnerability Type> on <Endpoint> leads to <Impact>"
  └─> Example: "SQL Injection on /api/search leads to unauthenticated data exfiltration"

□ SUMMARY (3-5 sentences)
  └─> What the vulnerability is
  └─> Where it exists (specific endpoint + parameter)
  └─> What an attacker can achieve
  └─> Why it matters (business impact)

□ STEPS TO REPRODUCE
  └─> Numbered, step-by-step instructions
  └─> Exact URLs, parameters, and payloads
  └─> Assumptions clearly stated (browser, authentication level)
  └─> Expected behavior vs actual behavior
  └─> Minimum 3 steps, maximum 15 steps

□ PROOF OF CONCEPT
  └─> Complete HTTP request (method, URL, headers, body)
  └─> Complete HTTP response showing vulnerability
  └─> Annotated screenshot or terminal output
  └─> PoC script if applicable (Python, curl, etc.)

□ IMPACT
  └─> Specific impact (not "could lead to" — state what IS possible)
  └─> Affected users/systems
  └─> Attack prerequisites (unauthenticated vs authenticated)
  └─> CVSS v3.1 vector string and score

□ MITIGATION
  └─> Specific remediation advice
  └─> Reference to relevant OWASP/CWE guidance

□ METADATA
  └─> Weakness: CWE-ID and name
  └─> Severity: CVSS score + severity level
  └─> Attack vector: Network / Adjacent / Local / Physical
  └─> Scope: Changed / Unchanged
```

### 11.2 CVSS Scoring Guide

| Severity | Score Range | Typical Indicators |
|----------|-------------|-------------------|
| Critical | 9.0 - 10.0 | RCE, unauth ATO, mass data breach |
| High | 7.0 - 8.9 | SQLi with data extraction, auth bypass |
| Medium | 4.0 - 6.9 | XSS (stored/reflected), CSRF, IDOR limited |
| Low | 0.1 - 3.9 | Info disclosure, missing headers, verbose errors |
| None | 0.0 | No security impact |

### 11.3 PoC Quality Standards

| Criterion | Requirement |
|-----------|-------------|
| Reproducibility | Anyone can reproduce in < 5 minutes |
| Minimalism | Only includes necessary steps/payloads |
| Clarity | Annotated screenshots for every critical step |
| Self-contained | Includes all required tools/configurations |
| Safe | Does not cause denial of service or data destruction |

---

## 12. Quick Reference: Hook-to-Action Mapping

| Hook | Kimi Pattern | When to Run | Action |
|------|-------------|-------------|--------|
| 1. session-start | Session-start checklist | Every session start/resume | Load context, inject worklog |
| 2. mastermind-guard | Pre-tool guard checks | Before every tool call | Rate-limit check, delegation nudge |
| 3. bug-triage-gate | 4-stage triage workflow | Before reporting any finding | Validate, verify, assess, approve |
| 4. hunt-learning | Dual-channel logging | After every tool call | Append JSONL + Obsidian entry |
| 5. agent-retry-detector | Pattern-match + retry | After every agent response | Detect surrender, inject bypasses |
| 6. hunt-handoff | State serialization | Session end or /compact | Write handoff document |

---

## 13. Metadata and Versioning

```yaml
skill_version: 1.0.0
last_updated: 2025-01-15
architecture: mastermind-hooks-v1
compatible_platforms: [kimi, claude-code]
source: https://labs.trace37.com/blog/mastermind-hooks-architecture/
hooks_implemented: 6/6
  - session-start: context-injector ✓
  - mastermind-guard: coordinator-guard ✓
  - bug-triage-gate: triage-gate ✓
  - hunt-learning: worklog-recorder ✓
  - agent-retry-detector: retry-detector ✓
  - hunt-handoff: handoff-saver ✓
```

---

*End of SKILL.md — mastermind-bug-bounty v1.0.0*
