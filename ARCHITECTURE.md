# PR Security Review Agent — Architecture, Specification & Execution Plan

**Version:** 1.0
**Date:** March 2026
**Status:** Pre-build

---

## 1. Executive Summary

This document is the comprehensive build spec for **pr-swarm**, an automated PR security review system built on LangGraph. It ingests GitHub pull requests, fans out analysis across five specialist agents running in parallel, synthesizes their typed findings, and posts a structured verdict (APPROVE / REQUEST_CHANGES / BLOCK) back to the PR.

The system is designed to catch what static linters miss — architectural drift, tainted data flows, cross-file logic errors, leaked credentials — while completing reviews in under 3 minutes and never blocking developer velocity.

This spec incorporates the original system context document, my review of its claims, and corrections where needed.

---

## 2. Problem Statement & Motivation

Manual PR review is inconsistent and doesn't scale. The core gaps this system fills:

- **Security blind spots:** Static linters catch syntax-level issues but miss semantic vulnerabilities like tainted data flows crossing trust boundaries, insecure deserialization patterns, or auth bypass via logic errors.
- **AI-generated code risk:** As AI-assisted coding grows, developers tend to review AI-generated code with lower scrutiny. This system applies consistent standards regardless of authorship.
- **Review fatigue:** Human reviewers lose effectiveness on large PRs. The system doesn't get tired.
- **Compliance audit trail:** Every finding is logged with timestamps, tool versions, and agent reasoning — useful for SOC 2, ISO 27001, or internal compliance.

### Design Constraints

1. Reviews must complete in **under 3 minutes** on average (with graceful degradation for large PRs).
2. All output must be **typed and structured** — no free-form prose verdicts.
3. Must be **configurable per repo/team** via a checked-in YAML file.
4. Must integrate into **existing GitHub PR workflows** with zero extra steps for developers.
5. Must maintain a **full audit trail** of every finding for compliance.

---

## 3. Architecture

### 3.1 Execution Pattern

The system uses a **parallel fan-out → synthesis** pattern:

```
┌─────────────────────────────┐
│        PR TRIGGER           │
│  (GitHub Actions webhook)   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│        DIFF PARSER          │
│  Extracts files, diffs,     │
│  context, PR metadata       │
└─────────────┬───────────────┘
              │ fan-out (parallel edges)
    ┌─────────┼─────────┬─────────┬──────────┐
    ▼         ▼         ▼         ▼          ▼
┌────────┐┌────────┐┌────────┐┌────────┐┌────────┐
│Security││Arch    ││Test    ││Secrets ││Style & │
│Auditor ││Cop     ││Coverage││Scanner ││Best    │
│        ││        ││Checker ││        ││Practice│
└───┬────┘└───┬────┘└───┬────┘└───┬────┘└───┬────┘
    └─────────┴─────────┴─────────┴──────────┘
              │ fan-in
              ▼
┌─────────────────────────────┐
│       SYNTHESIZER           │
│  Merges findings, applies   │
│  severity tiers, emits      │
│  ReviewResult               │
└─────────────┬───────────────┘
              │
              ▼
    APPROVE / REQUEST_CHANGES / BLOCK
    (posted as PR comment + status check)
```

### 3.2 Why Parallel Fan-Out (Not Sequential)

Sequential execution would mean a 5× latency multiplier. Since the specialist agents are independent — the Security Auditor doesn't need the Architecture Cop's output — they run concurrently. LangGraph supports this natively via **conditional edges** from the Diff Parser node to all five specialist nodes, with a fan-in edge collecting results into the Synthesizer.

**Important note:** The original spec references "ParallelNode" — this is not an actual LangGraph construct. LangGraph achieves parallelism through its graph edge topology. When multiple nodes share the same upstream dependency, LangGraph executes them concurrently within a single "superstep." No special node class is needed.

---

## 4. Agent Specifications

### 4.1 Shared State Schema

All agents read from and write to a shared `ReviewState` TypedDict:

```python
from typing import TypedDict, Optional
from pydantic import BaseModel, Field
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Action(str, Enum):
    APPROVE = "APPROVE"
    REQUEST_CHANGES = "REQUEST_CHANGES"
    BLOCK = "BLOCK"

class Finding(BaseModel):
    severity: Severity
    agent: str
    file: str
    line: Optional[int] = None
    description: str
    cwe_id: Optional[str] = None  # e.g., "CWE-89" for SQL injection
    suggestion: Optional[str] = None

class ReviewResult(BaseModel):
    action: Action
    findings: list[Finding]
    summary: str = Field(max_length=280)
    block_reason: Optional[str] = None  # required if action == BLOCK

class ParsedDiff(BaseModel):
    files: list[dict]        # {path, status, additions, deletions, patch}
    additions: list[str]     # all added lines
    deletions: list[str]     # all removed lines
    context: dict            # PR title, description, labels, linked issues
    metadata: dict           # author, base branch, head branch, repo

class ReviewState(TypedDict):
    parsed_diff: Optional[ParsedDiff]
    config: dict                        # loaded from .github/review-agent.yml
    security_findings: list[Finding]
    architecture_findings: list[Finding]
    coverage_findings: list[Finding]
    secrets_findings: list[Finding]
    style_findings: list[Finding]
    review_result: Optional[ReviewResult]
    errors: list[dict]                  # agent-level errors for debugging
```

### 4.2 Agent Detail

#### Diff Parser

| Property | Value |
|----------|-------|
| **Input** | GitHub webhook payload (PR number, repo) |
| **Tools** | GitHub REST API (via `PyGithub` or `httpx`) |
| **Output** | `ParsedDiff` written to `state["parsed_diff"]` |
| **Responsibilities** | Extract changed files with full diffs, pull surrounding context (±30 lines), load PR description and linked issues, load repo config from `.github/review-agent.yml` |

The Diff Parser is deterministic — no LLM call needed. It's pure API integration and data structuring.

#### Security Auditor

| Property | Value |
|----------|-------|
| **Input** | `state["parsed_diff"]`, semantic memory (OWASP rules, CVE data) |
| **Tools** | Semgrep (primary), Bandit (Python), ESLint-security (JS/TS), Trivy/Snyk (dependency scanning) |
| **Output** | `list[Finding]` written to `state["security_findings"]` |
| **Focus Areas** | OWASP Top 10, injection vectors, auth issues, tainted data flows, insecure deserialization, dependency vulnerabilities |

The LLM layer here **reasons about tool output** — it doesn't replace the tools. Semgrep runs deterministic rules; the LLM interprets whether a Semgrep match in context is a true positive or a false positive, and generates the human-readable description and suggestion.

#### Architecture Cop

| Property | Value |
|----------|-------|
| **Input** | `state["parsed_diff"]`, repo index (module boundaries, API contracts) |
| **Tools** | AST parser (tree-sitter or Python `ast`), internal architecture index |
| **Output** | `list[Finding]` written to `state["architecture_findings"]` |
| **Focus Areas** | Breaking changes, layer violations (e.g., UI importing directly from DB layer), cross-service drift, API contract changes without migration |

This agent requires a lightweight "architecture index" — a manifest of module boundaries and allowed dependency directions. This can start as a simple YAML file in the repo and evolve into an auto-generated dependency graph.

#### Test Coverage Checker

| Property | Value |
|----------|-------|
| **Input** | `state["parsed_diff"]`, existing test index |
| **Tools** | Coverage.py (Python), Jest/c8 (JS/TS), repo test file index |
| **Output** | `list[Finding]` written to `state["coverage_findings"]` |
| **Focus Areas** | Are new functions tested? Coverage delta (did coverage drop?). Missing edge cases for complex logic. |

**Important caveat:** This agent can only check *whether tests exist* for new code, not *whether the tests are good*. It compares the set of new/modified functions against the test index. Actual coverage percentage requires running the test suite, which is too slow for the 3-minute SLA. Instead, this agent should check the latest coverage report artifact from CI and compare against the diff.

#### Secrets Scanner

| Property | Value |
|----------|-------|
| **Input** | `state["parsed_diff"]` |
| **Tools** | Gitleaks, TruffleHog, custom regex patterns |
| **Output** | `list[Finding]` written to `state["secrets_findings"]` |
| **Focus Areas** | Hardcoded credentials, API keys, tokens, PII in code/comments, high-entropy strings |

Any finding from this agent with severity >= HIGH should **always** trigger a BLOCK. There is no acceptable scenario where a leaked secret should be merged.

#### Style & Best Practices

| Property | Value |
|----------|-------|
| **Input** | `state["parsed_diff"]` |
| **Tools** | Language-specific linters (already running in CI — this agent reads their output rather than re-running) |
| **Output** | `list[Finding]` written to `state["style_findings"]` |
| **Focus Areas** | Naming conventions, dead code, comment quality, minor refactor opportunities |

This agent only emits SUGGEST-tier findings. It never blocks or warns.

#### Synthesizer

| Property | Value |
|----------|-------|
| **Input** | All five `*_findings` lists from state |
| **Tools** | None (pure reasoning) |
| **Output** | `ReviewResult` written to `state["review_result"]` |
| **Responsibilities** | Deduplicate overlapping findings, apply severity tier logic, determine final action, generate 280-char summary |

The Synthesizer enforces the output schema via Pydantic validation. If the LLM generates output that doesn't conform, validation fails and the Synthesizer retries (up to 2 retries, then falls back to REQUEST_CHANGES with an error note).

**Important note:** The original spec mentions "ActionSchema enforcement" — this is not a LangGraph API. The equivalent is Pydantic model validation combined with LangChain's `with_structured_output()` method, which constrains LLM output to match a Pydantic schema.

---

## 5. Severity Tiers & Review Logic

| Tier | Action | Trigger Conditions | Human Gate |
|------|--------|--------------------|------------|
| **BLOCK** | Merge prevented | High-severity security finding, leaked secret, failing tests, missing DB migration | **Required** before merge |
| **WARN** | Request Changes | PR > 500 lines, complexity spike, test coverage drops > 1%, architectural concern | Optional — async notify |
| **SUGGEST** | Inline comment | Naming conventions, dead code, comment quality, minor refactors | None |
| **APPROVE** | Auto-approve eligible | No findings above SUGGEST tier, all required checks pass | None |

### Escalation Logic

```
if any finding.severity in [CRITICAL, HIGH] and finding.agent == "secrets_scanner":
    action = BLOCK  # zero tolerance for leaked secrets
elif any finding.severity == CRITICAL:
    action = BLOCK
elif any finding.severity == HIGH:
    action = REQUEST_CHANGES  # could be BLOCK based on repo config
elif any finding.severity == MEDIUM:
    action = REQUEST_CHANGES
elif only LOW or INFO findings:
    action = APPROVE
```

The per-repo config can override these defaults (e.g., a repo with `sensitivity: paranoid` could BLOCK on MEDIUM findings).

---

## 6. Memory & Context Architecture

### 6.1 Three Context Tiers

| Layer | Contents | Storage | Lifetime |
|-------|----------|---------|----------|
| **Short-term (In-context)** | Current PR diff, changed files + surrounding context, PR description, linked issues | Passed directly in each agent's context window | Duration of review run |
| **Episodic (Historical)** | Past PR decisions — what the team approved/rejected and why; previous findings on similar patterns | Postgres + pgvector (semantic similarity search) | Persistent, grows with every review |
| **Semantic (Knowledge)** | OWASP rules, internal architecture docs, style guide, dependency vulnerability DB | Vector DB (Pinecone or pgvector) | Persistent, updated when docs change |
| **Procedural (Rules)** | Per-repo config: sensitive directories, blocking rules, language-specific rules | YAML config file in repo (`.github/review-agent.yml`) | Versioned with repo |

### 6.2 Context Isolation (Critical)

Each specialist agent receives **only the context relevant to its specialty.** The Security Auditor gets OWASP data and CVE context but not style history. The Style Checker gets naming conventions but not vulnerability databases. This prevents context pollution — irrelevant information degrades LLM reasoning quality.

Implementation: each agent's node function builds its own context window from the shared state, pulling only its relevant slices.

### 6.3 Cold Start Strategy

On day one there's no episodic memory. Strategy:

1. **Weeks 1–2:** Run the agent in "shadow mode" — it reviews every PR but only posts findings as a comment, never blocks. Team reviews its output and flags false positives.
2. **Weeks 3–4:** Seed the episodic memory with the shadow-mode results and team feedback.
3. **Week 5+:** Enable blocking, with the episodic memory providing historical context.

---

## 7. Security Toolchain

Each specialist agent is a **reasoning layer over deterministic tools**. The LLM reasons about tool output — it doesn't substitute for it.

| Tool | Purpose | Used By | Install |
|------|---------|---------|---------|
| **Semgrep** | Fast AST-based static analysis with custom rules. Detects injection, XSS, insecure deserialization, and custom org patterns | Security Auditor | `pip install semgrep` |
| **Bandit** | Python-specific security linting | Security Auditor | `pip install bandit` |
| **ESLint-security** | JavaScript/TypeScript security anti-patterns | Security Auditor | `npm install eslint-plugin-security` |
| **Trivy** | Dependency vulnerability scanning against CVE databases | Security Auditor | Binary install |
| **Gitleaks** | Entropy-based secret detection — API keys, tokens, credentials in code and comments | Secrets Scanner | Binary install |
| **TruffleHog** | Additional secret detection with verified secret checks | Secrets Scanner | `pip install trufflehog` |
| **Coverage.py** | Python test coverage delta calculation | Test Coverage Checker | `pip install coverage` |
| **Jest** | JavaScript test coverage | Test Coverage Checker | `npm install jest` |
| **tree-sitter** | AST parsing for architectural boundary analysis | Architecture Cop | `pip install tree-sitter` |

### Tool Execution Model

All tools run in **isolated containers** with hash-verified binaries. Tool output is logged with timestamps for audit. The LLM never executes arbitrary code from the PR — it only analyzes static output.

---

## 8. GitHub Integration & CI/CD

### 8.1 GitHub Actions Workflow

```yaml
# .github/workflows/pr-review-agent.yml
name: PR Security Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read        # read repo files
  pull-requests: write  # post review comments
  checks: write         # post check run status
  security-events: write # publish SARIF to Security tab

concurrency:
  group: pr-review-${{ github.ref }}
  cancel-in-progress: true  # cancel stale runs on new commits

jobs:
  review:
    runs-on: ubuntu-latest
    timeout-minutes: 5  # hard ceiling above the 3-min SLA
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # need full history for diff context

      - name: Run PR Review Agent
        uses: ./  # or published action reference
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          config-path: .github/review-agent.yml
```

### 8.2 Security Note on `pull_request_target`

The original spec mentions triggering on `pull_request_target`. **Use this with extreme caution.** `pull_request_target` runs with the base branch's secrets and workflow — this is necessary for reviewing forked PRs, but introduces risk if the workflow ever checks out and *executes* code from the PR head. Our agent only performs **static analysis** of the diff, never executes PR code, so this is safe *as long as that invariant is maintained.* Add a CI safeguard that prevents the workflow from ever running `npm install`, `pip install`, or any build command from the PR's source.

### 8.3 Branch Protection Rules

Configure as **required status checks** in GitHub branch protection:

- `pr-review-agent/security` — blocks on CRITICAL or HIGH findings
- `pr-review-agent/secrets` — blocks on any secret detection (zero tolerance)
- `pr-review-agent/coverage` — warns if coverage delta exceeds threshold

### 8.4 Repo-Level Configuration

```yaml
# .github/review-agent.yml
sensitivity: high  # low | medium | high | paranoid

sensitive_paths:  # raise scrutiny on these directories
  - auth/
  - payments/
  - secrets-management/
  - infrastructure/

ignore_paths:  # skip review on generated/vendor code
  - vendor/
  - migrations/auto/
  - '**/*.generated.*'
  - '**/*.min.js'

block_on:  # conditions that must cause BLOCK verdict
  - secret_detected
  - cwe_critical
  - missing_migration

warn_on:
  - pr_size_lines: 500
  - coverage_drop_pct: 1.0
  - complexity_increase: 10  # cyclomatic complexity delta

# Language-specific overrides
languages:
  python:
    tools: [semgrep, bandit, coverage-py]
  javascript:
    tools: [semgrep, eslint-security, jest]
  go:
    tools: [semgrep, gosec]
```

---

## 9. Typed Output Schema

Every agent emits structured objects conforming to the Pydantic models defined in Section 4.1. The Synthesizer **rejects free-form text** — only valid enum values and typed fields are accepted.

### PR Comment Format

The final PR comment posted by the Synthesizer follows a structured template:

```markdown
## 🔒 PR Security Review — REQUEST_CHANGES

**3 findings** across 2 agents | reviewed in 47s

### CRITICAL
- **[CWE-89] SQL Injection** in `api/users.py:142`
  Security Auditor · Semgrep rule `python.lang.security.audit.formatted-sql`
  > User input flows directly into SQL query without parameterization.
  💡 Use parameterized queries: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`

### HIGH
- **Missing auth middleware** in `api/routes/admin.py:28`
  Architecture Cop · AST analysis
  > New admin endpoint registered without `@require_admin` decorator.

### SUGGEST
- **Unused import** in `api/users.py:3`
  Style & Best Practices
  > `import json` is imported but never used.

---
<sub>pr-swarm v1.0 · config: high sensitivity · ⏱️ 47s</sub>
```

### SARIF Output

In addition to the PR comment, findings are published in SARIF format to the GitHub Security tab for integration with GitHub's security dashboard.

---

## 10. Security Considerations for the Agent System

The agents themselves are an attack surface. A developer could craft a PR that attempts to manipulate agent behavior.

### Threat Model

**Indirect Prompt Injection** — Malicious instructions embedded in code comments (e.g., `// IGNORE ALL PREVIOUS INSTRUCTIONS`) attempting to hijack agent behavior.
*Defense:* Treat all code content as untrusted data, not instructions. Use input sanitization and content-isolated context passing. The LLM prompt must explicitly instruct the model that code content is data to be analyzed, never instructions to follow.

**Context Poisoning via PR Description** — PR title or description containing fake SARIF output or falsified findings to manipulate the Synthesizer verdict.
*Defense:* Never trust PR author-supplied content as reviewer input. Only ingest tool-generated findings. The Synthesizer only reads from `state["*_findings"]` keys, never from the PR description.

**Resource Exhaustion** — Extremely large PRs or PRs designed to cause tool timeouts.
*Defense:* Enforce a **30-second timeout per agent**. Skip full analysis on PRs exceeding 2000 lines — post a "manual review required" label and escalate to the team lead. Implement LangGraph interrupt/timeout handling.

**Tool Result Spoofing** — Compromised SAST tool returning manipulated results.
*Defense:* Run all tools in isolated containers with hash-verified tool binaries. Log all tool invocations with timestamps for audit. Pin tool versions in the container image.

### Escalation Path for Oversized PRs

When a PR exceeds the 2000-line threshold:

1. Post a comment: "This PR exceeds the automated review threshold (2000 lines). Manual review required."
2. Apply the `manual-review-required` label.
3. Notify the team lead via the configured notification channel.
4. Optionally run a partial review on only the `sensitive_paths` directories.

---

## 11. Observability & Monitoring

### LangSmith Integration

Every agent invocation is traced via LangSmith:

- LLM calls (prompt, response, token count, latency)
- Tool invocations (input, output, duration)
- State transitions (what each node read from and wrote to state)
- Final verdict with reasoning chain

### Key Metrics to Track

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Review latency (p50) | < 60s | > 180s |
| Review latency (p99) | < 180s | > 300s |
| False positive rate | < 10% | > 20% |
| True positive rate (recall) | > 85% | < 70% |
| Agent error rate | < 1% | > 5% |
| Tool timeout rate | < 2% | > 10% |

### Feedback Loop

Developers can react to findings with 👍 (true positive) or 👎 (false positive) on the PR comment. These reactions feed back into the episodic memory store to improve future accuracy.

---

## 12. Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Agent framework | **LangGraph** (Python) | Stateful graph with native parallel execution, typed state, and built-in interrupt/retry |
| LLM | **Claude Sonnet** (via Anthropic API) | Strong reasoning at low latency; good at structured output |
| CI trigger | **GitHub Actions** | Native integration, no external CI needed |
| State persistence | **Postgres + pgvector** | Episodic memory with semantic search; standard, battle-tested |
| Knowledge base | **pgvector** (same Postgres) | Simplify infra — one DB for both episodic and semantic memory |
| Observability | **LangSmith** | First-party tracing for LangGraph |
| Secret management | **GitHub Actions secrets** + **1Password CLI** (optional) | API keys for Anthropic, Snyk, etc. |
| Containerization | **Docker** | Reproducible tool environment with pinned versions |
| Config | **YAML** (`.github/review-agent.yml`) | Versioned with repo, human-readable |

---

## 13. Build Roadmap & Execution Plan

### Phase 1 — Foundation (Weeks 1–3)

**Goal:** End-to-end pipeline with one specialist agent, posting to a real PR.

| Step | Task | Details | Deliverable |
|------|------|---------|-------------|
| 1.1 | **Scaffold project** | Create Python project with `pyproject.toml`, set up LangGraph, define all Pydantic models from Section 4.1 | `pr_swarm/` package with `models.py`, `graph.py` |
| 1.2 | **Build Diff Parser** | Implement GitHub API integration to extract PR diffs, context lines, metadata. No LLM needed — pure API calls | Working `diff_parser.py` that returns `ParsedDiff` |
| 1.3 | **Build Security Auditor (Semgrep only)** | Install Semgrep, write LangGraph node that runs Semgrep on changed files and returns typed `Finding` objects. LLM interprets Semgrep results for description/suggestion | Working `security_auditor.py` |
| 1.4 | **Build Synthesizer** | Implement severity tier logic, deduplication, final verdict. Enforce Pydantic output schema with `with_structured_output()` | Working `synthesizer.py` |
| 1.5 | **Wire GitHub Actions** | Create `.github/workflows/pr-review-agent.yml`, post `ReviewResult` as PR comment | PR comment appears on test repo |
| 1.6 | **Validate with known-bad PRs** | Create 5–10 test PRs with known vulnerabilities (SQL injection, XSS, leaked key, missing auth) | Test suite of "golden" PRs with expected findings |

### Phase 2 — Full Specialist Team (Weeks 4–6)

**Goal:** All five specialist agents running in parallel.

| Step | Task | Details | Deliverable |
|------|------|---------|-------------|
| 2.1 | **Add Secrets Scanner** | Integrate Gitleaks/TruffleHog, wire into graph as parallel node | `secrets_scanner.py` |
| 2.2 | **Add Test Coverage Checker** | Parse coverage reports from CI artifacts, compare against diff | `coverage_checker.py` |
| 2.3 | **Add Architecture Cop** | Implement AST parsing for boundary violations, dependency direction checks | `architecture_cop.py` |
| 2.4 | **Add Style & Best Practices** | Read linter output from CI, emit SUGGEST-tier findings | `style_checker.py` |
| 2.5 | **Implement parallel fan-out** | Wire all five agents as concurrent nodes in LangGraph graph | Updated `graph.py` with fan-out/fan-in |
| 2.6 | **Add repo-level config** | Parse `.github/review-agent.yml`, apply sensitivity overrides and path rules | `config.py` |
| 2.7 | **Branch protection integration** | Publish required status checks per the spec | Status checks appear in GitHub |
| 2.8 | **Tune noise** | Review first 50 real PRs, adjust severity thresholds, suppress false positives | Tuned Semgrep rules and severity mappings |

### Phase 3 — Memory & Learning (Weeks 7–9)

**Goal:** The system improves over time by learning from past reviews.

| Step | Task | Details | Deliverable |
|------|------|---------|-------------|
| 3.1 | **Set up Postgres + pgvector** | Database schema for episodic and semantic memory | Migration scripts, Docker Compose |
| 3.2 | **Seed semantic memory** | Embed OWASP rules, internal architecture docs, style guide | Populated vector store |
| 3.3 | **Implement episodic memory** | Store every ReviewResult with embeddings; retrieve similar past reviews during new reviews | RAG pipeline for historical context |
| 3.4 | **Add recency weighting** | Recent decisions weighted higher than old ones to prevent context pollution | Weighted retrieval in episodic queries |
| 3.5 | **Add feedback loop** | Parse 👍/👎 reactions on PR comments, update finding accuracy scores | Feedback ingestion pipeline |
| 3.6 | **Evaluate impact** | Compare precision/recall before and after memory layer | Evaluation report |

### Phase 4 — Production Hardening (Weeks 10–12)

**Goal:** Production-grade reliability, security, and observability.

| Step | Task | Details | Deliverable |
|------|------|---------|-------------|
| 4.1 | **LangSmith observability** | Trace every agent invocation, LLM call, and tool run | Dashboard with latency, error rate, token usage |
| 4.2 | **SARIF output** | Publish findings to GitHub Security tab in SARIF format | Findings appear in Security tab |
| 4.3 | **Timeout/circuit-breaker** | 30s per agent, 5-minute hard ceiling, graceful degradation on timeout | Circuit breaker middleware |
| 4.4 | **Red-team the system** | Attempt prompt injection via PR comments, code comments, PR descriptions | Security report with findings and mitigations |
| 4.5 | **Load test** | Validate 3-minute SLA at 50 concurrent PRs | Load test results |
| 4.6 | **Docker packaging** | Single container image with all tools pre-installed, hash-verified | Published Docker image |
| 4.7 | **Documentation** | README, setup guide, configuration reference, contribution guide | Docs in repo |

---

## 14. Project Structure

```
pr-swarm/
├── .github/
│   ├── workflows/
│   │   └── pr-review-agent.yml    # GitHub Actions workflow
│   └── review-agent.yml           # Default repo config (dogfood)
├── pr_swarm/
│   ├── __init__.py
│   ├── models.py                  # Pydantic models (Finding, ReviewResult, etc.)
│   ├── graph.py                   # LangGraph graph definition
│   ├── state.py                   # ReviewState TypedDict
│   ├── config.py                  # YAML config loader + validation
│   ├── nodes/
│   │   ├── __init__.py
│   │   ├── diff_parser.py         # GitHub API integration
│   │   ├── security_auditor.py    # Semgrep + Bandit + ESLint-security
│   │   ├── architecture_cop.py    # AST analysis + boundary checks
│   │   ├── coverage_checker.py    # Coverage delta analysis
│   │   ├── secrets_scanner.py     # Gitleaks + TruffleHog
│   │   ├── style_checker.py       # Linter output parsing
│   │   └── synthesizer.py         # Final verdict + PR comment
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── semgrep.py             # Semgrep runner wrapper
│   │   ├── gitleaks.py            # Gitleaks runner wrapper
│   │   ├── coverage.py            # Coverage report parser
│   │   └── ast_parser.py          # tree-sitter wrapper
│   ├── memory/
│   │   ├── __init__.py
│   │   ├── episodic.py            # Past PR decision storage/retrieval
│   │   └── semantic.py            # Knowledge base (OWASP, arch docs)
│   └── github/
│       ├── __init__.py
│       ├── api.py                 # GitHub API client
│       ├── comment.py             # PR comment formatting
│       └── sarif.py               # SARIF output generation
├── tests/
│   ├── test_models.py
│   ├── test_graph.py
│   ├── test_nodes/
│   │   └── ...                    # Unit tests per node
│   ├── golden_prs/                # Known-bad PR fixtures
│   │   ├── sql_injection.diff
│   │   ├── leaked_api_key.diff
│   │   └── ...
│   └── integration/
│       └── test_end_to_end.py
├── docker/
│   ├── Dockerfile                 # All tools pre-installed
│   └── docker-compose.yml         # Agent + Postgres for local dev
├── pyproject.toml
├── README.md
└── .env.example                   # Required environment variables
```

---

## 15. Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=           # Claude API access
GITHUB_TOKEN=                # GitHub API (provided by Actions in CI)

# Optional — Phase 3+
DATABASE_URL=                # Postgres connection string for memory layer
LANGSMITH_API_KEY=           # LangSmith tracing
LANGSMITH_PROJECT=pr-swarm

# Tool-specific
SEMGREP_APP_TOKEN=           # For Semgrep Cloud rules (optional)
SNYK_TOKEN=                  # For Snyk dependency scanning (optional)
```

---

## 16. Corrections & Notes from Review

The original system context document is well-designed. These are the corrections and clarifications incorporated into this spec:

1. **"ParallelNode" does not exist in LangGraph.** Parallel execution is achieved via graph topology (multiple edges from one node to many). No code change needed — it's just terminology.

2. **"ActionSchema enforcement" is not a LangGraph API.** Use Pydantic models + `with_structured_output()` for the same effect. This spec uses that approach throughout.

3. **The 3-minute SLA is achievable but requires timeouts.** Without per-agent timeouts, a single slow Semgrep scan on a large repo can blow the budget. This spec adds a 30-second per-agent timeout with graceful degradation.

4. **The 2000-line escalation needs a defined flow.** The original spec notes the cutoff but doesn't say what happens next. This spec defines the escalation path (label + notify + optional partial review).

5. **`pull_request_target` is security-sensitive.** This spec adds an explicit warning and safeguard about never executing PR code.

6. **The 17% statistic is unsourced.** If this is an internal metric, document the measurement methodology. If it's an external claim, find and cite the source, or remove it.

7. **Cold-start problem for episodic memory.** The original spec defers memory to Phase 3 but doesn't address day-one behavior. This spec adds a shadow-mode rollout strategy.

8. **Test Coverage Checker can't run tests within the SLA.** This spec clarifies that it reads existing CI coverage reports rather than re-running the test suite.
