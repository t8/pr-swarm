# pr-swarm

Automated PR security review system built on LangGraph. Ingests GitHub pull requests, fans out analysis across 5 specialist agents in parallel, and posts a structured verdict (APPROVE / REQUEST_CHANGES / BLOCK) back to the PR.

Catches what static linters miss — architectural drift, tainted data flows, cross-file logic errors, leaked credentials — while completing reviews in under 3 minutes.

## How It Works

```
PR opened → Diff Parser → ┬─ Security Auditor ──┐
                           ├─ Secrets Scanner ───┤
                           ├─ Coverage Checker ──┼─→ Synthesizer → PR Comment + Status Check
                           ├─ Architecture Cop ──┤
                           └─ Style Checker ─────┘
```

1. **Diff Parser** extracts changed files, diffs, and PR metadata from GitHub
2. **5 specialist agents** run in parallel, each focused on a specific concern
3. **Synthesizer** merges findings, deduplicates, applies severity logic, and emits a final verdict

### Agents

| Agent | Focus | Severity Range |
|-------|-------|---------------|
| **Security Auditor** | OWASP Top 10, injection, auth issues, tainted data flows | CRITICAL–LOW |
| **Secrets Scanner** | API keys, tokens, credentials, private keys, connection strings | CRITICAL–HIGH (always blocks) |
| **Coverage Checker** | Missing tests for new code, coverage drops | MEDIUM–LOW |
| **Architecture Cop** | Layer violations, breaking changes, dependency direction | HIGH–LOW |
| **Style Checker** | Naming, dead code, minor refactors | LOW–INFO only |

### Verdict Logic

- Any secret detected → **BLOCK**
- Any CRITICAL finding → **BLOCK**
- Any HIGH or MEDIUM finding → **REQUEST_CHANGES**
- Only LOW/INFO findings → **APPROVE**

## Adding to Your Repository

### 1. Add secrets

Go to your repo's Settings → Secrets and variables → Actions, and add:
- `ANTHROPIC_API_KEY` — your Anthropic API key

(`GITHUB_TOKEN` is provided automatically by GitHub Actions.)

### 2. Create the workflow

Add `.github/workflows/pr-review.yml` to your repo:

```yaml
name: PR Security Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  checks: write
  security-events: write

concurrency:
  group: pr-review-${{ github.ref }}
  cancel-in-progress: true

jobs:
  review:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: PR Security Review
        id: review
        uses: YOUR_USER/pr-swarm@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Replace `YOUR_USER` with the GitHub user/org that hosts your pr-swarm fork.

### 3. (Optional) Add a config file

Create `.github/review-agent.yml` in your repo to customize behavior. See [Configuration](#configuration) below. If omitted, sensible defaults are used.

### Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `github-token` | Yes | — | GitHub token for comments and status checks |
| `anthropic-api-key` | Yes | — | Anthropic API key for Claude |
| `config-path` | No | `.github/review-agent.yml` | Path to config file |
| `sarif-output` | No | `pr-swarm-results.sarif` | Path to write SARIF file |
| `python-version` | No | `3.12` | Python version |
| `gitleaks-version` | No | `8.18.4` | Gitleaks version |

### Action Outputs

| Output | Description |
|--------|-------------|
| `action` | Verdict: `APPROVE`, `REQUEST_CHANGES`, or `BLOCK` |
| `findings-count` | Total number of findings |
| `sarif-file` | Path to SARIF output file |

You can use outputs in subsequent steps:

```yaml
- name: PR Security Review
  id: review
  uses: YOUR_USER/pr-swarm@main
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Fail on block
  if: steps.review.outputs.action == 'BLOCK'
  run: exit 1
```

## Local Development Setup

### Requirements

- Python 3.11+
- [Semgrep](https://semgrep.dev/) (for security scanning)
- [Gitleaks](https://github.com/gitleaks/gitleaks) (for secret detection)
- An Anthropic API key

### Install

```bash
pip install -e ".[dev,tools]"
```

### Environment Variables

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Required:
- `ANTHROPIC_API_KEY` — Claude API access
- `GITHUB_TOKEN` — GitHub API (auto-provided in GitHub Actions)

Optional:
- `DATABASE_URL` — Postgres connection for memory layer
- `LANGSMITH_API_KEY` — LangSmith tracing
- `SARIF_OUTPUT_PATH` — Path to write SARIF output

## Usage

### CLI

```bash
# Review a PR
python -m pr_swarm --repo owner/repo --pr 123

# Dry run (no GitHub posting)
python -m pr_swarm --repo owner/repo --pr 123 --dry-run

# With custom config and SARIF output
python -m pr_swarm --repo owner/repo --pr 123 \
  --config .github/review-agent.yml \
  --sarif-output results.sarif
```

### Docker

```bash
docker compose -f docker/docker-compose.yml up
```

This starts the agent and a Postgres+pgvector instance for the memory layer.

## Configuration

Create `.github/review-agent.yml` in your repo:

```yaml
sensitivity: high  # low | medium | high | paranoid

sensitive_paths:
  - auth/
  - payments/
  - infrastructure/

ignore_paths:
  - vendor/
  - '**/*.min.js'
  - '**/*.generated.*'

block_on:
  - secret_detected
  - cwe_critical

warn_on:
  pr_size_lines: 500
  coverage_drop_pct: 1.0

max_pr_lines: 2000
agent_timeout_seconds: 30
```

## Development

```bash
# Run unit tests
pytest tests/ --ignore=tests/integration

# Run integration tests (requires ANTHROPIC_API_KEY)
pytest tests/integration/ -m integration

# Lint
ruff check pr_swarm/ tests/

# Format
ruff format pr_swarm/ tests/

# Type check
mypy pr_swarm/
```

### Golden PR Fixtures

`tests/golden_prs/` contains diff fixtures with known vulnerabilities for testing:
- `sql_injection.diff` — SQL injection via string formatting
- `leaked_api_key.diff` — Hardcoded API keys and credentials
- `missing_auth.diff` — Admin endpoints without auth middleware
- `xss_vulnerability.diff` — XSS via innerHTML
- `layer_violation.diff` — UI layer importing from DB layer

## Project Structure

```
pr_swarm/
  models.py          # Pydantic models (Finding, ReviewResult, Severity, Action)
  state.py           # LangGraph ReviewState TypedDict
  graph.py           # LangGraph graph definition + run_review() entrypoint
  config.py          # YAML config loader
  nodes/             # One file per agent node
  tools/             # External tool wrappers (semgrep, gitleaks, coverage, AST)
  github/            # GitHub API client, comment formatting, SARIF output
  memory/            # Postgres+pgvector episodic and semantic memory
```
