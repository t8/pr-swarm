from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel

from pr_swarm.models import Action, Finding, ReviewResult, Severity, Triage
from pr_swarm.state import ReviewState

SYSTEM_PROMPT = """You are the final synthesizer for a PR security review system.
You receive findings from multiple specialist agents and must produce a final verdict.

Your job:
1. Deduplicate overlapping findings (same file + similar description = one finding)
2. Validate severity levels are appropriate
3. Classify each finding into a triage tier:
   - ACTION_REQUIRED: Findings that must be fixed before merge. Security vulnerabilities, leaked secrets, breaking changes, critical bugs.
   - FOR_REVIEW: Findings worth human review but not necessarily blocking. Architecture concerns, coverage gaps, potential issues that depend on context.
   - INFORMATIONAL: Low-priority suggestions, style nits, and observations. Useful but safe to skip.
4. Determine the final action (APPROVE, REQUEST_CHANGES, or BLOCK)
5. Write a concise summary (max 280 chars)

Triage guidelines:
- CRITICAL/HIGH severity from secrets_scanner → always ACTION_REQUIRED
- CRITICAL severity → always ACTION_REQUIRED
- HIGH severity → ACTION_REQUIRED unless the finding is clearly a false positive in context
- MEDIUM severity → FOR_REVIEW by default, ACTION_REQUIRED if in a sensitive path
- LOW severity → INFORMATIONAL by default, FOR_REVIEW if it's a genuine code quality issue
- INFO severity → always INFORMATIONAL
- Findings about CI config, naming, or style → INFORMATIONAL unless they're security-relevant

Escalation rules (MUST follow):
- Any CRITICAL or HIGH finding from secrets_scanner → BLOCK
- Any CRITICAL finding → BLOCK
- Any HIGH finding → REQUEST_CHANGES (or BLOCK based on context)
- Any MEDIUM finding → REQUEST_CHANGES
- Only LOW or INFO findings → APPROVE

If action is BLOCK, you MUST provide a block_reason."""


class SynthesizedResult(BaseModel):
    action: Action
    summary: str
    block_reason: str | None = None
    deduplicated_findings: list[Finding]


def synthesizer(state: ReviewState) -> dict:
    """Merge all findings, deduplicate, apply severity logic and triage, emit ReviewResult."""
    all_findings = _collect_findings(state)
    errors = state.get("errors", [])

    if not all_findings:
        return {
            "review_result": ReviewResult(
                action=Action.APPROVE,
                findings=[],
                summary="No issues found. LGTM!",
            )
        }

    deterministic_action = _determine_action(all_findings)
    _apply_default_triage(all_findings)

    try:
        llm = ChatAnthropic(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            timeout=25.0,
        )
        structured_llm = llm.with_structured_output(SynthesizedResult)

        findings_text = _format_findings_for_llm(all_findings)
        result = structured_llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=f"""Synthesize these findings into a final review verdict.

## All Findings ({len(all_findings)} total)
{findings_text}

## Errors during analysis
{_format_errors(errors)}

The deterministic escalation logic suggests: {deterministic_action.value}
You may upgrade the action (e.g., REQUEST_CHANGES -> BLOCK) but never downgrade it.

For each finding, set the triage field to ACTION_REQUIRED, FOR_REVIEW, or INFORMATIONAL.

Return the deduplicated findings with triage set, final action, summary (max 280 chars), and block_reason if blocking."""),
        ])

        if result:
            final_action = _enforce_minimum_action(result.action, deterministic_action)
            return {
                "review_result": ReviewResult(
                    action=final_action,
                    findings=result.deduplicated_findings,
                    summary=result.summary[:280],
                    block_reason=result.block_reason if final_action == Action.BLOCK else None,
                )
            }
    except Exception:
        pass

    return {
        "review_result": ReviewResult(
            action=deterministic_action,
            findings=all_findings,
            summary=_auto_summary(all_findings, deterministic_action),
            block_reason=_auto_block_reason(all_findings) if deterministic_action == Action.BLOCK else None,
        )
    }


def _collect_findings(state: ReviewState) -> list[Finding]:
    findings = []
    for key in ["security_findings", "architecture_findings", "coverage_findings", "secrets_findings", "style_findings"]:
        findings.extend(state.get(key, []))
    return findings


def _apply_default_triage(findings: list[Finding]) -> None:
    """Apply deterministic default triage based on severity and agent."""
    for f in findings:
        if f.agent == "secrets_scanner" and f.severity in (Severity.CRITICAL, Severity.HIGH):
            f.triage = Triage.ACTION_REQUIRED
        elif f.severity == Severity.CRITICAL:
            f.triage = Triage.ACTION_REQUIRED
        elif f.severity == Severity.HIGH:
            f.triage = Triage.ACTION_REQUIRED
        elif f.severity == Severity.MEDIUM:
            f.triage = Triage.FOR_REVIEW
        elif f.severity == Severity.LOW:
            f.triage = Triage.INFORMATIONAL
        elif f.severity == Severity.INFO:
            f.triage = Triage.INFORMATIONAL


def _determine_action(findings: list[Finding]) -> Action:
    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.agent == "secrets_scanner":
            return Action.BLOCK
    for f in findings:
        if f.severity == Severity.CRITICAL:
            return Action.BLOCK
    for f in findings:
        if f.severity == Severity.HIGH:
            return Action.REQUEST_CHANGES
    for f in findings:
        if f.severity == Severity.MEDIUM:
            return Action.REQUEST_CHANGES
    return Action.APPROVE


def _enforce_minimum_action(llm_action: Action, deterministic_action: Action) -> Action:
    priority = {Action.APPROVE: 0, Action.REQUEST_CHANGES: 1, Action.BLOCK: 2}
    if priority.get(llm_action, 0) >= priority.get(deterministic_action, 0):
        return llm_action
    return deterministic_action


def _format_findings_for_llm(findings: list[Finding]) -> str:
    parts = []
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        cwe = f" [{f.cwe_id}]" if f.cwe_id else ""
        parts.append(f"- [{f.severity.value}] ({f.agent}){cwe} {loc}: {f.description} [default triage: {f.triage.value}]")
    return "\n".join(parts)


def _format_errors(errors: list[dict]) -> str:
    if not errors:
        return "None"
    return "\n".join(f"- [{e.get('agent', 'unknown')}] {e.get('error', '')}" for e in errors)


def _auto_summary(findings: list[Finding], action: Action) -> str:
    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    parts = [f"{v} {k}" for k, v in counts.items()]
    return f"{action.value}: {', '.join(parts)} finding(s) across {len({f.agent for f in findings})} agent(s)"[:280]


def _auto_block_reason(findings: list[Finding]) -> str:
    critical = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if critical:
        return critical[0].description[:200]
    return "Critical findings detected"
