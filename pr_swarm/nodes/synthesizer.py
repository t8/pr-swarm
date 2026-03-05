from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel

from pr_swarm.models import Action, Finding, ReviewResult, Severity
from pr_swarm.state import ReviewState

SYSTEM_PROMPT = """You are the final synthesizer for a PR security review system.
You receive findings from multiple specialist agents and must produce a final verdict.

Your job:
1. Deduplicate overlapping findings (same file + similar description = one finding)
2. Validate severity levels are appropriate
3. Determine the final action (APPROVE, REQUEST_CHANGES, or BLOCK)
4. Write a concise summary (max 280 chars)

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
    """Merge all findings, deduplicate, apply severity logic, emit ReviewResult."""
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
You may upgrade the action (e.g., REQUEST_CHANGES → BLOCK) but never downgrade it.

Return the deduplicated findings, final action, summary (max 280 chars), and block_reason if blocking."""),
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
        parts.append(f"- [{f.severity.value}] ({f.agent}){cwe} {loc}: {f.description}")
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
