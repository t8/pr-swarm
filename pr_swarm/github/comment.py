from __future__ import annotations

from pr_swarm.models import Action, Finding, ReviewResult, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

ACTION_EMOJI = {
    Action.APPROVE: "APPROVE",
    Action.REQUEST_CHANGES: "REQUEST_CHANGES",
    Action.BLOCK: "BLOCK",
}


def format_review_comment(result: ReviewResult, elapsed_seconds: float) -> str:
    action_label = ACTION_EMOJI.get(result.action, str(result.action.value))
    agent_count = len({f.agent for f in result.findings})
    finding_count = len(result.findings)

    lines = [
        f"## PR Security Review -- {action_label}",
        "",
        f"**{finding_count} finding{'s' if finding_count != 1 else ''}** "
        f"across {agent_count} agent{'s' if agent_count != 1 else ''} "
        f"| reviewed in {elapsed_seconds:.0f}s",
    ]

    if result.block_reason:
        lines.extend(["", f"> **Block reason:** {result.block_reason}"])

    grouped = _group_by_severity(result.findings)
    for severity in SEVERITY_ORDER:
        findings = grouped.get(severity, [])
        if not findings:
            continue
        lines.extend(["", f"### {severity.value}"])
        for f in findings:
            lines.append(_format_finding(f))

    lines.extend([
        "",
        "---",
        f"<sub>pr-swarm v1.0 | {elapsed_seconds:.0f}s</sub>",
    ])
    return "\n".join(lines)


def _group_by_severity(findings: list[Finding]) -> dict[Severity, list[Finding]]:
    grouped: dict[Severity, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)
    return grouped


def _format_finding(f: Finding) -> str:
    location = f.file
    if f.line:
        location = f"{f.file}:{f.line}"

    cwe = f" [{f.cwe_id}]" if f.cwe_id else ""
    parts = [f"- **{cwe}{f.description}** in `{location}`"]
    parts.append(f"  {f.agent}")
    if f.suggestion:
        parts.append(f"  > {f.suggestion}")
    return "\n".join(parts)
