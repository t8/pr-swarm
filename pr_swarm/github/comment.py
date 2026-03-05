from __future__ import annotations

from pr_swarm.models import Action, Finding, ReviewResult, Severity, Triage

TRIAGE_ORDER = [Triage.ACTION_REQUIRED, Triage.FOR_REVIEW, Triage.INFORMATIONAL]

TRIAGE_HEADERS = {
    Triage.ACTION_REQUIRED: "Action Required",
    Triage.FOR_REVIEW: "For Review",
    Triage.INFORMATIONAL: "Informational",
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def format_review_body(result: ReviewResult, elapsed_seconds: float) -> str:
    """Format the top-level review body (summary + triage-grouped findings)."""
    action_label = result.action.value
    agent_count = len({f.agent for f in result.findings})
    finding_count = len(result.findings)

    action_counts = _count_by_triage(result.findings)
    action_required = action_counts.get(Triage.ACTION_REQUIRED, 0)

    lines = [
        f"## PR Security Review -- {action_label}",
        "",
        f"**{finding_count} finding{'s' if finding_count != 1 else ''}** "
        f"across {agent_count} agent{'s' if agent_count != 1 else ''} "
        f"| {action_required} action required "
        f"| reviewed in {elapsed_seconds:.0f}s",
    ]

    if result.block_reason:
        lines.extend(["", f"> **Block reason:** {result.block_reason}"])

    grouped = _group_by_triage(result.findings)
    for triage in TRIAGE_ORDER:
        findings = grouped.get(triage, [])
        if not findings:
            continue
        header = TRIAGE_HEADERS[triage]
        lines.extend(["", f"### {header} ({len(findings)})"])
        by_severity = _sort_by_severity(findings)
        for f in by_severity:
            lines.append(_format_finding(f))

    lines.extend([
        "",
        "---",
        f"<sub>pr-swarm v1.0 | {elapsed_seconds:.0f}s</sub>",
    ])
    return "\n".join(lines)


def format_review_comment(result: ReviewResult, elapsed_seconds: float) -> str:
    """Legacy: format as a single comment body."""
    return format_review_body(result, elapsed_seconds)


def build_inline_comments(
    findings: list[Finding],
    valid_files: set[str] | None = None,
) -> list[dict]:
    """Build GitHub PR review inline comment objects from findings.

    Returns a list of dicts with keys: path, line, body.
    Only includes findings that have both a file and line number.
    If valid_files is provided, only includes findings for those files.
    """
    comments = []
    for f in findings:
        if not f.line or not f.file or f.file == "(overall)":
            continue
        if valid_files is not None and f.file not in valid_files:
            continue

        severity_badge = f"**{f.severity.value}**"
        triage_badge = f"`{f.triage.value}`"
        cwe = f" [{f.cwe_id}]" if f.cwe_id else ""

        body_parts = [f"{severity_badge} | {triage_badge}{cwe}"]
        body_parts.append(f"{f.description}")
        body_parts.append(f"*— {f.agent}*")
        if f.suggestion:
            body_parts.append(f"\n> **Suggestion:** {f.suggestion}")

        comments.append({
            "path": f.file,
            "line": f.line,
            "body": "\n\n".join(body_parts),
        })
    return comments


def _group_by_triage(findings: list[Finding]) -> dict[Triage, list[Finding]]:
    grouped: dict[Triage, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.triage, []).append(f)
    return grouped


def _count_by_triage(findings: list[Finding]) -> dict[Triage, int]:
    counts: dict[Triage, int] = {}
    for f in findings:
        counts[f.triage] = counts.get(f.triage, 0) + 1
    return counts


def _sort_by_severity(findings: list[Finding]) -> list[Finding]:
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda f: order.get(f.severity, 99))


def _format_finding(f: Finding) -> str:
    location = f.file
    if f.line:
        location = f"{f.file}:{f.line}"

    cwe = f" [{f.cwe_id}]" if f.cwe_id else ""
    parts = [f"- **{f.severity.value}**{cwe} {f.description} in `{location}`"]
    parts.append(f"  {f.agent}")
    if f.suggestion:
        parts.append(f"  > {f.suggestion}")
    return "\n".join(parts)
