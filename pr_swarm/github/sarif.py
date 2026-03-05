from __future__ import annotations

import json
from typing import Any

from pr_swarm.models import Finding, ReviewResult, Severity

SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SARIF_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "warning",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def generate_sarif(result: ReviewResult, tool_name: str = "pr-swarm") -> dict[str, Any]:
    rules: list[dict] = []
    results: list[dict] = []
    rule_ids: dict[str, int] = {}

    for finding in result.findings:
        rule_id = _make_rule_id(finding)
        if rule_id not in rule_ids:
            rule_ids[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": finding.description[:200]},
                "defaultConfiguration": {
                    "level": SARIF_LEVEL_MAP.get(finding.severity, "note"),
                },
                **(
                    {"helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe_id.split('-')[1]}.html"}
                    if finding.cwe_id
                    else {}
                ),
            })

        sarif_result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_ids[rule_id],
            "level": SARIF_LEVEL_MAP.get(finding.severity, "note"),
            "message": {"text": finding.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        **(
                            {
                                "region": {
                                    "startLine": finding.line,
                                }
                            }
                            if finding.line
                            else {}
                        ),
                    }
                }
            ],
        }
        if finding.suggestion:
            sarif_result["fixes"] = [
                {
                    "description": {"text": finding.suggestion},
                }
            ]
        results.append(sarif_result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "1.0.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(result: ReviewResult, output_path: str) -> None:
    sarif = generate_sarif(result)
    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)


def _make_rule_id(finding: Finding) -> str:
    if finding.cwe_id:
        return finding.cwe_id
    slug = finding.description[:50].lower().replace(" ", "-")
    slug = "".join(c for c in slug if c.isalnum() or c == "-")
    return f"{finding.agent}/{slug}"
