from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CoverageReport:
    total_coverage_pct: float
    file_coverage: dict[str, float] = field(default_factory=dict)
    uncovered_lines: dict[str, list[int]] = field(default_factory=dict)


def parse_coverage_json(report_path: str) -> CoverageReport | None:
    """Parse a coverage.py JSON report."""
    path = Path(report_path)
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    totals = data.get("totals", {})
    total_pct = totals.get("percent_covered", 0.0)

    file_coverage: dict[str, float] = {}
    uncovered_lines: dict[str, list[int]] = {}

    for file_path, file_data in data.get("files", {}).items():
        summary = file_data.get("summary", {})
        file_coverage[file_path] = summary.get("percent_covered", 0.0)
        missing = file_data.get("missing_lines", [])
        if missing:
            uncovered_lines[file_path] = missing

    return CoverageReport(
        total_coverage_pct=total_pct,
        file_coverage=file_coverage,
        uncovered_lines=uncovered_lines,
    )


def parse_jest_coverage(report_path: str) -> CoverageReport | None:
    """Parse a Jest JSON coverage summary."""
    path = Path(report_path)
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    total = data.get("total", {})
    total_pct = total.get("lines", {}).get("pct", 0.0)

    file_coverage: dict[str, float] = {}
    for file_path, file_data in data.items():
        if file_path == "total":
            continue
        file_coverage[file_path] = file_data.get("lines", {}).get("pct", 0.0)

    return CoverageReport(
        total_coverage_pct=total_pct,
        file_coverage=file_coverage,
    )


def compute_coverage_delta(
    before: CoverageReport | None,
    after: CoverageReport | None,
) -> float:
    """Compute the coverage delta between two reports. Negative = drop."""
    if before is None or after is None:
        return 0.0
    return after.total_coverage_pct - before.total_coverage_pct


def find_untested_new_functions(
    changed_files: list[str],
    coverage: CoverageReport | None,
) -> dict[str, list[int]]:
    """Find lines in changed files that are not covered by tests."""
    if coverage is None:
        return {}

    result: dict[str, list[int]] = {}
    for f in changed_files:
        uncovered = coverage.uncovered_lines.get(f, [])
        if uncovered:
            result[f] = uncovered
    return result
