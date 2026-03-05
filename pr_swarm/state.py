from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict

from pr_swarm.models import Finding, ParsedDiff, ReviewResult


class ReviewState(TypedDict):
    pr_number: int
    repo_full_name: str  # e.g. "owner/repo"
    parsed_diff: Optional[ParsedDiff]
    config: dict
    security_findings: Annotated[list[Finding], operator.add]
    architecture_findings: Annotated[list[Finding], operator.add]
    coverage_findings: Annotated[list[Finding], operator.add]
    secrets_findings: Annotated[list[Finding], operator.add]
    style_findings: Annotated[list[Finding], operator.add]
    review_result: Optional[ReviewResult]
    errors: Annotated[list[dict], operator.add]
