"""End-to-end integration tests using golden PR fixtures.

These tests require ANTHROPIC_API_KEY to be set and run the full graph pipeline
with mocked GitHub API calls. Run with: pytest tests/integration/ -m integration
"""
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pr_swarm.config import load_config
from pr_swarm.graph import compile_graph
from pr_swarm.models import Action, Severity
from pr_swarm.state import ReviewState

GOLDEN_DIR = Path(__file__).parent.parent / "golden_prs"

pytestmark = pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set",
)


def _load_golden(name: str) -> str:
    return (GOLDEN_DIR / name).read_text()


def _make_initial_state(diff_content: str, filename: str) -> ReviewState:
    from pr_swarm.models import FileDiff, ParsedDiff

    additions = [l[1:] for l in diff_content.split("\n") if l.startswith("+") and not l.startswith("+++")]

    parsed = ParsedDiff(
        files=[
            FileDiff(
                path=filename,
                status="added",
                additions=len(additions),
                deletions=0,
                patch=diff_content,
            )
        ],
        additions=additions,
        deletions=[],
        context={"title": f"Test: {filename}", "description": "Golden PR test", "labels": []},
        metadata={"author": "test", "base_branch": "main", "head_branch": "test", "repo": "test/repo"},
    )

    return {
        "pr_number": 1,
        "repo_full_name": "test/repo",
        "parsed_diff": parsed,
        "config": load_config(),
        "security_findings": [],
        "architecture_findings": [],
        "coverage_findings": [],
        "secrets_findings": [],
        "style_findings": [],
        "review_result": None,
        "errors": [],
    }


def _run_specialists_only(state: ReviewState) -> ReviewState:
    """Run the graph skipping diff_parser (we provide the diff directly)."""
    from pr_swarm.nodes.architecture_cop import architecture_cop
    from pr_swarm.nodes.coverage_checker import coverage_checker
    from pr_swarm.nodes.secrets_scanner import secrets_scanner
    from pr_swarm.nodes.security_auditor import security_auditor
    from pr_swarm.nodes.style_checker import style_checker
    from pr_swarm.nodes.synthesizer import synthesizer

    for node_fn in [security_auditor, secrets_scanner, coverage_checker, architecture_cop, style_checker]:
        result = node_fn(state)
        for k, v in result.items():
            if isinstance(v, list) and k in state:
                state[k] = state[k] + v
            else:
                state[k] = v

    result = synthesizer(state)
    state.update(result)
    return state


@pytest.mark.integration
class TestGoldenPRs:
    def test_sql_injection_detected(self):
        diff = _load_golden("sql_injection.diff")
        state = _make_initial_state(diff, "api/users.py")
        final = _run_specialists_only(state)
        result = final["review_result"]
        assert result is not None
        assert result.action in (Action.REQUEST_CHANGES, Action.BLOCK)
        security_findings = final["security_findings"]
        assert len(security_findings) > 0

    def test_leaked_secrets_blocked(self):
        diff = _load_golden("leaked_api_key.diff")
        state = _make_initial_state(diff, "config.py")
        final = _run_specialists_only(state)
        result = final["review_result"]
        assert result is not None
        assert result.action == Action.BLOCK
        secrets = final["secrets_findings"]
        assert len(secrets) > 0

    def test_missing_auth_flagged(self):
        diff = _load_golden("missing_auth.diff")
        state = _make_initial_state(diff, "api/routes/admin.py")
        final = _run_specialists_only(state)
        result = final["review_result"]
        assert result is not None
        all_findings = (
            final["security_findings"]
            + final["architecture_findings"]
            + final["coverage_findings"]
        )
        assert len(all_findings) > 0

    def test_xss_detected(self):
        diff = _load_golden("xss_vulnerability.diff")
        state = _make_initial_state(diff, "templates/profile.js")
        final = _run_specialists_only(state)
        result = final["review_result"]
        assert result is not None
        assert result.action in (Action.REQUEST_CHANGES, Action.BLOCK)
