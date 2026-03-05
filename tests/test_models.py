import pytest
from pydantic import ValidationError

from pr_swarm.models import (
    Action,
    FileDiff,
    Finding,
    ParsedDiff,
    ReviewResult,
    Severity,
)


class TestSeverity:
    def test_all_values(self):
        assert set(Severity) == {
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        }

    def test_string_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.INFO.value == "INFO"


class TestAction:
    def test_all_values(self):
        assert set(Action) == {Action.APPROVE, Action.REQUEST_CHANGES, Action.BLOCK}


class TestFinding:
    def test_minimal(self):
        f = Finding(
            severity=Severity.HIGH,
            agent="security_auditor",
            file="api/users.py",
            description="SQL injection vulnerability",
        )
        assert f.line is None
        assert f.cwe_id is None
        assert f.suggestion is None

    def test_full(self):
        f = Finding(
            severity=Severity.CRITICAL,
            agent="security_auditor",
            file="api/users.py",
            line=142,
            description="SQL injection",
            cwe_id="CWE-89",
            suggestion="Use parameterized queries",
        )
        assert f.line == 142
        assert f.cwe_id == "CWE-89"

    def test_invalid_severity(self):
        with pytest.raises(ValidationError):
            Finding(
                severity="INVALID",
                agent="test",
                file="test.py",
                description="test",
            )


class TestReviewResult:
    def test_approve(self):
        r = ReviewResult(
            action=Action.APPROVE,
            findings=[],
            summary="LGTM!",
        )
        assert r.block_reason is None

    def test_block_with_reason(self):
        r = ReviewResult(
            action=Action.BLOCK,
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    agent="secrets_scanner",
                    file="config.py",
                    description="API key detected",
                )
            ],
            summary="Secret detected",
            block_reason="Leaked API key in config.py",
        )
        assert r.action == Action.BLOCK
        assert len(r.findings) == 1

    def test_summary_max_length(self):
        with pytest.raises(ValidationError):
            ReviewResult(
                action=Action.APPROVE,
                findings=[],
                summary="x" * 281,
            )

    def test_summary_at_max_length(self):
        r = ReviewResult(
            action=Action.APPROVE,
            findings=[],
            summary="x" * 280,
        )
        assert len(r.summary) == 280


class TestParsedDiff:
    def test_basic(self):
        d = ParsedDiff(
            files=[
                FileDiff(
                    path="api/users.py",
                    status="modified",
                    additions=10,
                    deletions=5,
                    patch="@@ -1,5 +1,10 @@\n+import os\n",
                )
            ],
            additions=["import os"],
            deletions=[],
            context={"title": "Add user auth", "description": "", "labels": []},
            metadata={"author": "dev", "base_branch": "main", "head_branch": "feature", "repo": "org/repo"},
        )
        assert len(d.files) == 1
        assert d.files[0].path == "api/users.py"
