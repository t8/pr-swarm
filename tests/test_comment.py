from pr_swarm.github.comment import build_inline_comments, format_review_body, format_review_comment
from pr_swarm.models import Action, Finding, ReviewResult, Severity, Triage


class TestFormatReviewBody:
    def test_approve_no_findings(self):
        result = ReviewResult(action=Action.APPROVE, findings=[], summary="LGTM!")
        body = format_review_body(result, 12.5)
        assert "APPROVE" in body
        assert "0 findings" in body

    def test_block_with_findings(self):
        result = ReviewResult(
            action=Action.BLOCK,
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    agent="secrets_scanner",
                    file="config.py",
                    line=10,
                    description="API key detected",
                    suggestion="Remove and rotate",
                    triage=Triage.ACTION_REQUIRED,
                ),
            ],
            summary="Secret found",
            block_reason="Leaked API key",
        )
        body = format_review_body(result, 47.0)
        assert "BLOCK" in body
        assert "CRITICAL" in body
        assert "API key detected" in body
        assert "config.py:10" in body
        assert "Block reason" in body
        assert "Action Required" in body

    def test_request_changes_mixed(self):
        result = ReviewResult(
            action=Action.REQUEST_CHANGES,
            findings=[
                Finding(severity=Severity.HIGH, agent="security_auditor", file="a.py", line=5, description="XSS", cwe_id="CWE-79", triage=Triage.ACTION_REQUIRED),
                Finding(severity=Severity.LOW, agent="style_checker", file="b.py", description="unused import", triage=Triage.INFORMATIONAL),
            ],
            summary="2 findings",
        )
        body = format_review_body(result, 33.0)
        assert "REQUEST_CHANGES" in body
        assert "HIGH" in body
        assert "LOW" in body
        assert "CWE-79" in body
        assert "2 findings" in body
        assert "Action Required" in body
        assert "Informational" in body

    def test_triage_grouping(self):
        result = ReviewResult(
            action=Action.REQUEST_CHANGES,
            findings=[
                Finding(severity=Severity.CRITICAL, agent="security_auditor", file="a.py", description="RCE", triage=Triage.ACTION_REQUIRED),
                Finding(severity=Severity.MEDIUM, agent="architecture_cop", file="b.py", description="layer violation", triage=Triage.FOR_REVIEW),
                Finding(severity=Severity.LOW, agent="style_checker", file="c.py", description="naming", triage=Triage.INFORMATIONAL),
            ],
            summary="3 findings",
        )
        body = format_review_body(result, 20.0)
        # Verify triage sections appear in correct order
        action_pos = body.index("Action Required")
        review_pos = body.index("For Review")
        info_pos = body.index("Informational")
        assert action_pos < review_pos < info_pos

    def test_legacy_format_review_comment(self):
        result = ReviewResult(action=Action.APPROVE, findings=[], summary="clean")
        assert format_review_comment(result, 5.0) == format_review_body(result, 5.0)


class TestBuildInlineComments:
    def test_builds_inline_comments(self):
        findings = [
            Finding(severity=Severity.HIGH, agent="security_auditor", file="api/users.py", line=42, description="SQL injection", cwe_id="CWE-89", suggestion="Use parameterized queries", triage=Triage.ACTION_REQUIRED),
            Finding(severity=Severity.LOW, agent="style_checker", file="utils.py", line=10, description="unused import", triage=Triage.INFORMATIONAL),
        ]
        comments = build_inline_comments(findings)
        assert len(comments) == 2
        assert comments[0]["path"] == "api/users.py"
        assert comments[0]["line"] == 42
        assert "SQL injection" in comments[0]["body"]
        assert "CWE-89" in comments[0]["body"]
        assert "parameterized queries" in comments[0]["body"]
        assert "ACTION_REQUIRED" in comments[0]["body"]

    def test_skips_findings_without_line(self):
        findings = [
            Finding(severity=Severity.MEDIUM, agent="coverage_checker", file="(overall)", description="no tests"),
            Finding(severity=Severity.LOW, agent="style_checker", file="a.py", description="naming"),
        ]
        comments = build_inline_comments(findings)
        assert len(comments) == 0

    def test_filters_by_valid_files(self):
        findings = [
            Finding(severity=Severity.HIGH, agent="security_auditor", file="api/users.py", line=10, description="XSS"),
            Finding(severity=Severity.HIGH, agent="security_auditor", file="old_file.py", line=5, description="issue"),
        ]
        comments = build_inline_comments(findings, valid_files={"api/users.py"})
        assert len(comments) == 1
        assert comments[0]["path"] == "api/users.py"
