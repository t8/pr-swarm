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
        assert "Block reason" in body
        # ACTION_REQUIRED with file+line goes inline, not in body
        assert "inline comments" in body

    def test_informational_stays_in_body(self):
        result = ReviewResult(
            action=Action.APPROVE,
            findings=[
                Finding(severity=Severity.LOW, agent="style_checker", file="b.py", line=5, description="unused import", triage=Triage.INFORMATIONAL),
            ],
            summary="minor",
        )
        body = format_review_body(result, 10.0)
        assert "Informational" in body
        assert "unused import" in body

    def test_action_required_with_line_omitted_from_body(self):
        result = ReviewResult(
            action=Action.REQUEST_CHANGES,
            findings=[
                Finding(severity=Severity.HIGH, agent="security_auditor", file="a.py", line=5, description="XSS", triage=Triage.ACTION_REQUIRED),
                Finding(severity=Severity.LOW, agent="style_checker", file="b.py", line=10, description="naming", triage=Triage.INFORMATIONAL),
            ],
            summary="2 findings",
        )
        body = format_review_body(result, 20.0)
        # XSS has line+file and is ACTION_REQUIRED, so it goes inline
        assert "XSS" not in body
        # naming is INFORMATIONAL, stays in body
        assert "naming" in body
        assert "1 finding posted as inline" in body

    def test_action_required_without_line_stays_in_body(self):
        result = ReviewResult(
            action=Action.REQUEST_CHANGES,
            findings=[
                Finding(severity=Severity.MEDIUM, agent="coverage_checker", file="(overall)", description="no tests", triage=Triage.ACTION_REQUIRED),
            ],
            summary="missing tests",
        )
        body = format_review_body(result, 15.0)
        # No line number, so it stays in body even though ACTION_REQUIRED
        assert "no tests" in body
        assert "Action Required" in body

    def test_mixed_triage_body(self):
        result = ReviewResult(
            action=Action.REQUEST_CHANGES,
            findings=[
                Finding(severity=Severity.CRITICAL, agent="security_auditor", file="a.py", line=1, description="RCE", triage=Triage.ACTION_REQUIRED),
                Finding(severity=Severity.MEDIUM, agent="architecture_cop", file="b.py", line=5, description="coupling", triage=Triage.FOR_REVIEW),
                Finding(severity=Severity.LOW, agent="style_checker", file="c.py", line=10, description="naming", triage=Triage.INFORMATIONAL),
                Finding(severity=Severity.MEDIUM, agent="coverage_checker", file="(overall)", description="no tests", triage=Triage.FOR_REVIEW),
            ],
            summary="4 findings",
        )
        body = format_review_body(result, 30.0)
        # RCE and coupling have lines → inline, not in body
        assert "RCE" not in body
        assert "coupling" not in body
        # naming is INFORMATIONAL → in body
        assert "naming" in body
        # no tests has no line → in body
        assert "no tests" in body
        assert "2 findings posted as inline" in body

    def test_legacy_format_review_comment(self):
        result = ReviewResult(action=Action.APPROVE, findings=[], summary="clean")
        assert format_review_comment(result, 5.0) == format_review_body(result, 5.0)


class TestBuildInlineComments:
    def test_builds_inline_for_action_required(self):
        findings = [
            Finding(severity=Severity.HIGH, agent="security_auditor", file="api/users.py", line=42, description="SQL injection", cwe_id="CWE-89", suggestion="Use parameterized queries", triage=Triage.ACTION_REQUIRED),
        ]
        comments = build_inline_comments(findings)
        assert len(comments) == 1
        assert comments[0]["path"] == "api/users.py"
        assert comments[0]["line"] == 42
        assert "SQL injection" in comments[0]["body"]
        assert "CWE-89" in comments[0]["body"]
        assert "ACTION_REQUIRED" in comments[0]["body"]

    def test_builds_inline_for_for_review(self):
        findings = [
            Finding(severity=Severity.MEDIUM, agent="architecture_cop", file="b.py", line=10, description="layer violation", triage=Triage.FOR_REVIEW),
        ]
        comments = build_inline_comments(findings)
        assert len(comments) == 1
        assert "FOR_REVIEW" in comments[0]["body"]

    def test_excludes_informational(self):
        findings = [
            Finding(severity=Severity.LOW, agent="style_checker", file="a.py", line=5, description="naming", triage=Triage.INFORMATIONAL),
        ]
        comments = build_inline_comments(findings)
        assert len(comments) == 0

    def test_skips_findings_without_line(self):
        findings = [
            Finding(severity=Severity.HIGH, agent="security_auditor", file="(overall)", description="no tests", triage=Triage.ACTION_REQUIRED),
            Finding(severity=Severity.MEDIUM, agent="coverage_checker", file="a.py", description="coverage drop", triage=Triage.FOR_REVIEW),
        ]
        comments = build_inline_comments(findings)
        assert len(comments) == 0

    def test_filters_by_valid_files(self):
        findings = [
            Finding(severity=Severity.HIGH, agent="security_auditor", file="api/users.py", line=10, description="XSS", triage=Triage.ACTION_REQUIRED),
            Finding(severity=Severity.HIGH, agent="security_auditor", file="old_file.py", line=5, description="issue", triage=Triage.ACTION_REQUIRED),
        ]
        comments = build_inline_comments(findings, valid_files={"api/users.py"})
        assert len(comments) == 1
        assert comments[0]["path"] == "api/users.py"

    def test_mixed_triage(self):
        findings = [
            Finding(severity=Severity.HIGH, agent="security_auditor", file="a.py", line=1, description="vuln", triage=Triage.ACTION_REQUIRED),
            Finding(severity=Severity.MEDIUM, agent="architecture_cop", file="b.py", line=5, description="coupling", triage=Triage.FOR_REVIEW),
            Finding(severity=Severity.LOW, agent="style_checker", file="c.py", line=10, description="naming", triage=Triage.INFORMATIONAL),
        ]
        comments = build_inline_comments(findings)
        assert len(comments) == 2
        paths = {c["path"] for c in comments}
        assert paths == {"a.py", "b.py"}
