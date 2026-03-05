from pr_swarm.github.comment import format_review_comment
from pr_swarm.models import Action, Finding, ReviewResult, Severity


class TestFormatReviewComment:
    def test_approve_no_findings(self):
        result = ReviewResult(action=Action.APPROVE, findings=[], summary="LGTM!")
        comment = format_review_comment(result, 12.5)
        assert "APPROVE" in comment
        assert "0 findings" in comment

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
                ),
            ],
            summary="Secret found",
            block_reason="Leaked API key",
        )
        comment = format_review_comment(result, 47.0)
        assert "BLOCK" in comment
        assert "CRITICAL" in comment
        assert "API key detected" in comment
        assert "config.py:10" in comment
        assert "Block reason" in comment

    def test_request_changes_mixed(self):
        result = ReviewResult(
            action=Action.REQUEST_CHANGES,
            findings=[
                Finding(severity=Severity.HIGH, agent="security_auditor", file="a.py", line=5, description="XSS", cwe_id="CWE-79"),
                Finding(severity=Severity.LOW, agent="style_checker", file="b.py", description="unused import"),
            ],
            summary="2 findings",
        )
        comment = format_review_comment(result, 33.0)
        assert "REQUEST_CHANGES" in comment
        assert "HIGH" in comment
        assert "LOW" in comment
        assert "CWE-79" in comment
        assert "2 findings" in comment
