from pr_swarm.models import Action, Finding, Severity, Triage
from pr_swarm.nodes.synthesizer import _apply_default_triage, _collect_findings, _determine_action


class TestDetermineAction:
    def test_no_findings(self):
        assert _determine_action([]) == Action.APPROVE

    def test_info_only(self):
        findings = [
            Finding(severity=Severity.INFO, agent="style_checker", file="a.py", description="unused import"),
        ]
        assert _determine_action(findings) == Action.APPROVE

    def test_low_only(self):
        findings = [
            Finding(severity=Severity.LOW, agent="style_checker", file="a.py", description="naming"),
        ]
        assert _determine_action(findings) == Action.APPROVE

    def test_medium_triggers_request_changes(self):
        findings = [
            Finding(severity=Severity.MEDIUM, agent="security_auditor", file="a.py", description="missing validation"),
        ]
        assert _determine_action(findings) == Action.REQUEST_CHANGES

    def test_high_triggers_request_changes(self):
        findings = [
            Finding(severity=Severity.HIGH, agent="security_auditor", file="a.py", description="xss"),
        ]
        assert _determine_action(findings) == Action.REQUEST_CHANGES

    def test_critical_triggers_block(self):
        findings = [
            Finding(severity=Severity.CRITICAL, agent="security_auditor", file="a.py", description="rce"),
        ]
        assert _determine_action(findings) == Action.BLOCK

    def test_secrets_high_triggers_block(self):
        findings = [
            Finding(severity=Severity.HIGH, agent="secrets_scanner", file="config.py", description="api key"),
        ]
        assert _determine_action(findings) == Action.BLOCK

    def test_secrets_critical_triggers_block(self):
        findings = [
            Finding(severity=Severity.CRITICAL, agent="secrets_scanner", file=".env", description="password"),
        ]
        assert _determine_action(findings) == Action.BLOCK

    def test_mixed_severities_takes_highest(self):
        findings = [
            Finding(severity=Severity.LOW, agent="style_checker", file="a.py", description="naming"),
            Finding(severity=Severity.MEDIUM, agent="coverage_checker", file="b.py", description="no tests"),
            Finding(severity=Severity.HIGH, agent="security_auditor", file="c.py", description="xss"),
        ]
        assert _determine_action(findings) == Action.REQUEST_CHANGES


class TestCollectFindings:
    def test_collects_all(self):
        state = {
            "security_findings": [
                Finding(severity=Severity.HIGH, agent="security_auditor", file="a.py", description="xss"),
            ],
            "architecture_findings": [],
            "coverage_findings": [
                Finding(severity=Severity.MEDIUM, agent="coverage_checker", file="b.py", description="no tests"),
            ],
            "secrets_findings": [],
            "style_findings": [
                Finding(severity=Severity.LOW, agent="style_checker", file="c.py", description="naming"),
            ],
        }
        findings = _collect_findings(state)
        assert len(findings) == 3

    def test_empty_state(self):
        state = {
            "security_findings": [],
            "architecture_findings": [],
            "coverage_findings": [],
            "secrets_findings": [],
            "style_findings": [],
        }
        assert len(_collect_findings(state)) == 0


class TestApplyDefaultTriage:
    def test_critical_is_action_required(self):
        findings = [Finding(severity=Severity.CRITICAL, agent="security_auditor", file="a.py", description="rce")]
        _apply_default_triage(findings)
        assert findings[0].triage == Triage.ACTION_REQUIRED

    def test_high_is_action_required(self):
        findings = [Finding(severity=Severity.HIGH, agent="security_auditor", file="a.py", description="xss")]
        _apply_default_triage(findings)
        assert findings[0].triage == Triage.ACTION_REQUIRED

    def test_medium_is_for_review(self):
        findings = [Finding(severity=Severity.MEDIUM, agent="coverage_checker", file="a.py", description="no tests")]
        _apply_default_triage(findings)
        assert findings[0].triage == Triage.FOR_REVIEW

    def test_low_is_informational(self):
        findings = [Finding(severity=Severity.LOW, agent="style_checker", file="a.py", description="naming")]
        _apply_default_triage(findings)
        assert findings[0].triage == Triage.INFORMATIONAL

    def test_info_is_informational(self):
        findings = [Finding(severity=Severity.INFO, agent="style_checker", file="a.py", description="note")]
        _apply_default_triage(findings)
        assert findings[0].triage == Triage.INFORMATIONAL

    def test_secrets_high_is_action_required(self):
        findings = [Finding(severity=Severity.HIGH, agent="secrets_scanner", file="config.py", description="api key")]
        _apply_default_triage(findings)
        assert findings[0].triage == Triage.ACTION_REQUIRED

    def test_mixed(self):
        findings = [
            Finding(severity=Severity.CRITICAL, agent="security_auditor", file="a.py", description="rce"),
            Finding(severity=Severity.MEDIUM, agent="architecture_cop", file="b.py", description="coupling"),
            Finding(severity=Severity.LOW, agent="style_checker", file="c.py", description="naming"),
        ]
        _apply_default_triage(findings)
        assert findings[0].triage == Triage.ACTION_REQUIRED
        assert findings[1].triage == Triage.FOR_REVIEW
        assert findings[2].triage == Triage.INFORMATIONAL
