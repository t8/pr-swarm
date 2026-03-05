from pr_swarm.github.sarif import generate_sarif
from pr_swarm.models import Action, Finding, ReviewResult, Severity


class TestSarifGeneration:
    def test_empty_findings(self):
        result = ReviewResult(action=Action.APPROVE, findings=[], summary="clean")
        sarif = generate_sarif(result)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []

    def test_with_findings(self):
        result = ReviewResult(
            action=Action.BLOCK,
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    agent="security_auditor",
                    file="api/users.py",
                    line=142,
                    description="SQL injection",
                    cwe_id="CWE-89",
                    suggestion="Use parameterized queries",
                ),
                Finding(
                    severity=Severity.LOW,
                    agent="style_checker",
                    file="utils.py",
                    description="Unused import",
                ),
            ],
            summary="Critical findings",
            block_reason="SQL injection",
        )
        sarif = generate_sarif(result)
        run = sarif["runs"][0]
        assert len(run["results"]) == 2
        assert run["results"][0]["ruleId"] == "CWE-89"
        assert run["results"][0]["level"] == "error"
        assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 142
        assert run["results"][1]["level"] == "note"

    def test_cwe_helpuri(self):
        result = ReviewResult(
            action=Action.REQUEST_CHANGES,
            findings=[
                Finding(
                    severity=Severity.HIGH,
                    agent="security_auditor",
                    file="a.py",
                    line=1,
                    description="XSS",
                    cwe_id="CWE-79",
                ),
            ],
            summary="XSS found",
        )
        sarif = generate_sarif(result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert "helpUri" in rules[0]
        assert "79" in rules[0]["helpUri"]
