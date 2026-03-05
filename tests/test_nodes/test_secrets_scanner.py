from pr_swarm.models import FileDiff, ParsedDiff, Severity
from pr_swarm.nodes.secrets_scanner import secrets_scanner


def _make_state(patch: str, path: str = "config.py"):
    return {
        "pr_number": 1,
        "repo_full_name": "test/repo",
        "parsed_diff": ParsedDiff(
            files=[FileDiff(path=path, status="modified", additions=1, deletions=0, patch=patch)],
            additions=[],
            deletions=[],
            context={"title": "test", "description": "", "labels": []},
            metadata={"author": "dev", "base_branch": "main", "head_branch": "feat", "repo": "test/repo"},
        ),
        "config": {},
        "security_findings": [],
        "architecture_findings": [],
        "coverage_findings": [],
        "secrets_findings": [],
        "style_findings": [],
        "review_result": None,
        "errors": [],
    }


class TestRegexSecretDetection:
    def test_detects_api_key(self):
        patch = '+API_KEY = "sk-1234567890abcdefghijklmnop"'
        result = secrets_scanner(_make_state(patch))
        assert len(result["secrets_findings"]) > 0
        assert any("key" in f.description.lower() or "secret" in f.description.lower() for f in result["secrets_findings"])

    def test_detects_github_token(self):
        patch = '+token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"'
        result = secrets_scanner(_make_state(patch))
        assert len(result["secrets_findings"]) > 0

    def test_detects_private_key(self):
        patch = "+-----BEGIN RSA PRIVATE KEY-----"
        result = secrets_scanner(_make_state(patch))
        assert len(result["secrets_findings"]) > 0

    def test_detects_postgres_uri(self):
        patch = '+DATABASE_URL = "postgres://user:password@localhost:5432/db"'
        result = secrets_scanner(_make_state(patch))
        assert len(result["secrets_findings"]) > 0

    def test_clean_code_no_findings(self):
        patch = "+def hello():\n+    return 'world'"
        result = secrets_scanner(_make_state(patch))
        assert len(result["secrets_findings"]) == 0

    def test_removed_lines_ignored(self):
        patch = '-API_KEY = "sk-1234567890abcdefghijklmnop"'
        result = secrets_scanner(_make_state(patch))
        assert len(result["secrets_findings"]) == 0

    def test_no_diff(self):
        state = {
            "pr_number": 1,
            "repo_full_name": "test/repo",
            "parsed_diff": None,
            "config": {},
            "security_findings": [],
            "architecture_findings": [],
            "coverage_findings": [],
            "secrets_findings": [],
            "style_findings": [],
            "review_result": None,
            "errors": [],
        }
        result = secrets_scanner(state)
        assert len(result["secrets_findings"]) == 0
        assert len(result["errors"]) > 0
