"""Tests for diff parser — requires mocking GitHub API calls."""
from unittest.mock import MagicMock, patch

from pr_swarm.github.api import PRData
from pr_swarm.nodes.diff_parser import diff_parser


def _make_pr_data(files=None):
    return PRData(
        number=42,
        title="Add user auth",
        body="Implements basic auth flow",
        author="dev",
        base_branch="main",
        head_branch="feature/auth",
        labels=["enhancement"],
        files=files
        or [
            {
                "filename": "api/auth.py",
                "status": "added",
                "additions": 50,
                "deletions": 0,
                "patch": "@@ -0,0 +1,50 @@\n+import jwt\n+def login(user, password):\n+    pass\n",
            },
            {
                "filename": "tests/test_auth.py",
                "status": "added",
                "additions": 30,
                "deletions": 0,
                "patch": "@@ -0,0 +1,30 @@\n+def test_login():\n+    pass\n",
            },
        ],
        repo_full_name="org/repo",
    )


class TestDiffParser:
    @patch("pr_swarm.nodes.diff_parser.GitHubClient")
    def test_basic_parse(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.get_pr.return_value = _make_pr_data()
        mock_client_cls.return_value = mock_client

        state = {
            "pr_number": 42,
            "repo_full_name": "org/repo",
            "parsed_diff": None,
            "config": {"ignore_paths": [], "max_pr_lines": 2000},
            "security_findings": [],
            "architecture_findings": [],
            "coverage_findings": [],
            "secrets_findings": [],
            "style_findings": [],
            "review_result": None,
            "errors": [],
        }
        result = diff_parser(state)
        parsed = result["parsed_diff"]
        assert len(parsed.files) == 2
        assert parsed.files[0].path == "api/auth.py"
        assert parsed.context["title"] == "Add user auth"
        assert parsed.metadata["author"] == "dev"

    @patch("pr_swarm.nodes.diff_parser.GitHubClient")
    def test_ignores_vendor(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.get_pr.return_value = _make_pr_data(
            files=[
                {"filename": "vendor/lib.js", "status": "added", "additions": 100, "deletions": 0, "patch": "+stuff"},
                {"filename": "src/app.py", "status": "modified", "additions": 5, "deletions": 2, "patch": "+code"},
            ]
        )
        mock_client_cls.return_value = mock_client

        state = {
            "pr_number": 42,
            "repo_full_name": "org/repo",
            "parsed_diff": None,
            "config": {"ignore_paths": ["vendor/*"], "max_pr_lines": 2000},
            "security_findings": [],
            "architecture_findings": [],
            "coverage_findings": [],
            "secrets_findings": [],
            "style_findings": [],
            "review_result": None,
            "errors": [],
        }
        result = diff_parser(state)
        assert len(result["parsed_diff"].files) == 1
        assert result["parsed_diff"].files[0].path == "src/app.py"

    @patch("pr_swarm.nodes.diff_parser.GitHubClient")
    def test_oversized_pr(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client.get_pr.return_value = _make_pr_data(
            files=[
                {"filename": "big.py", "status": "added", "additions": 3000, "deletions": 0, "patch": "+x\n" * 3000},
            ]
        )
        mock_client_cls.return_value = mock_client

        state = {
            "pr_number": 42,
            "repo_full_name": "org/repo",
            "parsed_diff": None,
            "config": {"ignore_paths": [], "max_pr_lines": 2000},
            "security_findings": [],
            "architecture_findings": [],
            "coverage_findings": [],
            "secrets_findings": [],
            "style_findings": [],
            "review_result": None,
            "errors": [],
        }
        result = diff_parser(state)
        assert any(e.get("escalate") for e in result["errors"])
