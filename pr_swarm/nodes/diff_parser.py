from __future__ import annotations

from pr_swarm.config import is_path_ignored, load_config
from pr_swarm.github.api import GitHubClient
from pr_swarm.models import FileDiff, ParsedDiff
from pr_swarm.state import ReviewState


def diff_parser(state: ReviewState) -> dict:
    """Extract PR diffs, metadata, and context from GitHub. Pure API calls, no LLM."""
    repo = state["repo_full_name"]
    pr_number = state["pr_number"]

    client = GitHubClient()
    try:
        pr_data = client.get_pr(repo, pr_number)
    finally:
        client.close()

    config = state.get("config") or load_config()

    files: list[FileDiff] = []
    all_additions: list[str] = []
    all_deletions: list[str] = []

    for f in pr_data.files:
        path = f["filename"]
        if is_path_ignored(path, config):
            continue

        status_map = {
            "added": "added",
            "removed": "removed",
            "modified": "modified",
            "renamed": "renamed",
        }
        status = status_map.get(f.get("status", "modified"), "modified")
        patch = f.get("patch", "")

        files.append(
            FileDiff(
                path=path,
                status=status,
                additions=f.get("additions", 0),
                deletions=f.get("deletions", 0),
                patch=patch,
            )
        )

        for line in patch.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                all_additions.append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                all_deletions.append(line[1:])

    total_lines = sum(fd.additions + fd.deletions for fd in files)

    parsed = ParsedDiff(
        files=files,
        additions=all_additions,
        deletions=all_deletions,
        context={
            "title": pr_data.title,
            "description": pr_data.body,
            "labels": pr_data.labels,
        },
        metadata={
            "author": pr_data.author,
            "base_branch": pr_data.base_branch,
            "head_branch": pr_data.head_branch,
            "repo": repo,
            "total_lines_changed": total_lines,
        },
    )

    errors = []
    if total_lines > config.get("max_pr_lines", 2000):
        errors.append({
            "agent": "diff_parser",
            "error": f"PR exceeds {config['max_pr_lines']} line threshold ({total_lines} lines). Partial review only.",
            "escalate": True,
        })

    return {
        "parsed_diff": parsed,
        "config": config,
        "errors": errors,
    }
