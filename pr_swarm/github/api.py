from __future__ import annotations

import os
from dataclasses import dataclass

import httpx


@dataclass
class PRData:
    number: int
    title: str
    body: str
    author: str
    base_branch: str
    head_branch: str
    labels: list[str]
    files: list[dict]
    repo_full_name: str


class GitHubClient:
    def __init__(self, token: str | None = None):
        self.token = token or os.environ["GITHUB_TOKEN"]
        self._client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github.v3+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
        )

    def get_pr(self, repo: str, pr_number: int) -> PRData:
        pr = self._client.get(f"/repos/{repo}/pulls/{pr_number}").raise_for_status().json()
        files = self.get_pr_files(repo, pr_number)
        return PRData(
            number=pr["number"],
            title=pr["title"],
            body=pr.get("body") or "",
            author=pr["user"]["login"],
            base_branch=pr["base"]["ref"],
            head_branch=pr["head"]["ref"],
            labels=[l["name"] for l in pr.get("labels", [])],
            files=files,
            repo_full_name=repo,
        )

    def get_pr_files(self, repo: str, pr_number: int) -> list[dict]:
        files = []
        page = 1
        while True:
            resp = self._client.get(
                f"/repos/{repo}/pulls/{pr_number}/files",
                params={"per_page": 100, "page": page},
            ).raise_for_status()
            batch = resp.json()
            if not batch:
                break
            files.extend(batch)
            page += 1
        return files

    def get_file_content(self, repo: str, path: str, ref: str) -> str | None:
        resp = self._client.get(
            f"/repos/{repo}/contents/{path}",
            params={"ref": ref},
            headers={"Accept": "application/vnd.github.v3.raw"},
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.text

    def post_review_comment(self, repo: str, pr_number: int, body: str) -> dict:
        return (
            self._client.post(
                f"/repos/{repo}/issues/{pr_number}/comments",
                json={"body": body},
            )
            .raise_for_status()
            .json()
        )

    def create_check_run(
        self,
        repo: str,
        head_sha: str,
        name: str,
        conclusion: str,
        summary: str,
        details: str = "",
    ) -> dict:
        return (
            self._client.post(
                f"/repos/{repo}/check-runs",
                json={
                    "name": name,
                    "head_sha": head_sha,
                    "status": "completed",
                    "conclusion": conclusion,
                    "output": {
                        "title": name,
                        "summary": summary,
                        "text": details,
                    },
                },
            )
            .raise_for_status()
            .json()
        )

    def add_label(self, repo: str, pr_number: int, label: str) -> None:
        self._client.post(
            f"/repos/{repo}/issues/{pr_number}/labels",
            json={"labels": [label]},
        ).raise_for_status()

    def get_head_sha(self, repo: str, pr_number: int) -> str:
        pr = self._client.get(f"/repos/{repo}/pulls/{pr_number}").raise_for_status().json()
        return pr["head"]["sha"]

    def close(self) -> None:
        self._client.close()
