from __future__ import annotations

import os
import time

from langgraph.graph import END, START, StateGraph

from pr_swarm.github.api import GitHubClient
from pr_swarm.github.comment import build_inline_comments, format_review_body
from pr_swarm.github.sarif import write_sarif
from pr_swarm.models import Action
from pr_swarm.nodes.architecture_cop import architecture_cop
from pr_swarm.nodes.coverage_checker import coverage_checker
from pr_swarm.nodes.diff_parser import diff_parser
from pr_swarm.nodes.secrets_scanner import secrets_scanner
from pr_swarm.nodes.security_auditor import security_auditor
from pr_swarm.nodes.style_checker import style_checker
from pr_swarm.nodes.synthesizer import synthesizer
from pr_swarm.state import ReviewState

SPECIALIST_NODES = [
    "security_auditor",
    "secrets_scanner",
    "coverage_checker",
    "architecture_cop",
    "style_checker",
]


def route_after_diff_parser(state: ReviewState) -> list[str] | str:
    """Route to specialists or oversized handler based on PR size."""
    errors = state.get("errors", [])
    for e in errors:
        if e.get("escalate"):
            return "oversized_handler"
    return SPECIALIST_NODES


def oversized_handler(state: ReviewState) -> dict:
    """Handle oversized PRs by posting a manual review notice."""
    return {
        "review_result": None,
        "errors": [{"agent": "graph", "error": "PR exceeds size threshold. Manual review required."}],
    }


def build_graph() -> StateGraph:
    """Build the LangGraph review pipeline with parallel fan-out."""
    graph = StateGraph(ReviewState)

    graph.add_node("diff_parser", diff_parser)
    graph.add_node("security_auditor", security_auditor)
    graph.add_node("secrets_scanner", secrets_scanner)
    graph.add_node("coverage_checker", coverage_checker)
    graph.add_node("architecture_cop", architecture_cop)
    graph.add_node("style_checker", style_checker)
    graph.add_node("synthesizer", synthesizer)
    graph.add_node("oversized_handler", oversized_handler)

    graph.add_edge(START, "diff_parser")

    graph.add_conditional_edges("diff_parser", route_after_diff_parser)

    for node in SPECIALIST_NODES:
        graph.add_edge(node, "synthesizer")

    graph.add_edge("synthesizer", END)
    graph.add_edge("oversized_handler", END)

    return graph


def compile_graph():
    """Compile the graph for execution."""
    return build_graph().compile()


def run_review(repo: str, pr_number: int, config: dict | None = None) -> ReviewState:
    """Run the full review pipeline on a PR."""
    start = time.time()

    app = compile_graph()

    initial_state: ReviewState = {
        "pr_number": pr_number,
        "repo_full_name": repo,
        "parsed_diff": None,
        "config": config or {},
        "security_findings": [],
        "architecture_findings": [],
        "coverage_findings": [],
        "secrets_findings": [],
        "style_findings": [],
        "review_result": None,
        "errors": [],
    }

    final_state = app.invoke(initial_state)
    elapsed = time.time() - start

    _post_results(final_state, elapsed)

    return final_state


def _post_results(state: ReviewState, elapsed: float) -> None:
    """Post review results to GitHub as a proper PR review with inline comments."""
    result = state.get("review_result")
    if not result:
        return

    repo = state["repo_full_name"]
    pr_number = state["pr_number"]

    review_body = format_review_body(result, elapsed)

    # Map action to GitHub review event
    # GitHub doesn't have BLOCK — REQUEST_CHANGES + branch protection achieves the same
    event_map = {
        Action.APPROVE: "APPROVE",
        Action.REQUEST_CHANGES: "REQUEST_CHANGES",
        Action.BLOCK: "REQUEST_CHANGES",
    }
    review_event = event_map.get(result.action, "COMMENT")

    # Build inline comments for findings with file + line
    parsed_diff = state.get("parsed_diff")
    valid_files = {f.path for f in parsed_diff.files} if parsed_diff else None
    inline_comments = build_inline_comments(result.findings, valid_files)

    try:
        client = GitHubClient()

        # Submit as a real PR review with inline comments
        client.create_review(
            repo=repo,
            pr_number=pr_number,
            body=review_body,
            event=review_event,
            comments=inline_comments if inline_comments else None,
        )

        head_sha = client.get_head_sha(repo, pr_number)

        conclusion_map = {
            Action.APPROVE: "success",
            Action.REQUEST_CHANGES: "neutral",
            Action.BLOCK: "failure",
        }

        client.create_check_run(
            repo=repo,
            head_sha=head_sha,
            name="pr-swarm/security",
            conclusion=conclusion_map.get(result.action, "neutral"),
            summary=result.summary,
        )

        has_secrets = any(f.agent == "secrets_scanner" for f in result.findings)
        if has_secrets:
            client.create_check_run(
                repo=repo,
                head_sha=head_sha,
                name="pr-swarm/secrets",
                conclusion="failure",
                summary="Secrets detected in PR",
            )

        sarif_path = os.environ.get("SARIF_OUTPUT_PATH")
        if sarif_path:
            write_sarif(result, sarif_path)

        for error in state.get("errors", []):
            if error.get("escalate"):
                client.add_label(repo, pr_number, "manual-review-required")
                break

        client.close()
    except Exception:
        pass
