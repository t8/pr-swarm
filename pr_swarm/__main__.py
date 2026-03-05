"""CLI entrypoint for pr-swarm."""
from __future__ import annotations

import argparse
import json
import os
import sys

from pr_swarm.config import load_config
from pr_swarm.graph import run_review


def main() -> None:
    parser = argparse.ArgumentParser(description="PR Security Review Agent")
    parser.add_argument("--repo", required=True, help="Repository (owner/name)")
    parser.add_argument("--pr", required=True, type=int, help="PR number")
    parser.add_argument("--config", default=None, help="Path to review-agent.yml")
    parser.add_argument("--sarif-output", default=None, help="Path to write SARIF output")
    parser.add_argument("--dry-run", action="store_true", help="Run without posting to GitHub")
    args = parser.parse_args()

    if args.sarif_output:
        os.environ["SARIF_OUTPUT_PATH"] = args.sarif_output

    config = load_config(config_yaml=open(args.config).read()) if args.config else load_config()

    if args.dry_run:
        os.environ.setdefault("GITHUB_TOKEN", "dry-run")

    final_state = run_review(args.repo, args.pr, config)

    result = final_state.get("review_result")
    if result:
        print(json.dumps(result.model_dump(), indent=2, default=str))
        # Exit 0 on successful review regardless of verdict.
        # The verdict is communicated via PR review event and check runs.
        # Exit 1 only on BLOCK so the workflow step fails visibly.
        sys.exit(1 if result.action.value == "BLOCK" else 0)
    else:
        print("Review did not produce a result.", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
