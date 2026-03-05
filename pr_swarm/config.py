from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "sensitivity": "high",
    "sensitive_paths": [],
    "ignore_paths": ["vendor/", "**/*.min.js", "**/*.generated.*"],
    "block_on": ["secret_detected", "cwe_critical"],
    "warn_on": {
        "pr_size_lines": 500,
        "coverage_drop_pct": 1.0,
        "complexity_increase": 10,
    },
    "languages": {},
    "max_pr_lines": 2000,
    "agent_timeout_seconds": 30,
}


def load_config(repo_root: str | Path | None = None, config_yaml: str | None = None) -> dict:
    """Load review agent config from YAML string or .github/review-agent.yml."""
    config = dict(DEFAULT_CONFIG)

    raw: dict[str, Any] = {}
    if config_yaml:
        raw = yaml.safe_load(config_yaml) or {}
    elif repo_root:
        config_path = Path(repo_root) / ".github" / "review-agent.yml"
        if config_path.exists():
            raw = yaml.safe_load(config_path.read_text()) or {}

    config.update(raw)
    return config


def is_path_ignored(file_path: str, config: dict) -> bool:
    """Check if a file path matches any ignore pattern."""
    from fnmatch import fnmatch

    for pattern in config.get("ignore_paths", []):
        if fnmatch(file_path, pattern):
            return True
    return False


def is_sensitive_path(file_path: str, config: dict) -> bool:
    """Check if a file path is in a sensitive directory."""
    for pattern in config.get("sensitive_paths", []):
        if file_path.startswith(pattern) or f"/{pattern}" in file_path:
            return True
    return False


def get_sensitivity(config: dict) -> str:
    return config.get("sensitivity", "high")
