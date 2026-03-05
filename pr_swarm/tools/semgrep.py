from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SemgrepMatch:
    rule_id: str
    path: str
    start_line: int
    end_line: int
    message: str
    severity: str
    metadata: dict


def run_semgrep(
    files: list[str],
    rules: str = "auto",
    timeout: int = 25,
    work_dir: str | None = None,
) -> list[SemgrepMatch]:
    """Run Semgrep on a list of files and return structured matches."""
    if not files:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for file_path in files:
            f.write(file_path + "\n")
        target_file = f.name

    cmd = [
        "semgrep",
        "scan",
        "--json",
        "--config",
        rules,
        "--target-list",
        target_file,
        "--timeout",
        str(timeout),
        "--no-git-ignore",
        "--quiet",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
            cwd=work_dir,
        )
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []

    if not result.stdout:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    matches = []
    for r in data.get("results", []):
        matches.append(
            SemgrepMatch(
                rule_id=r.get("check_id", "unknown"),
                path=r.get("path", ""),
                start_line=r.get("start", {}).get("line", 0),
                end_line=r.get("end", {}).get("line", 0),
                message=r.get("extra", {}).get("message", ""),
                severity=r.get("extra", {}).get("severity", "WARNING"),
                metadata=r.get("extra", {}).get("metadata", {}),
            )
        )
    return matches


def write_files_to_temp(files: dict[str, str]) -> Path:
    """Write file contents to a temp directory for scanning. Returns the temp dir path."""
    tmp = Path(tempfile.mkdtemp(prefix="pr-swarm-"))
    for path, content in files.items():
        file_path = tmp / path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)
    return tmp
