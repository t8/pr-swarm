from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SecretMatch:
    rule_id: str
    description: str
    file: str
    line: int
    match: str  # redacted version of the match
    entropy: float


def run_gitleaks(
    scan_path: str,
    timeout: int = 25,
) -> list[SecretMatch]:
    """Run Gitleaks on a directory and return structured matches."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = f.name

    cmd = [
        "gitleaks",
        "detect",
        "--source",
        scan_path,
        "--report-format",
        "json",
        "--report-path",
        report_path,
        "--no-git",
        "--exit-code",
        "0",
    ]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []

    try:
        report = Path(report_path).read_text()
        data = json.loads(report) if report.strip() else []
    except (json.JSONDecodeError, FileNotFoundError):
        return []

    matches = []
    for item in data:
        secret = item.get("Secret", "")
        redacted = secret[:4] + "****" if len(secret) > 4 else "****"
        matches.append(
            SecretMatch(
                rule_id=item.get("RuleID", "unknown"),
                description=item.get("Description", "Potential secret detected"),
                file=item.get("File", ""),
                line=item.get("StartLine", 0),
                match=redacted,
                entropy=item.get("Entropy", 0.0),
            )
        )
    return matches


def run_trufflehog(
    scan_path: str,
    timeout: int = 25,
) -> list[SecretMatch]:
    """Run TruffleHog on a directory and return structured matches."""
    cmd = [
        "trufflehog",
        "filesystem",
        scan_path,
        "--json",
        "--no-update",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []

    matches = []
    for line in (result.stdout or "").strip().split("\n"):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        matches.append(
            SecretMatch(
                rule_id=item.get("DetectorName", "unknown"),
                description=f"Secret detected by TruffleHog: {item.get('DetectorName', '')}",
                file=item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                line=item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                match="****",
                entropy=item.get("Entropy", 0.0),
            )
        )
    return matches
