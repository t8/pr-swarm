from __future__ import annotations

import re
import shutil

from pr_swarm.models import Finding, Severity
from pr_swarm.state import ReviewState
from pr_swarm.tools.gitleaks import SecretMatch, run_gitleaks, run_trufflehog
from pr_swarm.tools.semgrep import write_files_to_temp

HIGH_ENTROPY_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[\w\-]{20,}', "API key"),
    (r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{8,}', "Password/secret"),
    (r'(?i)(token|bearer)\s*[=:]\s*["\']?[\w\-\.]{20,}', "Token"),
    (r'(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\sKEY-----', "Private key"),
    (r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*[\w/+=]{16,}', "AWS credential"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub personal access token"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/Stripe secret key"),
    (r'(?i)mongodb(\+srv)?://[^\s]+:[^\s]+@', "MongoDB connection string with credentials"),
    (r'(?i)postgres(ql)?://[^\s]+:[^\s]+@', "PostgreSQL connection string with credentials"),
]


def secrets_scanner(state: ReviewState) -> dict:
    """Scan for leaked secrets using Gitleaks, TruffleHog, and custom regex patterns."""
    parsed_diff = state.get("parsed_diff")
    if not parsed_diff:
        return {"secrets_findings": [], "errors": [{"agent": "secrets_scanner", "error": "No parsed diff"}]}

    findings: list[Finding] = []
    errors: list[dict] = []

    file_contents: dict[str, str] = {}
    for f in parsed_diff.files:
        if f.status == "removed":
            continue
        file_contents[f.path] = f.patch

    tmp_dir = None
    try:
        if file_contents:
            tmp_dir = write_files_to_temp(file_contents)
            scan_path = str(tmp_dir)

            gitleaks_matches = _safe_run(lambda: run_gitleaks(scan_path), errors, "gitleaks")
            trufflehog_matches = _safe_run(lambda: run_trufflehog(scan_path), errors, "trufflehog")

            for match in gitleaks_matches + trufflehog_matches:
                rel_path = match.file.replace(scan_path + "/", "").replace(str(tmp_dir) + "/", "")
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        agent="secrets_scanner",
                        file=rel_path,
                        line=match.line,
                        description=f"Secret detected: {match.description} (rule: {match.rule_id})",
                        suggestion="Remove this secret immediately and rotate the credential.",
                    )
                )
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    for f in parsed_diff.files:
        if f.status == "removed":
            continue
        regex_findings = _scan_with_regex(f.path, f.patch)
        for rf in regex_findings:
            if not any(
                ef.file == rf.file and ef.line == rf.line
                for ef in findings
            ):
                findings.append(rf)

    return {"secrets_findings": findings, "errors": errors}


def _scan_with_regex(file_path: str, patch: str) -> list[Finding]:
    findings = []
    for line_num, line in enumerate(patch.split("\n"), 1):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        content = line[1:]
        for pattern, desc in HIGH_ENTROPY_PATTERNS:
            if re.search(pattern, content):
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        agent="secrets_scanner",
                        file=file_path,
                        line=line_num,
                        description=f"Potential {desc} detected in added code",
                        suggestion="Move this credential to environment variables or a secrets manager.",
                    )
                )
                break
    return findings


def _safe_run(fn, errors: list[dict], tool_name: str) -> list[SecretMatch]:
    try:
        return fn()
    except Exception as e:
        errors.append({"agent": "secrets_scanner", "error": f"{tool_name} failed: {e}"})
        return []
