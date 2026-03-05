from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Action(str, Enum):
    APPROVE = "APPROVE"
    REQUEST_CHANGES = "REQUEST_CHANGES"
    BLOCK = "BLOCK"


class Finding(BaseModel):
    severity: Severity
    agent: str
    file: str
    line: Optional[int] = None
    description: str
    cwe_id: Optional[str] = None
    suggestion: Optional[str] = None


class ReviewResult(BaseModel):
    action: Action
    findings: list[Finding]
    summary: str = Field(max_length=280)
    block_reason: Optional[str] = None


class FileDiff(BaseModel):
    path: str
    status: str  # added, modified, removed, renamed
    additions: int
    deletions: int
    patch: str


class ParsedDiff(BaseModel):
    files: list[FileDiff]
    additions: list[str]
    deletions: list[str]
    context: dict  # PR title, description, labels, linked issues
    metadata: dict  # author, base branch, head branch, repo
