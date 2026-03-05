from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import psycopg
from pgvector.psycopg import register_vector

from pr_swarm.models import ReviewResult

SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS review_episodes (
    id SERIAL PRIMARY KEY,
    repo TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    action TEXT NOT NULL,
    summary TEXT NOT NULL,
    findings JSONB NOT NULL,
    embedding vector(1536),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    feedback_score FLOAT DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_episodes_repo ON review_episodes(repo);
CREATE INDEX IF NOT EXISTS idx_episodes_embedding ON review_episodes
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
"""


class EpisodicMemory:
    def __init__(self, database_url: str | None = None):
        self.database_url = database_url or os.environ.get("DATABASE_URL")
        self._conn: psycopg.Connection | None = None

    def _get_conn(self) -> psycopg.Connection:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg.connect(self.database_url)
            register_vector(self._conn)
        return self._conn

    def initialize(self) -> None:
        """Create tables if they don't exist."""
        conn = self._get_conn()
        conn.execute(SCHEMA_SQL)
        conn.commit()

    def store_review(
        self,
        repo: str,
        pr_number: int,
        result: ReviewResult,
        embedding: list[float] | None = None,
    ) -> int:
        """Store a review result in episodic memory."""
        conn = self._get_conn()
        findings_json = json.dumps([f.model_dump() for f in result.findings])

        if embedding:
            row = conn.execute(
                """INSERT INTO review_episodes (repo, pr_number, action, summary, findings, embedding)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (repo, pr_number, result.action.value, result.summary, findings_json, embedding),
            ).fetchone()
        else:
            row = conn.execute(
                """INSERT INTO review_episodes (repo, pr_number, action, summary, findings)
                   VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                (repo, pr_number, result.action.value, result.summary, findings_json),
            ).fetchone()
        conn.commit()
        return row[0]

    def search_similar(
        self,
        embedding: list[float],
        repo: str | None = None,
        limit: int = 5,
        recency_weight: float = 0.3,
    ) -> list[dict[str, Any]]:
        """Search for similar past reviews using vector similarity with recency weighting."""
        conn = self._get_conn()

        repo_filter = "AND repo = %s" if repo else ""
        params: list = [embedding, limit]
        if repo:
            params.insert(1, repo)

        query = f"""
            SELECT id, repo, pr_number, action, summary, findings, created_at, feedback_score,
                   1 - (embedding <=> %s) as similarity
            FROM review_episodes
            WHERE embedding IS NOT NULL {repo_filter}
            ORDER BY embedding <=> %s
            LIMIT %s
        """
        params_final = [embedding]
        if repo:
            params_final.append(repo)
        params_final.extend([embedding, limit])

        rows = conn.execute(query, params_final).fetchall()
        results = []
        for row in rows:
            age_days = (datetime.now(timezone.utc) - row[6].replace(tzinfo=timezone.utc)).days
            recency_score = max(0, 1 - (age_days / 365))
            combined_score = (1 - recency_weight) * row[8] + recency_weight * recency_score

            results.append({
                "id": row[0],
                "repo": row[1],
                "pr_number": row[2],
                "action": row[3],
                "summary": row[4],
                "findings": json.loads(row[5]),
                "created_at": row[6].isoformat(),
                "feedback_score": row[7],
                "similarity": row[8],
                "combined_score": combined_score,
            })
        results.sort(key=lambda x: x["combined_score"], reverse=True)
        return results

    def record_feedback(self, episode_id: int, is_positive: bool) -> None:
        """Record developer feedback (thumbs up/down) on a finding."""
        conn = self._get_conn()
        delta = 0.1 if is_positive else -0.1
        conn.execute(
            """UPDATE review_episodes
               SET feedback_score = COALESCE(feedback_score, 0.5) + %s
               WHERE id = %s""",
            (delta, episode_id),
        )
        conn.commit()

    def get_repo_history(self, repo: str, limit: int = 20) -> list[dict]:
        """Get recent review history for a repo."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT id, pr_number, action, summary, created_at, feedback_score
               FROM review_episodes
               WHERE repo = %s
               ORDER BY created_at DESC
               LIMIT %s""",
            (repo, limit),
        ).fetchall()
        return [
            {
                "id": r[0],
                "pr_number": r[1],
                "action": r[2],
                "summary": r[3],
                "created_at": r[4].isoformat(),
                "feedback_score": r[5],
            }
            for r in rows
        ]

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
