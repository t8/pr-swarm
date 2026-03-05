from __future__ import annotations

import json
import os
from typing import Any

import psycopg
from pgvector.psycopg import register_vector

SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS knowledge_base (
    id SERIAL PRIMARY KEY,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    metadata JSONB DEFAULT '{}',
    embedding vector(1536),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_kb_category ON knowledge_base(category);
CREATE INDEX IF NOT EXISTS idx_kb_embedding ON knowledge_base
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
"""

OWASP_TOP_10 = [
    {
        "category": "owasp",
        "title": "A01:2021 Broken Access Control",
        "content": "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.",
    },
    {
        "category": "owasp",
        "title": "A02:2021 Cryptographic Failures",
        "content": "Failures related to cryptography which often lead to sensitive data exposure or system compromise. Use of hard-coded passwords, broken or risky crypto algorithms, insufficient entropy.",
    },
    {
        "category": "owasp",
        "title": "A03:2021 Injection",
        "content": "SQL, NoSQL, OS, LDAP injection occurs when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.",
    },
    {
        "category": "owasp",
        "title": "A04:2021 Insecure Design",
        "content": "Insecure design is a broad category representing different weaknesses, expressed as missing or ineffective control design. Threat modeling, secure design patterns, and reference architectures.",
    },
    {
        "category": "owasp",
        "title": "A05:2021 Security Misconfiguration",
        "content": "Missing appropriate security hardening, improperly configured permissions, unnecessary features enabled, default accounts enabled/unchanged, error handling reveals stack traces, security settings not set to secure values.",
    },
    {
        "category": "owasp",
        "title": "A06:2021 Vulnerable and Outdated Components",
        "content": "Components such as libraries, frameworks, and other software modules run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.",
    },
    {
        "category": "owasp",
        "title": "A07:2021 Identification and Authentication Failures",
        "content": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. Permits brute force, default/weak passwords, missing MFA.",
    },
    {
        "category": "owasp",
        "title": "A08:2021 Software and Data Integrity Failures",
        "content": "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. Insecure deserialization, CI/CD pipeline compromise, auto-update without integrity verification.",
    },
    {
        "category": "owasp",
        "title": "A09:2021 Security Logging and Monitoring Failures",
        "content": "Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response. Auditable events are not logged, warnings and errors generate no/unclear logs.",
    },
    {
        "category": "owasp",
        "title": "A10:2021 Server-Side Request Forgery (SSRF)",
        "content": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.",
    },
]


class SemanticMemory:
    def __init__(self, database_url: str | None = None):
        self.database_url = database_url or os.environ.get("DATABASE_URL")
        self._conn: psycopg.Connection | None = None

    def _get_conn(self) -> psycopg.Connection:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg.connect(self.database_url)
            register_vector(self._conn)
        return self._conn

    def initialize(self) -> None:
        """Create tables and seed with OWASP data."""
        conn = self._get_conn()
        conn.execute(SCHEMA_SQL)
        conn.commit()

    def seed_owasp(self, embed_fn=None) -> None:
        """Seed the knowledge base with OWASP Top 10 data."""
        conn = self._get_conn()
        for item in OWASP_TOP_10:
            existing = conn.execute(
                "SELECT id FROM knowledge_base WHERE title = %s",
                (item["title"],),
            ).fetchone()
            if existing:
                continue

            embedding = embed_fn(item["content"]) if embed_fn else None
            if embedding:
                conn.execute(
                    """INSERT INTO knowledge_base (category, title, content, embedding)
                       VALUES (%s, %s, %s, %s)""",
                    (item["category"], item["title"], item["content"], embedding),
                )
            else:
                conn.execute(
                    """INSERT INTO knowledge_base (category, title, content)
                       VALUES (%s, %s, %s)""",
                    (item["category"], item["title"], item["content"]),
                )
        conn.commit()

    def add_document(
        self,
        category: str,
        title: str,
        content: str,
        metadata: dict | None = None,
        embedding: list[float] | None = None,
    ) -> int:
        """Add a document to the knowledge base."""
        conn = self._get_conn()
        meta_json = json.dumps(metadata or {})
        if embedding:
            row = conn.execute(
                """INSERT INTO knowledge_base (category, title, content, metadata, embedding)
                   VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                (category, title, content, meta_json, embedding),
            ).fetchone()
        else:
            row = conn.execute(
                """INSERT INTO knowledge_base (category, title, content, metadata)
                   VALUES (%s, %s, %s, %s) RETURNING id""",
                (category, title, content, meta_json),
            ).fetchone()
        conn.commit()
        return row[0]

    def search(
        self,
        embedding: list[float],
        category: str | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Search the knowledge base by vector similarity."""
        conn = self._get_conn()

        if category:
            rows = conn.execute(
                """SELECT id, category, title, content, metadata,
                          1 - (embedding <=> %s) as similarity
                   FROM knowledge_base
                   WHERE embedding IS NOT NULL AND category = %s
                   ORDER BY embedding <=> %s
                   LIMIT %s""",
                (embedding, category, embedding, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, category, title, content, metadata,
                          1 - (embedding <=> %s) as similarity
                   FROM knowledge_base
                   WHERE embedding IS NOT NULL
                   ORDER BY embedding <=> %s
                   LIMIT %s""",
                (embedding, embedding, limit),
            ).fetchall()

        return [
            {
                "id": r[0],
                "category": r[1],
                "title": r[2],
                "content": r[3],
                "metadata": json.loads(r[4]) if isinstance(r[4], str) else r[4],
                "similarity": r[5],
            }
            for r in rows
        ]

    def get_by_category(self, category: str) -> list[dict]:
        """Get all documents in a category."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT id, title, content, metadata FROM knowledge_base
               WHERE category = %s ORDER BY title""",
            (category,),
        ).fetchall()
        return [
            {"id": r[0], "title": r[1], "content": r[2], "metadata": json.loads(r[3]) if isinstance(r[3], str) else r[3]}
            for r in rows
        ]

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
