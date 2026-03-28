"""
osint/db.py

Async database layer for the OSINT CLI tool.

Two SQLite databases, both under ~/.osint/:
  - findings.db  — sessions, findings, graph edges, audit log
  - cache.db     — HTTP response cache with TTL

All I/O is async via aiosqlite through SQLAlchemy's async extension.
SQLModel is used for table definitions and for generating DDL.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import Field, SQLModel, select

# ---------------------------------------------------------------------------
# Database directory
# ---------------------------------------------------------------------------

_DB_DIR = Path.home() / ".osint"
_FINDINGS_DB = _DB_DIR / "findings.db"
_CACHE_DB = _DB_DIR / "cache.db"


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Table definitions — findings.db
# ---------------------------------------------------------------------------


class Session(SQLModel, table=True):
    """
    Top-level container for a single OSINT investigation run.

    Each session has a unique name and records the seed target that was
    investigated along with high-level metadata about how the run was
    configured.
    """

    __tablename__ = "session"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    seed: str                       # Starting target (e.g. "user@example.com")
    seed_type: str                  # email | domain | ip | username | org
    active_mode: bool = False
    stealth_mode: bool = False
    finding_count: int = 0
    metadata_json: str = "{}"       # Arbitrary session metadata (JSON blob)


class Finding(SQLModel, table=True):
    """
    A single discrete piece of intelligence produced during a session.

    Findings are deduplicated on (session_id, type, value): adding the same
    artefact twice will update its confidence if the new value is higher rather
    than inserting a duplicate row.
    """

    __tablename__ = "finding"

    id: int | None = Field(default=None, primary_key=True)
    session_id: int = Field(foreign_key="session.id", index=True)
    type: str                       # email | ip | domain | username | org |
                                    # url | hash | phone | asn | person_name
    value: str
    source: str                     # Module/API that produced this finding
    confidence: int                 # 0–100
    created_at: datetime = Field(default_factory=_utcnow)
    raw_data_json: str = "{}"       # Full API response payload
    tags_json: str = "[]"           # List of string tags
    parent_finding_id: int | None = Field(default=None, foreign_key="finding.id")


class GraphEdge(SQLModel, table=True):
    """
    A directed relationship between two findings within a session.

    Edges are deduplicated on (session_id, from_finding_id, to_finding_id,
    relationship) so the same relationship is never recorded twice.
    """

    __tablename__ = "graphedge"

    id: int | None = Field(default=None, primary_key=True)
    session_id: int = Field(foreign_key="session.id", index=True)
    from_finding_id: int = Field(foreign_key="finding.id")
    to_finding_id: int = Field(foreign_key="finding.id")
    relationship: str               # whois_registrant | dns_a_record | same_avatar …
    created_at: datetime = Field(default_factory=_utcnow)


class AuditLog(SQLModel, table=True):
    """
    Append-only record of every significant action taken during a session.

    response_hash stores the SHA-256 of the raw API response for chain-of-
    custody purposes so findings can be traced back to verifiable raw data.
    """

    __tablename__ = "auditlog"

    id: int | None = Field(default=None, primary_key=True)
    session_id: int = Field(index=True)
    timestamp: datetime = Field(default_factory=_utcnow)
    action: str                     # query | finding_added | module_run
    details_json: str = "{}"
    response_hash: str | None = None  # SHA-256 of raw response


# ---------------------------------------------------------------------------
# Table definitions — cache.db
# ---------------------------------------------------------------------------


class CacheEntry(SQLModel, table=True):
    """
    Cached HTTP response, keyed by a SHA-256 of (url + serialised params).

    Callers must check expires_at themselves; cache_get() handles this.
    """

    __tablename__ = "cacheentry"

    id: int | None = Field(default=None, primary_key=True)
    cache_key: str = Field(unique=True, index=True)  # SHA-256(url + params)
    url: str
    response_body: str
    status_code: int
    created_at: datetime = Field(default_factory=_utcnow)
    ttl_seconds: int
    expires_at: datetime


# ---------------------------------------------------------------------------
# Database manager
# ---------------------------------------------------------------------------


class Database:
    """
    Async database manager for both findings.db and cache.db.

    Intended to be used as a module-level singleton via get_db().

    Example:
        db = get_db()
        await db.init()
        session = await db.get_or_create_session("run-1", "user@example.com", "email")
    """

    def __init__(self) -> None:
        _DB_DIR.mkdir(parents=True, exist_ok=True)

        self._findings_engine: AsyncEngine = create_async_engine(
            f"sqlite+aiosqlite:///{_FINDINGS_DB}",
            echo=False,
            future=True,
        )
        self._cache_engine: AsyncEngine = create_async_engine(
            f"sqlite+aiosqlite:///{_CACHE_DB}",
            echo=False,
            future=True,
        )

        # Separate session factories for each database.
        self._findings_session = sessionmaker(
            self._findings_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        self._cache_session = sessionmaker(
            self._cache_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def init(self) -> None:
        """
        Create all tables if they do not already exist.

        Call this once at application startup before any other database
        operations.
        """
        # findings.db — Session, Finding, GraphEdge, AuditLog
        async with self._findings_engine.begin() as conn:
            await conn.run_sync(
                SQLModel.metadata.create_all,
                tables=[
                    Session.__table__,      # type: ignore[attr-defined]
                    Finding.__table__,      # type: ignore[attr-defined]
                    GraphEdge.__table__,    # type: ignore[attr-defined]
                    AuditLog.__table__,     # type: ignore[attr-defined]
                ],
            )

        # cache.db — CacheEntry
        async with self._cache_engine.begin() as conn:
            await conn.run_sync(
                SQLModel.metadata.create_all,
                tables=[
                    CacheEntry.__table__,   # type: ignore[attr-defined]
                ],
            )

    async def close(self) -> None:
        """Dispose of both engine connection pools."""
        await self._findings_engine.dispose()
        await self._cache_engine.dispose()

    # Async context manager support so callers can use `async with get_db()`.
    async def __aenter__(self) -> "Database":
        await self.init()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Session operations
    # ------------------------------------------------------------------

    async def get_or_create_session(
        self,
        name: str,
        seed: str,
        seed_type: str,
        **kwargs: Any,
    ) -> Session:
        """
        Return the session with the given name, creating it if absent.

        Extra keyword arguments (active_mode, stealth_mode, metadata_json,
        etc.) are applied only when creating; they are ignored on fetch so
        that existing sessions are not accidentally modified.
        """
        async with self._findings_session() as db_session:
            result = await db_session.exec(
                select(Session).where(Session.name == name)
            )
            existing = result.first()
            if existing is not None:
                return existing

            new_session = Session(
                name=name,
                seed=seed,
                seed_type=seed_type,
                **{k: v for k, v in kwargs.items() if hasattr(Session, k)},
            )
            db_session.add(new_session)
            await db_session.commit()
            await db_session.refresh(new_session)
            return new_session

    async def list_sessions(self) -> list[Session]:
        """Return all sessions ordered by creation time (newest first)."""
        async with self._findings_session() as db_session:
            result = await db_session.exec(
                select(Session).order_by(Session.created_at.desc())  # type: ignore[attr-defined]
            )
            return list(result.all())

    async def get_session_by_name(self, name: str) -> Session | None:
        """Return the session matching `name`, or None if not found."""
        async with self._findings_session() as db_session:
            result = await db_session.exec(
                select(Session).where(Session.name == name)
            )
            return result.first()

    async def _increment_session_finding_count(
        self,
        db_session: AsyncSession,
        session_id: int,
    ) -> None:
        result = await db_session.exec(
            select(Session).where(Session.id == session_id)
        )
        sess = result.first()
        if sess is not None:
            sess.finding_count += 1
            sess.updated_at = _utcnow()
            db_session.add(sess)

    # ------------------------------------------------------------------
    # Finding operations
    # ------------------------------------------------------------------

    async def add_finding(
        self,
        session_id: int,
        type: str,
        value: str,
        source: str,
        confidence: int,
        raw_data: dict[str, Any] | str | None = None,
        tags: list[str] | None = None,
        parent_id: int | None = None,
    ) -> Finding:
        """
        Insert a finding, deduplicating on (session_id, type, value).

        If the same (session_id, type, value) triple already exists, the
        existing row is returned unchanged unless the new confidence score is
        higher, in which case confidence is updated in place.
        """
        raw_data_json = (
            json.dumps(raw_data) if isinstance(raw_data, dict) else (raw_data or "{}")
        )
        tags_json = json.dumps(tags or [])

        async with self._findings_session() as db_session:
            result = await db_session.exec(
                select(Finding).where(
                    Finding.session_id == session_id,
                    Finding.type == type,
                    Finding.value == value,
                )
            )
            existing = result.first()

            if existing is not None:
                if confidence > existing.confidence:
                    existing.confidence = confidence
                    db_session.add(existing)
                    await db_session.commit()
                    await db_session.refresh(existing)
                return existing

            finding = Finding(
                session_id=session_id,
                type=type,
                value=value,
                source=source,
                confidence=confidence,
                raw_data_json=raw_data_json,
                tags_json=tags_json,
                parent_finding_id=parent_id,
            )
            db_session.add(finding)
            await self._increment_session_finding_count(db_session, session_id)
            await db_session.commit()
            await db_session.refresh(finding)
            return finding

    async def get_findings(
        self,
        session_id: int,
        type: str | None = None,
    ) -> list[Finding]:
        """
        Return all findings for a session, optionally filtered by type.

        Results are ordered by creation time (oldest first) so callers get a
        deterministic, chronological view of how the investigation unfolded.
        """
        async with self._findings_session() as db_session:
            stmt = select(Finding).where(Finding.session_id == session_id)
            if type is not None:
                stmt = stmt.where(Finding.type == type)
            stmt = stmt.order_by(Finding.created_at)  # type: ignore[attr-defined]
            result = await db_session.exec(stmt)
            return list(result.all())

    # ------------------------------------------------------------------
    # Graph operations
    # ------------------------------------------------------------------

    async def add_edge(
        self,
        session_id: int,
        from_id: int,
        to_id: int,
        relationship: str,
    ) -> GraphEdge:
        """
        Record a directed edge between two findings.

        Deduplicated on (session_id, from_finding_id, to_finding_id,
        relationship): inserting the same edge twice returns the original.
        """
        async with self._findings_session() as db_session:
            result = await db_session.exec(
                select(GraphEdge).where(
                    GraphEdge.session_id == session_id,
                    GraphEdge.from_finding_id == from_id,
                    GraphEdge.to_finding_id == to_id,
                    GraphEdge.relationship == relationship,
                )
            )
            existing = result.first()
            if existing is not None:
                return existing

            edge = GraphEdge(
                session_id=session_id,
                from_finding_id=from_id,
                to_finding_id=to_id,
                relationship=relationship,
            )
            db_session.add(edge)
            await db_session.commit()
            await db_session.refresh(edge)
            return edge

    async def get_graph(
        self,
        session_id: int,
    ) -> tuple[list[Finding], list[GraphEdge]]:
        """
        Return all findings and edges for a session as a graph snapshot.

        Returns:
            A (findings, edges) tuple suitable for feeding directly into
            networkx or pyvis for visualisation.
        """
        findings = await self.get_findings(session_id)
        async with self._findings_session() as db_session:
            result = await db_session.exec(
                select(GraphEdge)
                .where(GraphEdge.session_id == session_id)
                .order_by(GraphEdge.created_at)  # type: ignore[attr-defined]
            )
            edges = list(result.all())
        return findings, edges

    # ------------------------------------------------------------------
    # Cache operations
    # ------------------------------------------------------------------

    async def cache_get(self, key: str) -> str | None:
        """
        Return the cached response body for `key`, or None if absent/expired.

        Expired entries are left in the database; they will be overwritten on
        the next cache_set() call for the same key.
        """
        async with self._cache_session() as db_session:
            result = await db_session.exec(
                select(CacheEntry).where(CacheEntry.cache_key == key)
            )
            entry = result.first()
            if entry is None:
                return None
            if _utcnow() >= entry.expires_at:
                return None
            return entry.response_body

    async def cache_set(
        self,
        key: str,
        url: str,
        body: str,
        status: int,
        ttl: int,
    ) -> None:
        """
        Insert or replace a cache entry.

        Args:
            key:    SHA-256 cache key (callers are responsible for deriving
                    this consistently, e.g. via hashlib.sha256(url+params)).
            url:    The request URL, stored for debugging/auditing.
            body:   Raw response body as a string.
            status: HTTP status code of the cached response.
            ttl:    Seconds until the entry expires.
        """
        now = _utcnow()
        expires_at = datetime.fromtimestamp(
            now.timestamp() + ttl, tz=timezone.utc
        )

        async with self._cache_session() as db_session:
            result = await db_session.exec(
                select(CacheEntry).where(CacheEntry.cache_key == key)
            )
            existing = result.first()

            if existing is not None:
                existing.url = url
                existing.response_body = body
                existing.status_code = status
                existing.created_at = now
                existing.ttl_seconds = ttl
                existing.expires_at = expires_at
                db_session.add(existing)
            else:
                entry = CacheEntry(
                    cache_key=key,
                    url=url,
                    response_body=body,
                    status_code=status,
                    ttl_seconds=ttl,
                    expires_at=expires_at,
                )
                db_session.add(entry)

            await db_session.commit()

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    async def log_audit(
        self,
        session_id: int,
        action: str,
        details: dict[str, Any] | str,
        response_hash: str | None = None,
    ) -> None:
        """
        Append an audit log entry.

        Args:
            session_id:     Owning session.
            action:         One of "query", "finding_added", "module_run".
            details:        Arbitrary detail dict or pre-serialised JSON string.
            response_hash:  SHA-256 of the raw API response for chain-of-custody.
        """
        details_json = (
            json.dumps(details) if isinstance(details, dict) else details
        )
        async with self._findings_session() as db_session:
            entry = AuditLog(
                session_id=session_id,
                action=action,
                details_json=details_json,
                response_hash=response_hash,
            )
            db_session.add(entry)
            await db_session.commit()


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def make_cache_key(url: str, params: dict[str, Any] | None = None) -> str:
    """
    Derive a stable SHA-256 cache key from a URL and optional query parameters.

    Parameters are sorted by key before hashing so that {a:1, b:2} and
    {b:2, a:1} produce the same key.
    """
    params_str = json.dumps(params or {}, sort_keys=True)
    raw = f"{url}:{params_str}".encode()
    return hashlib.sha256(raw).hexdigest()


def make_response_hash(raw_response: str | bytes) -> str:
    """Return the SHA-256 hex digest of a raw API response for audit logs."""
    data = raw_response.encode() if isinstance(raw_response, str) else raw_response
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_db: Database | None = None


def get_db() -> Database:
    """
    Return the module-level Database singleton, creating it if necessary.

    The singleton is not initialised (tables not created) until init() is
    called.  Application startup should do:

        db = get_db()
        await db.init()
    """
    global _db
    if _db is None:
        _db = Database()
    return _db
