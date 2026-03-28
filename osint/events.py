"""
osint/events.py

The event bus — the correlation engine's heart.

Every module publishes findings as typed Finding objects. The bus dispatches
them to registered CorrelationRule handlers, which run follow-up lookups and
publish their own findings back onto the bus, forming an auto-expanding graph.

Usage
-----
    from osint.events import init_bus, get_bus, Finding, FindingType

    bus = init_bus(active_mode=False)
    bus.register_rule(some_rule)

    # In an async context:
    await bus.publish_and_wait(Finding(...))
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import Enum
from typing import Callable, Awaitable


# ---------------------------------------------------------------------------
# Finding types
# ---------------------------------------------------------------------------


class FindingType(str, Enum):
    EMAIL = "email"
    IP = "ip"
    DOMAIN = "domain"
    USERNAME = "username"
    ORG = "org"
    URL = "url"
    PHONE = "phone"
    ASN = "asn"
    PERSON_NAME = "person_name"
    HASH = "hash"
    CREDENTIAL = "credential"
    CERTIFICATE = "certificate"
    SUBDOMAIN = "subdomain"
    SOCIAL_PROFILE = "social_profile"
    GEO_COORD = "geo_coord"


# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single piece of intelligence discovered during a session."""

    type: FindingType
    value: str
    source: str           # e.g. "whois", "dns_a", "crt_sh", "hibp"
    confidence: int       # 0–100
    session_id: int
    parent_id: int | None = None
    raw_data: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    db_id: int | None = None  # set after persisting to DB


@dataclass
class CorrelationRule:
    """
    Declares when and how to fire an automated follow-up lookup.

    When a Finding whose type matches `trigger_type` is published on the bus,
    the bus calls `handler(finding)` — which performs a lookup and returns
    zero or more new findings that are published back onto the bus.
    """

    trigger_type: FindingType
    handler: Callable[[Finding], Awaitable[list[Finding]]]
    name: str
    description: str
    requires_active: bool = False  # only fires when --active mode is on
    min_confidence: int = 0        # only fires if finding.confidence >= this
    cooldown_seconds: int = 0      # don't re-fire for same value within this window


# ---------------------------------------------------------------------------
# Event bus
# ---------------------------------------------------------------------------

# Deduplication window: a finding with the same type+value seen within this
# many seconds in the same session is silently dropped.
_DEDUP_WINDOW_SECONDS = 60


class EventBus:
    """
    Async, rule-driven event bus for OSINT correlation.

    Findings are published to a queue.  The internal processing loop dequeues
    each finding, matches it against registered CorrelationRules, fires
    handlers concurrently, and publishes the returned findings back onto the
    queue — continuing until no rules fire and the queue drains.
    """

    def __init__(self, active_mode: bool = False) -> None:
        self._rules: list[CorrelationRule] = []
        self._queue: asyncio.Queue[Finding] = asyncio.Queue()
        # "type:value" -> last-seen timestamp; used for deduplication
        self._seen: dict[str, datetime] = {}
        # "type:value" -> set of rule names that have already fired within cooldown
        self._fired: dict[str, set[str]] = {}
        self._findings: list[Finding] = []
        self._active_mode = active_mode
        self._running = False
        # Sync callbacks invoked immediately on publish (used for live UI updates)
        self._callbacks: list[Callable[[Finding], None]] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_rule(self, rule: CorrelationRule) -> None:
        """Add a correlation rule to this bus."""
        self._rules.append(rule)

    def on_finding(self, callback: Callable[[Finding], None]) -> None:
        """
        Register a synchronous callback that fires immediately each time a
        finding is published.  Intended for live display / progress updates.
        """
        self._callbacks.append(callback)

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    async def publish(self, finding: Finding) -> None:
        """
        Enqueue a finding for processing.

        Deduplication: if a finding with the same type+value has been seen
        within _DEDUP_WINDOW_SECONDS in this session it is dropped.  This
        prevents infinite loops when two rules create each other's trigger.

        Sync callbacks are invoked immediately before the finding reaches the
        queue so that the UI can show progress without waiting for the queue
        to drain.
        """
        key = f"{finding.type}:{finding.value}"
        now = datetime.now(UTC)

        if key in self._seen:
            elapsed = (now - self._seen[key]).total_seconds()
            if elapsed < _DEDUP_WINDOW_SECONDS:
                return

        self._seen[key] = now
        self._findings.append(finding)

        for cb in self._callbacks:
            try:
                cb(finding)
            except Exception:
                pass  # never let a display callback crash the engine

        await self._queue.put(finding)

    # ------------------------------------------------------------------
    # Processing loop
    # ------------------------------------------------------------------

    async def _process(self) -> None:
        """
        Internal loop: dequeue findings, match rules, fire handlers.

        Handler results are published back through publish() so deduplication
        and callbacks apply uniformly.  All eligible handlers for a single
        finding run concurrently via asyncio.gather.
        """
        while self._running:
            try:
                finding = await asyncio.wait_for(self._queue.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue

            try:
                eligible: list[CorrelationRule] = []
                fired_key = f"{finding.type}:{finding.value}"
                already_fired = self._fired.get(fired_key, set())

                for rule in self._rules:
                    if rule.trigger_type != finding.type:
                        continue
                    if rule.requires_active and not self._active_mode:
                        continue
                    if finding.confidence < rule.min_confidence:
                        continue

                    # Cooldown check
                    if rule.cooldown_seconds > 0 and rule.name in already_fired:
                        last_seen = self._seen.get(fired_key)
                        if last_seen is not None:
                            elapsed = (datetime.now(UTC) - last_seen).total_seconds()
                            if elapsed < rule.cooldown_seconds:
                                continue

                    eligible.append(rule)

                if not eligible:
                    continue

                # Mark rules as fired before we await, so concurrent publishes
                # of the same value don't double-fire while handlers are running.
                if fired_key not in self._fired:
                    self._fired[fired_key] = set()
                for rule in eligible:
                    self._fired[fired_key].add(rule.name)

                # Run all eligible handlers concurrently
                results: list[list[Finding]] = await asyncio.gather(
                    *(rule.handler(finding) for rule in eligible),
                    return_exceptions=False,
                )

                for new_findings in results:
                    for nf in new_findings:
                        await self.publish(nf)

            finally:
                self._queue.task_done()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start the processing loop.  Returns when stop() is called."""
        self._running = True
        await self._process()

    async def stop(self) -> None:
        """Drain the queue and stop the processing loop."""
        self._running = False
        try:
            await asyncio.wait_for(self._queue.join(), timeout=30.0)
        except asyncio.TimeoutError:
            pass

    async def publish_and_wait(self, finding: Finding) -> None:
        """
        Publish a finding and block until the queue fully drains.

        Used by CLI one-shot commands that publish a seed finding and then
        want all downstream correlations to complete before returning.
        """
        self._running = True

        # Start the processing loop as a background task
        processor = asyncio.create_task(self._process())

        await self.publish(finding)

        # Wait for the queue to drain — all recursive publishes included
        await self._queue.join()

        self._running = False
        processor.cancel()
        try:
            await processor
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # Query interface
    # ------------------------------------------------------------------

    def get_all_findings(self) -> list[Finding]:
        """Return every finding accumulated in this session."""
        return list(self._findings)

    def get_findings_by_type(self, type: FindingType) -> list[Finding]:
        """Return all findings of a specific type."""
        return [f for f in self._findings if f.type == type]

    def get_graph(self) -> tuple[list[Finding], list[dict]]:
        """
        Return (findings, edges) for graph rendering.

        An edge represents a parent→child relationship between two findings,
        annotated with the source string of the child finding as the
        relationship label.  This traces the full derivation chain.
        """
        findings = list(self._findings)

        # Build an index from db_id to Finding for efficient edge construction
        id_index: dict[int, Finding] = {}
        for f in findings:
            if f.db_id is not None:
                id_index[f.db_id] = f

        edges: list[dict] = []
        for f in findings:
            if f.parent_id is not None and f.parent_id in id_index:
                parent = id_index[f.parent_id]
                edges.append({
                    "from": parent,
                    "to": f,
                    "relationship": f.source,
                })

        return findings, edges


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_bus: EventBus | None = None


def get_bus() -> EventBus:
    """
    Return the module-level EventBus singleton.

    If init_bus() has not been called, initialises with default settings
    (passive mode).  Modules that need the bus during import should use this.
    """
    global _bus
    if _bus is None:
        _bus = EventBus(active_mode=False)
    return _bus


def init_bus(active_mode: bool = False) -> EventBus:
    """
    Initialise (or reinitialise) the module-level EventBus singleton.

    Called once at CLI startup after --active mode is resolved.  All
    subsequent calls to get_bus() return this instance.
    """
    global _bus
    _bus = EventBus(active_mode=active_mode)
    return _bus
