"""
osint/watch.py

Watch mode daemon — periodically re-runs a scan module against a target and
alerts when findings change.

Usage pattern:
    target = WatchTarget(
        target="example.com",
        target_type="domain",
        module="domain.dns",
        interval_seconds=21600,
        session_base="example-watch",
    )
    stop = asyncio.Event()
    await watch_loop([target], stop)
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Any

import httpx

from osint.output import (
    get_console,
    print_error,
    print_info,
    print_success,
    print_warning,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class WatchTarget:
    """Configuration for a single monitored target."""

    target: str
    target_type: str       # "domain", "ip", "email", "username"
    module: str            # "domain.whois", "domain.dns", "ip.geo", etc.
    interval_seconds: int
    session_base: str      # each run appends a timestamp suffix
    notify_webhook: str | None = None
    notify_email: str | None = None
    last_run: datetime | None = None
    last_finding_count: int = 0

    # internal: findings from the previous cycle, used for diffing
    _previous_findings: list[dict] = field(default_factory=list, repr=False)


# ---------------------------------------------------------------------------
# Module routing
# ---------------------------------------------------------------------------

# Maps the user-facing module name to (import_path, function_name, arg_builder).
# arg_builder takes a WatchTarget and returns the kwargs for the function.

_MODULE_ROUTES: dict[str, tuple[str, str, Any]] = {
    "domain.whois": (
        "osint.modules.domain.whois_lookup",
        "lookup_whois",
        lambda t: {"domain": t.target},
    ),
    "domain.dns": (
        "osint.modules.domain.dns_lookup",
        "lookup_records",
        lambda t: {"domain": t.target},
    ),
    "domain.subdomains": (
        "osint.modules.domain.subdomain_enum",
        "enumerate_subdomains",
        lambda t: {"domain": t.target},
    ),
    "ip.geo": (
        "osint.modules.ip.geo_lookup",
        "lookup_geo",
        lambda t: {"ip": t.target},
    ),
    "ip.reputation": (
        "osint.modules.ip.ip_reputation",
        "check_reputation",
        lambda t: {"ip": t.target},
    ),
    "person.email": (
        "osint.modules.person.email_lookup",
        "check_email",
        lambda t: {"email": t.target, "session_id": 0},
    ),
}


def _resolve_module(module_name: str) -> tuple[Any, dict]:
    """
    Import the appropriate lookup function lazily and return (fn, kwargs_template).

    Raises ValueError for unknown module names.
    """
    route = _MODULE_ROUTES.get(module_name)
    if route is None:
        known = ", ".join(sorted(_MODULE_ROUTES))
        raise ValueError(
            f"Unknown module '{module_name}'. Known modules: {known}"
        )
    import_path, fn_name, arg_builder = route
    import importlib
    mod = importlib.import_module(import_path)
    fn = getattr(mod, fn_name)
    return fn, arg_builder


# ---------------------------------------------------------------------------
# Normalise findings
# ---------------------------------------------------------------------------


def _normalise_findings(raw: Any) -> list[dict]:
    """
    Coerce whatever a module returns into a flat list of finding-like dicts.

    Modules return varied shapes (dict, list[dict], list[str]).  We normalise
    everything into {"type": str, "value": str, "confidence": int, ...} so
    that compute_changes() always works on a uniform representation.
    """
    if raw is None:
        return []

    if isinstance(raw, list):
        results: list[dict] = []
        for item in raw:
            if isinstance(item, dict):
                # Already dict — ensure required keys are present
                results.append({
                    "type": str(item.get("type", "unknown")),
                    "value": str(item.get("value", "")),
                    "confidence": int(item.get("confidence", 50)),
                    "source": str(item.get("source", "")),
                })
            elif hasattr(item, "__dict__"):
                # Dataclass / SQLModel row
                d = item.__dict__ if not hasattr(item, "model_dump") else item.model_dump()
                results.append({
                    "type": str(d.get("type", "unknown")),
                    "value": str(d.get("value", "")),
                    "confidence": int(d.get("confidence", 50)),
                    "source": str(d.get("source", "")),
                })
            else:
                results.append({"type": "unknown", "value": str(item), "confidence": 50, "source": ""})
        return results

    if isinstance(raw, dict):
        # Flatten a dict of lists (e.g. dns lookup returns {"A": [...], "MX": [...]})
        results = []
        for key, val in raw.items():
            if isinstance(val, list):
                for item in val:
                    results.append({
                        "type": key.lower(),
                        "value": str(item),
                        "confidence": 80,
                        "source": "",
                    })
            else:
                results.append({
                    "type": key.lower(),
                    "value": str(val),
                    "confidence": 80,
                    "source": "",
                })
        return results

    return []


# ---------------------------------------------------------------------------
# Core watch cycle
# ---------------------------------------------------------------------------


async def run_watch_cycle(target: WatchTarget) -> dict:
    """
    Execute the configured module for target and return a normalised findings dict.

    Returns {"findings": list[dict], "session_name": str, "error": str | None}.
    """
    run_ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    session_name = f"{target.session_base}-{run_ts}"

    try:
        fn, arg_builder = _resolve_module(target.module)
        kwargs = arg_builder(target)
        raw_result = await fn(**kwargs)
        findings = _normalise_findings(raw_result)
        return {"findings": findings, "session_name": session_name, "error": None}

    except Exception as exc:
        return {"findings": [], "session_name": session_name, "error": str(exc)}


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------


async def compute_changes(old_findings: list[dict], new_findings: list[dict]) -> dict:
    """
    Diff two normalised findings lists.

    Identity key: (type, value).  Confidence differences on the same identity
    are classified as "changed" rather than added+removed.
    """
    old_index: dict[tuple[str, str], dict] = {
        (f["type"], f["value"]): f for f in old_findings
    }
    new_index: dict[tuple[str, str], dict] = {
        (f["type"], f["value"]): f for f in new_findings
    }

    old_keys = set(old_index)
    new_keys = set(new_index)

    added = [new_index[k] for k in sorted(new_keys - old_keys)]
    removed = [old_index[k] for k in sorted(old_keys - new_keys)]

    changed: list[dict] = []
    for key in sorted(old_keys & new_keys):
        old_f = old_index[key]
        new_f = new_index[key]
        if old_f.get("confidence") != new_f.get("confidence"):
            changed.append(
                {
                    "type": key[0],
                    "value": key[1],
                    "old_confidence": old_f.get("confidence"),
                    "new_confidence": new_f.get("confidence"),
                }
            )

    return {"added": added, "removed": removed, "changed": changed}


def _changes_summary(changes: dict, target: WatchTarget) -> str:
    """Build a short human-readable summary string from a changes dict."""
    parts: list[str] = []
    if changes["added"]:
        # Group by type for a richer summary
        by_type: dict[str, int] = {}
        for f in changes["added"]:
            by_type[f["type"]] = by_type.get(f["type"], 0) + 1
        parts.append(
            ", ".join(f"{count} new {t}" for t, count in sorted(by_type.items()))
        )
    if changes["removed"]:
        parts.append(f"{len(changes['removed'])} removed")
    if changes["changed"]:
        parts.append(f"{len(changes['changed'])} confidence change(s)")
    return ", ".join(parts) if parts else "no changes"


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------


async def notify_webhook(url: str, changes: dict, target: WatchTarget) -> None:
    """POST a JSON change payload to the configured webhook URL."""
    payload = {
        "tool": "osint-tool",
        "target": target.target,
        "target_type": target.target_type,
        "timestamp": datetime.now(UTC).isoformat(),
        "changes": {
            "added": changes["added"],
            "removed": changes["removed"],
            "changed": changes["changed"],
        },
        "summary": _changes_summary(changes, target),
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        print_warning(f"Webhook returned {exc.response.status_code}: {url}")
    except Exception as exc:
        print_warning(f"Webhook delivery failed ({url}): {exc}")


# ---------------------------------------------------------------------------
# Watch loop
# ---------------------------------------------------------------------------


async def watch_loop(targets: list[WatchTarget], stop_event: asyncio.Event) -> None:
    """
    Main watch daemon loop.

    Iterates over all targets on each tick and runs a scan cycle when the
    configured interval has elapsed since the last run.  Sleeps 30 seconds
    between ticks to avoid busy-spinning.
    """
    console = get_console()

    while not stop_event.is_set():
        for target in targets:
            now = datetime.now(UTC)
            elapsed = (
                (now - target.last_run).total_seconds()
                if target.last_run is not None
                else float("inf")
            )

            if elapsed < target.interval_seconds:
                continue

            console.print(
                f"[dim][{now.strftime('%H:%M:%S')}][/dim] "
                f"Running [bold]{target.module}[/bold] on [cyan]{target.target}[/cyan] ..."
            )

            result = await run_watch_cycle(target)

            if result["error"]:
                print_error(
                    f"Cycle failed for {target.target} ({target.module}): {result['error']}"
                )
                target.last_run = now
                continue

            new_findings: list[dict] = result["findings"]
            changes = await compute_changes(target._previous_findings, new_findings)

            has_changes = any(
                [changes["added"], changes["removed"], changes["changed"]]
            )

            if has_changes:
                summary = _changes_summary(changes, target)
                print_success(f"Changes detected on {target.target}: {summary}")

                if target.notify_webhook:
                    await notify_webhook(target.notify_webhook, changes, target)
            else:
                print_info(f"No changes for {target.target} ({len(new_findings)} finding(s))")

            # Update target state
            target._previous_findings = new_findings
            target.last_finding_count = len(new_findings)
            target.last_run = now

        # Avoid busy-spinning — check again after a short sleep
        try:
            await asyncio.wait_for(
                asyncio.shield(stop_event.wait()),
                timeout=30,
            )
        except asyncio.TimeoutError:
            pass


# ---------------------------------------------------------------------------
# Interval parsing
# ---------------------------------------------------------------------------


def parse_interval(s: str) -> int:
    """
    Parse a human interval string to seconds.

    Examples:
        "30m"  -> 1800
        "6h"   -> 21600
        "1d"   -> 86400
        "90s"  -> 90
        "3600" -> 3600 (bare integer treated as seconds)
    """
    s = s.strip().lower()

    if s.endswith("d"):
        return int(s[:-1]) * 86400
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("s"):
        return int(s[:-1])

    # Bare integer — assume seconds
    return int(s)
