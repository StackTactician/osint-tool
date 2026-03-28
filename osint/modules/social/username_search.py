"""
osint/modules/social/username_search.py

Core async search engine for username enumeration across social platforms.

Probes each configured platform concurrently using aiohttp, capped by a
semaphore so we never open more than `workers` simultaneous connections.
Results are streamed to an optional callback as they arrive.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import AsyncIterator, Callable

import aiohttp

from osint.modules.social.platforms import PlatformDef, load_platforms
from osint.utils import make_stealth_headers


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class ProbeResult:
    """The outcome of probing a single platform for a given username."""

    platform: str
    url: str
    found: bool
    confidence: int
    status_code: int
    response_time_ms: int
    status: str  # "found" | "not_found" | "timeout" | "error" | "rate_limited"
    error: str | None = None
    tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Per-platform probe
# ---------------------------------------------------------------------------


async def probe_platform(
    session: aiohttp.ClientSession,
    platform: PlatformDef,
    username: str,
    semaphore: asyncio.Semaphore,
) -> ProbeResult:
    """
    Probe a single platform for the given username.

    Acquires the semaphore before making the request so that at most
    `workers` concurrent requests run at any moment.  Every exception is
    caught and returned as a typed error result so that one failing platform
    never interrupts the broader search.
    """
    async with semaphore:
        url = platform.build_url(username)
        start = time.monotonic()

        try:
            request_headers = {
                **make_stealth_headers(),
                **(platform.headers or {}),
            }
            async with session.request(
                platform.request_method,
                url,
                headers=request_headers,
                timeout=aiohttp.ClientTimeout(total=platform.timeout),
                allow_redirects=True,
                ssl=False,
            ) as resp:
                body = await resp.text(encoding="utf-8", errors="ignore")
                elapsed = int((time.monotonic() - start) * 1000)
                final_url = str(resp.url)

                # Detect rate limiting early so callers can surface it distinctly
                if resp.status == 429:
                    return ProbeResult(
                        platform=platform.name,
                        url=url,
                        found=False,
                        confidence=0,
                        status_code=resp.status,
                        response_time_ms=elapsed,
                        status="rate_limited",
                        tags=list(platform.tags or []),
                    )

                # Boost confidence when username appears in the response body.
                # check_found only has access to the body as a whole; we do the
                # username-in-body check here where username is in scope.
                found, confidence = platform.check_found(resp.status, body, final_url)

                if found and confidence < 90 and username.lower() in body.lower():
                    confidence = 90

                return ProbeResult(
                    platform=platform.name,
                    url=url,
                    found=found,
                    confidence=confidence,
                    status_code=resp.status,
                    response_time_ms=elapsed,
                    status="found" if found else "not_found",
                    tags=list(platform.tags or []),
                )

        except asyncio.TimeoutError:
            return ProbeResult(
                platform=platform.name,
                url=url,
                found=False,
                confidence=0,
                status_code=0,
                response_time_ms=platform.timeout * 1000,
                status="timeout",
                tags=list(platform.tags or []),
            )
        except aiohttp.ClientResponseError as exc:
            return ProbeResult(
                platform=platform.name,
                url=url,
                found=False,
                confidence=0,
                status_code=exc.status,
                response_time_ms=int((time.monotonic() - start) * 1000),
                status="error",
                error=f"HTTP error {exc.status}: {exc.message}",
                tags=list(platform.tags or []),
            )
        except Exception as exc:
            return ProbeResult(
                platform=platform.name,
                url=url,
                found=False,
                confidence=0,
                status_code=0,
                response_time_ms=int((time.monotonic() - start) * 1000),
                status="error",
                error=str(exc),
                tags=list(platform.tags or []),
            )


# ---------------------------------------------------------------------------
# Main search entry points
# ---------------------------------------------------------------------------


async def search_username(
    username: str,
    platforms: list[str] | None = None,
    timeout: int = 10,
    workers: int = 25,
    on_result: Callable[[ProbeResult], None] | None = None,
) -> list[ProbeResult]:
    """
    Search for *username* across all (or the specified subset of) platforms.

    Args:
        username:   The username string to probe.
        platforms:  Optional list of platform names to restrict the search to.
                    Case-insensitive.  Defaults to all loaded platforms.
        timeout:    Per-request timeout in seconds (overridden by platform-
                    specific timeouts defined in platforms.json).
        workers:    Maximum number of concurrent HTTP requests.
        on_result:  Optional synchronous callback invoked with each ProbeResult
                    as it completes.  Used for live display updates.

    Returns:
        Sorted list of ProbeResult: found entries first, then alphabetically
        by platform name within each group.
    """
    platform_defs = load_platforms(filter_names=platforms)

    if not platform_defs:
        return []

    semaphore = asyncio.Semaphore(workers)

    connector = aiohttp.TCPConnector(
        limit=workers,
        limit_per_host=2,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )

    base_headers = make_stealth_headers()

    async with aiohttp.ClientSession(
        connector=connector,
        headers=base_headers,
        cookie_jar=aiohttp.DummyCookieJar(),
    ) as session:
        tasks = [
            probe_platform(session, platform, username, semaphore)
            for platform in platform_defs
        ]

        results: list[ProbeResult] = []

        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            if on_result is not None:
                try:
                    on_result(result)
                except Exception:
                    pass  # never let a display callback abort the search

    return sorted(results, key=lambda r: (not r.found, r.platform.lower()))


async def search_username_stream(
    username: str,
    platforms: list[str] | None = None,
    timeout: int = 10,
    workers: int = 25,
) -> AsyncIterator[ProbeResult]:
    """
    Async generator that yields ProbeResult values as they arrive.

    Suitable for streaming results directly to a live display without
    buffering all results first.

    Usage::

        async for result in search_username_stream("johndoe"):
            display.on_result(result)
    """
    results_queue: asyncio.Queue[ProbeResult | None] = asyncio.Queue()

    async def _producer() -> None:
        await search_username(
            username,
            platforms=platforms,
            timeout=timeout,
            workers=workers,
            on_result=lambda r: results_queue.put_nowait(r),
        )
        await results_queue.put(None)  # sentinel signals exhaustion

    asyncio.create_task(_producer())

    while True:
        result = await results_queue.get()
        if result is None:
            break
        yield result
