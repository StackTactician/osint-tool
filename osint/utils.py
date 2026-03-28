from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import random
import re
import time
from typing import Any, AsyncIterator

import httpx
from email_validator import EmailNotValidError, validate_email
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9\u00a1-\uffff]"          # first label char (allows IDN)
    r"(?:[a-zA-Z0-9\u00a1-\uffff\-]{0,61}"
    r"[a-zA-Z0-9\u00a1-\uffff])?)?"
    r"(?:\.[a-zA-Z0-9\u00a1-\uffff]"
    r"(?:[a-zA-Z0-9\u00a1-\uffff\-]{0,61}"
    r"[a-zA-Z0-9\u00a1-\uffff])?)*"
    r"\.[a-zA-Z\u00a1-\uffff]{2,}$"
)

_PHONE_RE = re.compile(r"^\+?[\d\s\-\(\)]{7,20}$")

_ASN_RE = re.compile(r"^[Aa][Ss]\d+$")


def validate_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return a parsed IP address object, or None if the value is not a valid IP."""
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def validate_domain(value: str) -> str | None:
    """
    Validate a domain name (including IDN).
    Returns the normalized lowercase domain, or None if invalid.
    """
    stripped = value.strip().lower()
    # Strip a trailing dot (FQDN) for validation purposes
    candidate = stripped.rstrip(".")
    if not candidate or len(candidate) > 253:
        return None
    if not _DOMAIN_RE.match(candidate):
        return None
    return candidate


def validate_email_addr(value: str) -> str | None:
    """
    Validate an email address using the email-validator library.
    Returns the normalized email, or None if invalid.
    """
    try:
        info = validate_email(value.strip(), check_deliverability=False)
        return info.normalized
    except EmailNotValidError:
        return None


def validate_url(value: str) -> str | None:
    """
    Validate and normalize a URL.  Scheme must be http or https.
    Returns the normalized URL string, or None if invalid.
    """
    stripped = value.strip()
    try:
        parsed = urlparse(stripped)
    except Exception:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return stripped


def detect_target_type(value: str) -> str:
    """
    Auto-detect the type of an input string.

    Returns one of: "ip", "domain", "email", "url", "username",
                    "asn", "phone".
    """
    stripped = value.strip()

    # 1. IP address
    if validate_ip(stripped) is not None:
        return "ip"

    # 2. Email (contains @)
    if "@" in stripped and validate_email_addr(stripped) is not None:
        return "email"

    # 3. URL (has a recognised scheme)
    parsed = urlparse(stripped)
    if parsed.scheme in ("http", "https", "ftp") and parsed.netloc:
        return "url"

    # 4. Domain (contains a dot and passes domain validation)
    if "." in stripped and validate_domain(stripped) is not None:
        return "domain"

    # 5. ASN — e.g. AS12345 or as12345
    if _ASN_RE.match(stripped):
        return "asn"

    # 6. Phone — starts with + or is all digits/spaces/dashes
    if stripped.startswith("+") or (stripped[0].isdigit() if stripped else False):
        if _PHONE_RE.match(stripped):
            return "phone"

    # 7. Fall through to username
    return "username"


# ---------------------------------------------------------------------------
# Port range parser
# ---------------------------------------------------------------------------

def parse_port_range(spec: str) -> list[int]:
    """
    Parse a port specification such as "80,443,8000-8090,3306" into a
    sorted, deduplicated list of valid port integers (1-65535).

    Raises ValueError on invalid input.
    """
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_str, hi_str = part.split("-", 1)
            lo, hi = int(lo_str.strip()), int(hi_str.strip())
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise ValueError(f"Port out of range: {part}")
            if lo > hi:
                raise ValueError(f"Invalid port range (start > end): {part}")
            ports.update(range(lo, hi + 1))
        else:
            port = int(part)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port out of range: {port}")
            ports.add(port)
    return sorted(ports)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,fr;q=0.6",
    "en-US,en;q=0.9,de;q=0.7",
    "en-US,en;q=0.9,es;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.7",
]


def make_cache_key(url: str, params: dict = {}) -> str:
    """Return the SHA-256 hex digest of the URL combined with sorted params."""
    raw = url + str(sorted(params.items()))
    return hashlib.sha256(raw.encode()).hexdigest()


def make_http_client(
    proxy: str | None = None,
    timeout: int = 10,
    headers: dict = {},
) -> httpx.AsyncClient:
    """
    Return a configured async httpx client.

    Supports SOCKS5 and HTTP proxies.  Follows redirects and verifies TLS
    by default.
    """
    default_headers = {
        "User-Agent": _DEFAULT_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    default_headers.update(headers)

    return httpx.AsyncClient(
        headers=default_headers,
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
        verify=True,
        proxy=proxy or None,  # httpx >= 0.28 uses `proxy` (singular)
    )


def make_stealth_headers(base_headers: dict = {}) -> dict:
    """
    Return a dict of headers that mimic a real browser.

    Randomizes Accept-Language and includes Sec-Fetch-* headers.
    Merges with base_headers (base_headers take precedence).
    """
    headers = {
        "User-Agent": _DEFAULT_UA,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "Accept-Language": random.choice(_ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
    }
    headers.update(base_headers)
    return headers


# ---------------------------------------------------------------------------
# Collection utilities
# ---------------------------------------------------------------------------

def chunk_list(lst: list, size: int) -> list[list]:
    """Split *lst* into sublists of at most *size* elements."""
    if size < 1:
        raise ValueError("chunk size must be >= 1")
    return [lst[i : i + size] for i in range(0, len(lst), size)]


def flatten(nested: list[list]) -> list:
    """Flatten one level of nesting."""
    return [item for sublist in nested for item in sublist]


def safe_get(d: dict, *keys: str, default: Any = None) -> Any:
    """
    Safely navigate nested dicts without raising KeyError.

    Example::

        safe_get(data, "registrant", "email", default="")
    """
    current: Any = d
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
        if current is default:
            return default
    return current


def truncate(s: str, max_len: int = 80) -> str:
    """Truncate *s* to *max_len* characters, appending ellipsis if truncated."""
    if len(s) <= max_len:
        return s
    return s[: max(0, max_len - 3)] + "..."


def sha256_of(data: str | bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Async helpers
# ---------------------------------------------------------------------------

async def async_retry(
    coro_fn: Any,
    retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
) -> Any:
    """
    Call *coro_fn()* (a zero-argument coroutine factory) and retry on exception.

    Waits ``delay * backoff ** attempt`` seconds before each retry.
    Re-raises the last exception if all attempts are exhausted.

    Usage::

        result = await async_retry(lambda: fetch(url), retries=3, delay=0.5)
    """
    last_exc: BaseException | None = None
    for attempt in range(retries):
        try:
            return await coro_fn()
        except Exception as exc:
            last_exc = exc
            if attempt < retries - 1:
                wait = delay * (backoff ** attempt)
                await asyncio.sleep(wait)
    raise last_exc  # type: ignore[misc]


class RateLimiter:
    """
    Token-bucket rate limiter for async code.

    Limits callers to at most *calls_per_second* concurrent acquisitions per
    wall-clock second.
    """

    def __init__(self, calls_per_second: float) -> None:
        if calls_per_second <= 0:
            raise ValueError("calls_per_second must be > 0")
        self._min_interval: float = 1.0 / calls_per_second
        self._last_call: float = 0.0
        self._lock: asyncio.Lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait if necessary to respect the configured rate limit."""
        async with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()


class AsyncSemaphorePool:
    """
    Thin async context manager around asyncio.Semaphore that also tracks
    the number of currently active slots for progress-display purposes.
    """

    def __init__(self, max_concurrent: int) -> None:
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(max_concurrent)
        self._active: int = 0
        self._counter_lock: asyncio.Lock = asyncio.Lock()

    @property
    def active(self) -> int:
        """Number of currently acquired slots."""
        return self._active

    async def __aenter__(self) -> "AsyncSemaphorePool":
        await self._semaphore.acquire()
        async with self._counter_lock:
            self._active += 1
        return self

    async def __aexit__(self, *_: Any) -> None:
        async with self._counter_lock:
            self._active -= 1
        self._semaphore.release()
