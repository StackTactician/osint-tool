from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Callable

import aiohttp

from osint.output import get_console, print_info, print_section, print_warning

# ---------------------------------------------------------------------------
# Platform data loader
# ---------------------------------------------------------------------------

_PLATFORMS_PATH = Path(__file__).parents[3] / "data" / "platforms.json"

_platforms_cache: list[dict] | None = None


def _load_platforms() -> list[dict]:
    global _platforms_cache
    if _platforms_cache is None:
        try:
            _platforms_cache = json.loads(_PLATFORMS_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError(
                f"Could not load platforms.json from {_PLATFORMS_PATH}: {exc}"
            ) from exc
    return _platforms_cache


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------


def _score_confidence(
    platform: dict,
    status_code: int,
    body: str,
    final_url: str,
    username: str,
) -> tuple[bool, int]:
    """
    Compute (found, confidence_pct) for a single platform response.

    Confidence logic:
      - Status-code check alone: base 70
      - body length > 500 bytes after a status hit: +10
      - username appears literally in body after a status hit: +15
      - body-text check (negative assertion): base 80 if no error text found
      - response_url check: base 75 if final URL does not match error pattern
    All checks cap at 100.
    """
    error_type = platform.get("error_type", "status_code")
    found = False
    confidence = 0

    if error_type == "status_code":
        error_code = platform.get("error_code", 404)
        found = status_code != error_code
        if found:
            confidence = 70
            if len(body) > 500:
                confidence += 10
            if username.lower() in body.lower():
                confidence += 15

    elif error_type == "body_text":
        error_text = platform.get("error_text", "")
        found = bool(error_text) and (error_text not in body)
        if found:
            confidence = 80
            if username.lower() in body.lower():
                confidence += 10

    elif error_type == "response_url":
        pattern = platform.get("error_url_pattern", "")
        if pattern:
            found = not bool(re.search(pattern, final_url))
        else:
            found = True
        if found:
            confidence = 75
            if username.lower() in body.lower():
                confidence += 10

    return found, min(confidence, 100)


# ---------------------------------------------------------------------------
# Per-platform fetch
# ---------------------------------------------------------------------------


async def _check_platform(
    session: aiohttp.ClientSession,
    platform: dict,
    username: str,
    semaphore: asyncio.Semaphore,
    timeout: int,
    on_result: Callable[[dict], None] | None,
) -> dict[str, Any]:
    name = platform["name"]
    url = platform["url_template"].format(username)
    extra_headers: dict = platform.get("headers", {}) or {}

    result: dict[str, Any] = {
        "platform": name,
        "url": url,
        "found": False,
        "confidence": 0,
        "status": "error",
        "tags": platform.get("tags", []),
    }

    async with semaphore:
        try:
            async with session.get(
                url,
                headers=extra_headers,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True,
                ssl=False,
            ) as resp:
                body = await resp.text(errors="replace")
                final_url = str(resp.url)
                status_code = resp.status

            found, confidence = _score_confidence(
                platform, status_code, body, final_url, username
            )
            result["found"] = found
            result["confidence"] = confidence
            result["status"] = "found" if found else "not_found"

        except asyncio.TimeoutError:
            result["status"] = "timeout"
        except Exception as exc:
            result["status"] = "error"
            result["error"] = str(exc)

    if on_result is not None:
        try:
            on_result(result)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# Main search function
# ---------------------------------------------------------------------------


async def search_username(
    username: str,
    platforms: list[str] | None = None,
    timeout: int = 10,
    workers: int = 20,
    on_result: Callable[[dict], None] | None = None,
) -> list[dict[str, Any]]:
    """
    Search for *username* across all platforms in platforms.json.

    Args:
        username:   The username to search for.
        platforms:  Optional list of platform names to restrict the search.
                    If None, all platforms are checked.
        timeout:    Per-request timeout in seconds.
        workers:    Maximum concurrent HTTP requests.
        on_result:  Optional callback invoked immediately after each platform
                    completes. Useful for live display updates.

    Returns:
        List of result dicts, one per platform checked.
    """
    all_platforms = _load_platforms()

    if platforms:
        normalized_filter = {p.lower() for p in platforms}
        targets = [p for p in all_platforms if p["name"].lower() in normalized_filter]
        missing = normalized_filter - {p["name"].lower() for p in targets}
        if missing:
            print_warning(f"Unknown platforms ignored: {', '.join(sorted(missing))}")
    else:
        targets = all_platforms

    if not targets:
        print_warning("No platforms to search.")
        return []

    semaphore = asyncio.Semaphore(workers)

    connector = aiohttp.TCPConnector(ssl=False, limit=workers)
    browser_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    async with aiohttp.ClientSession(
        headers=browser_headers,
        connector=connector,
        cookie_jar=aiohttp.CookieJar(unsafe=True),
    ) as session:
        tasks = [
            _check_platform(session, p, username, semaphore, timeout, on_result)
            for p in targets
        ]
        results = await asyncio.gather(*tasks)

    return list(results)


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------


def format_username_output(
    username: str,
    results: list[dict[str, Any]],
    found_only: bool = False,
) -> None:
    """Render username search results to the console as a grouped Rich table."""
    from rich import box
    from rich.table import Table
    from rich.text import Text

    console = get_console()

    found = [r for r in results if r.get("found")]
    not_found = [r for r in results if not r.get("found") and r.get("status") == "not_found"]
    errors = [r for r in results if r.get("status") in ("error", "timeout")]

    # ------------------------------------------------------------------
    # Found section
    # ------------------------------------------------------------------
    if found:
        print_section(f"Found ({len(found)})")
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold bright_white",
            border_style="bright_black",
        )
        table.add_column("Platform", no_wrap=True)
        table.add_column("URL")
        table.add_column("Confidence", justify="right")

        for r in sorted(found, key=lambda x: x.get("confidence", 0), reverse=True):
            conf = r.get("confidence", 0)
            if conf >= 90:
                conf_str = f"[bold green]{conf}%[/]"
            elif conf >= 70:
                conf_str = f"[green]{conf}%[/]"
            else:
                conf_str = f"[yellow]{conf}%[/]"

            url = r.get("url", "")
            url_markup = f"[link={url}]{url}[/link]"

            table.add_row(r["platform"], url_markup, conf_str)

        console.print(table)

    # ------------------------------------------------------------------
    # Not found section (only when not in found_only mode)
    # ------------------------------------------------------------------
    if not found_only and not_found:
        print_section(f"Not Found ({len(not_found)})")
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold bright_white",
            border_style="bright_black",
        )
        table.add_column("Platform", no_wrap=True)
        table.add_column("URL")

        for r in sorted(not_found, key=lambda x: x["platform"]):
            url = r.get("url", "")
            table.add_row(r["platform"], f"[dim]{url}[/]")

        console.print(table)

    # ------------------------------------------------------------------
    # Errors section
    # ------------------------------------------------------------------
    if not found_only and errors:
        print_section(f"Errors / Timeouts ({len(errors)})")
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold bright_white",
            border_style="bright_black",
        )
        table.add_column("Platform", no_wrap=True)
        table.add_column("Status")
        table.add_column("Detail")

        for r in sorted(errors, key=lambda x: x["platform"]):
            status = r.get("status", "error")
            detail = r.get("error", "") if status == "error" else ""
            status_str = (
                "[yellow]timeout[/]" if status == "timeout" else "[red]error[/]"
            )
            table.add_row(r["platform"], status_str, f"[dim]{detail}[/]")

        console.print(table)

    # ------------------------------------------------------------------
    # Summary line
    # ------------------------------------------------------------------
    total = len(results)
    summary_text = Text()
    summary_text.append("  Summary: ", style="dim")
    summary_text.append(f"{len(found)}", style="bold green")
    summary_text.append(f" found / ", style="dim")
    summary_text.append(f"{len(not_found)}", style="dim")
    summary_text.append(f" not found / ", style="dim")
    summary_text.append(f"{len(errors)}", style="yellow" if errors else "dim")
    summary_text.append(f" errors  —  {total} platforms checked", style="dim")
    console.print()
    console.print(summary_text)
    console.print()
