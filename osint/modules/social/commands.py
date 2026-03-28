"""
osint/modules/social/commands.py

Click command group for social-media OSINT.

Commands:
  username  - Probe N platforms concurrently for a given username.
  analyze   - Scrape a known profile URL and extract bio / links / avatar.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import click

from osint.output import (
    print_error,
    print_info,
    print_section,
    print_success,
    print_warning,
)


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@click.group("social")
def social() -> None:
    """Social media OSINT tools."""


# ---------------------------------------------------------------------------
# username
# ---------------------------------------------------------------------------


@social.command("username")
@click.argument("username")
@click.option(
    "--platforms",
    default=None,
    help="Comma-separated list of platforms to check (default: all).",
)
@click.option(
    "--tags",
    default=None,
    help="Filter platforms by tag (e.g. developer, social, gaming).",
)
@click.option(
    "--workers",
    default=25,
    show_default=True,
    type=int,
    help="Number of concurrent HTTP workers.",
)
@click.option(
    "--timeout",
    default=10,
    show_default=True,
    type=int,
    help="Per-request timeout in seconds.",
)
@click.option(
    "--found-only",
    "found_only",
    is_flag=True,
    default=False,
    help="Only display platforms where the username was found.",
)
@click.option(
    "--output-json",
    "output_json",
    default=None,
    type=click.Path(),
    help="Export full results to a JSON file.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Alias for --output-json.",
)
@click.pass_context
def username_cmd(
    ctx: click.Context,
    username: str,
    platforms: str | None,
    tags: str | None,
    workers: int,
    timeout: int,
    found_only: bool,
    output_json: str | None,
    output: str | None,
) -> None:
    """Search for USERNAME across social media platforms."""
    from osint.events import Finding, FindingType, get_bus
    from osint.modules.social.display import UsernameSearchDisplay
    from osint.modules.social.platforms import load_platforms
    from osint.modules.social.username_search import ProbeResult, search_username
    from osint.output import export_json

    # Resolve output path — --output-json takes precedence over -o
    out_path = output_json or output

    # Build the platform name filter
    platform_list: list[str] | None = None
    if platforms:
        platform_list = [p.strip() for p in platforms.split(",") if p.strip()]

    # Load platform definitions so we know the total before starting
    try:
        all_platforms = load_platforms(filter_names=platform_list)
    except (FileNotFoundError, ValueError) as exc:
        print_error(f"Could not load platform definitions: {exc}")
        raise SystemExit(1) from exc

    # Apply tag filter if requested
    if tags:
        tag_set = {t.strip().lower() for t in tags.split(",") if t.strip()}
        all_platforms = [p for p in all_platforms if tag_set & {t.lower() for t in (p.tags or [])}]

    if not all_platforms:
        print_warning("No platforms matched the given filter — nothing to search.")
        return

    total = len(all_platforms)
    # Build the actual name list from the filtered set so search_username
    # loads exactly the same subset without re-applying tag logic.
    resolved_names = [p.name for p in all_platforms]

    print_section(f"Username Search: {username}")
    print_info(f"Searching {total} platform{'s' if total != 1 else ''} with {workers} concurrent workers")

    results: list[ProbeResult] = []

    async def run() -> None:
        nonlocal results
        with UsernameSearchDisplay(username, total) as display:
            results = await search_username(
                username,
                platforms=resolved_names,
                timeout=timeout,
                workers=workers,
                on_result=display.on_result,
            )

        # Publish found profiles to the event bus for downstream correlation
        bus = get_bus()
        for r in results:
            if r.found:
                await bus.publish(
                    Finding(
                        type=FindingType.SOCIAL_PROFILE,
                        value=r.url,
                        source=f"social_{r.platform.lower()}",
                        confidence=r.confidence,
                        session_id=0,
                        raw_data={
                            "platform": r.platform,
                            "username": username,
                            "url": r.url,
                            "response_time_ms": r.response_time_ms,
                        },
                        tags=["social", r.platform.lower()] + list(r.tags or []),
                    )
                )

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print_warning("Search interrupted.")

    if out_path and results:
        try:
            export_json(
                {
                    "username": username,
                    "platforms_searched": total,
                    "found_count": sum(1 for r in results if r.found),
                    "results": [
                        {
                            "platform": r.platform,
                            "url": r.url,
                            "found": r.found,
                            "confidence": r.confidence,
                            "status_code": r.status_code,
                            "response_time_ms": r.response_time_ms,
                            "status": r.status,
                            "error": r.error,
                            "tags": r.tags,
                        }
                        for r in results
                    ],
                },
                out_path,
            )
        except Exception as exc:
            print_error(f"Failed to export JSON: {exc}")


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


@social.command("analyze")
@click.argument("url")
@click.option(
    "--output-json",
    "output_json",
    default=None,
    type=click.Path(),
    help="Export extracted data to a JSON file.",
)
@click.pass_context
def analyze_cmd(
    ctx: click.Context,
    url: str,
    output_json: str | None,
) -> None:
    """
    Analyze a social profile URL and extract bio, links, and avatar.

    Performs a direct HTTP request to the profile page and parses the
    HTML for publicly visible metadata.  This is an active operation —
    it makes a real outbound request to the target platform.

    Examples:

      osint social analyze https://github.com/johndoe
    """
    from osint.events import Finding, FindingType, get_bus
    from osint.output import export_json, print_finding, print_panel

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print_error(f"Invalid URL: {url!r}. Must be an http/https URL.")
        raise SystemExit(1)

    print_section(f"Profile Analysis: {url}")
    print_info("Fetching profile page...")

    extracted: dict[str, Any] = {
        "url": url,
        "bio": None,
        "avatar_url": None,
        "linked_urls": [],
        "title": None,
        "description": None,
    }

    async def run() -> None:
        import aiohttp

        from osint.utils import make_stealth_headers

        headers = make_stealth_headers()

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                connector=connector,
                headers=headers,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=20),
                    allow_redirects=True,
                ) as resp:
                    if resp.status != 200:
                        print_warning(f"Profile returned HTTP {resp.status}. Analysis may be incomplete.")

                    body = await resp.text(encoding="utf-8", errors="ignore")
                    _parse_profile_html(body, url, extracted)

        except asyncio.TimeoutError:
            print_error("Request timed out after 20 seconds.")
        except Exception as exc:
            print_error(f"Request failed: {exc}")

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print_warning("Analysis interrupted.")
        return

    # Display results
    _print_analysis_results(extracted)

    # Publish findings to event bus
    async def publish_findings() -> None:
        bus = get_bus()

        if extracted["bio"]:
            await bus.publish(
                Finding(
                    type=FindingType.URL,
                    value=url,
                    source="social_analyze",
                    confidence=70,
                    session_id=0,
                    raw_data=extracted,
                    tags=["social", "profile", "bio"],
                )
            )

        for linked in extracted["linked_urls"]:
            await bus.publish(
                Finding(
                    type=FindingType.URL,
                    value=linked,
                    source="social_analyze_link",
                    confidence=60,
                    session_id=0,
                    raw_data={"source_profile": url, "linked_url": linked},
                    tags=["social", "profile_link"],
                )
            )

    try:
        asyncio.run(publish_findings())
    except Exception:
        pass  # event bus errors are non-fatal

    if output_json:
        try:
            from osint.output import export_json
            export_json(extracted, output_json)
        except Exception as exc:
            print_error(f"Failed to export JSON: {exc}")


# ---------------------------------------------------------------------------
# HTML parsing helpers for analyze
# ---------------------------------------------------------------------------


def _parse_profile_html(html: str, base_url: str, extracted: dict[str, Any]) -> None:
    """
    Parse profile HTML and populate the extracted dict in-place.

    Uses lightweight regex-based extraction to avoid pulling in a full
    HTML parser dependency.  Targets Open Graph tags, meta description,
    and common avatar / bio patterns.
    """
    # -- Page title --
    title_match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
    if title_match:
        extracted["title"] = _clean_text(title_match.group(1))

    # -- Open Graph / Twitter Card meta tags --
    og_desc = _meta_content(html, "og:description")
    tw_desc = _meta_content(html, "twitter:description")
    meta_desc = _meta_content(html, "description")
    extracted["description"] = og_desc or tw_desc or meta_desc

    og_image = _meta_content(html, "og:image")
    tw_image = _meta_content(html, "twitter:image")
    extracted["avatar_url"] = og_image or tw_image or _find_avatar_heuristic(html, base_url)

    # -- Bio: prefer OG description, fall back to meta description --
    extracted["bio"] = extracted["description"]

    # -- Extract URLs from the body text (href and src attributes) --
    href_urls = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
    src_urls = re.findall(r'src=["\']([^"\']+)["\']', html, re.IGNORECASE)

    linked: list[str] = []
    seen: set[str] = set()

    for raw_url in href_urls + src_urls:
        raw_url = raw_url.strip()
        if not raw_url or raw_url.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        # Resolve relative URLs against the base page URL
        if raw_url.startswith("//"):
            raw_url = "https:" + raw_url
        elif raw_url.startswith("/"):
            parsed_base = urlparse(base_url)
            raw_url = f"{parsed_base.scheme}://{parsed_base.netloc}{raw_url}"

        parsed = urlparse(raw_url)
        if parsed.scheme not in ("http", "https"):
            continue

        # Exclude same-domain URLs — only surface off-site links
        base_host = urlparse(base_url).netloc
        if parsed.netloc == base_host or not parsed.netloc:
            continue

        normalized = raw_url.split("?")[0].rstrip("/")
        if normalized in seen:
            continue
        seen.add(normalized)
        linked.append(raw_url)

    extracted["linked_urls"] = linked[:50]  # cap to 50 to avoid noise


def _meta_content(html: str, name: str) -> str | None:
    """Extract the content attribute of a named meta tag."""
    # Matches both name= and property= variants
    pattern = (
        rf'<meta[^>]+(?:name|property)=["\'](?:twitter:|og:)?{re.escape(name.split(":")[-1])}'
        rf'["\'][^>]+content=["\']([^"\']+)["\']'
        r"|"
        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:name|property)=["\'](?:twitter:|og:)?'
        rf'{re.escape(name.split(":")[-1])}'
        rf'["\']'
    )
    match = re.search(pattern, html, re.IGNORECASE)
    if match:
        value = match.group(1) or match.group(2)
        if value:
            return _clean_text(value)
    return None


def _find_avatar_heuristic(html: str, base_url: str) -> str | None:
    """
    Fallback avatar detection using common HTML patterns when OG tags are absent.

    Looks for img tags with common avatar-related class or id attributes.
    """
    patterns = [
        r'<img[^>]+(?:class|id)=["\'][^"\']*avatar[^"\']*["\'][^>]+src=["\']([^"\']+)["\']',
        r'<img[^>]+src=["\']([^"\']+)["\'][^>]+(?:class|id)=["\'][^"\']*avatar[^"\']*["\']',
        r'<img[^>]+(?:class|id)=["\'][^"\']*profile-pic[^"\']*["\'][^>]+src=["\']([^"\']+)["\']',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            src = m.group(1).strip()
            if src.startswith("//"):
                return "https:" + src
            if src.startswith("/"):
                parsed = urlparse(base_url)
                return f"{parsed.scheme}://{parsed.netloc}{src}"
            if src.startswith("http"):
                return src
    return None


def _clean_text(s: str) -> str:
    """Strip HTML entities and excess whitespace from extracted text."""
    # Basic entity decoding for the most common cases
    entities = {
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&#39;": "'",
        "&nbsp;": " ",
    }
    for entity, char in entities.items():
        s = s.replace(entity, char)
    return " ".join(s.split())


def _print_analysis_results(extracted: dict[str, Any]) -> None:
    """Print the extracted profile data using the standard output helpers."""
    from osint.output import print_finding

    if extracted.get("title"):
        print_finding("Title", extracted["title"])

    if extracted.get("bio"):
        print_finding("Bio", extracted["bio"])

    if extracted.get("avatar_url"):
        print_finding("Avatar", extracted["avatar_url"])

    linked = extracted.get("linked_urls", [])
    if linked:
        print_info(f"Found {len(linked)} off-site linked URL{'s' if len(linked) != 1 else ''}:")
        for link_url in linked[:20]:
            print_finding("Link", link_url)
        if len(linked) > 20:
            print_info(f"  ... and {len(linked) - 20} more (export with --output-json to see all).")
    else:
        print_info("No off-site linked URLs found.")

    if not any([extracted.get("title"), extracted.get("bio"), linked]):
        print_warning("No structured metadata could be extracted from this page.")
