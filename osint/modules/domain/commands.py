"""
osint/modules/domain/commands.py

Click command group for domain reconnaissance.

Commands: whois, dns, subdomains, headers

Each command:
  1. Validates input
  2. Checks the cache
  3. Calls the relevant lookup coroutine
  4. Formats output
  5. Publishes findings to the event bus
  6. Persists to cache
  7. Optionally exports JSON
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import click

from osint.output import (
    export_json,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from osint.utils import validate_domain, make_cache_key


# ---------------------------------------------------------------------------
# Command group
# ---------------------------------------------------------------------------

@click.group("domain")
def domain() -> None:
    """Investigate a domain name."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _init_infra(ctx: click.Context) -> tuple[Any, Any, Any]:
    """
    Initialise settings, event bus, and database from the CLI context object.

    Returns (settings, bus, db) — all singletons.
    Lazy-imported to avoid circular imports at module load time.
    """
    from osint.config import init_settings, get_settings
    from osint.events import init_bus
    from osint.db import get_db

    obj: dict = ctx.obj or {}

    # Settings
    settings = get_settings()
    try:
        from pathlib import Path
        config_path = obj.get("config_path")
        settings = init_settings(
            config_path=Path(config_path) if config_path else None,
            active=obj.get("active", False),
            stealth=obj.get("stealth", False),
            tor=obj.get("tor", False),
            session=obj.get("session_name") or "",
            verbose=obj.get("verbosity") == "verbose",
        )
    except Exception:
        pass

    # Event bus
    bus = init_bus(active_mode=settings.runtime.active)

    # Database (not initialised here — callers that need persistence call
    # asyncio.run(db.init()) themselves)
    db = get_db()

    return settings, bus, db


async def _get_session_id(db: Any, domain_name: str, settings: Any) -> int:
    """Get or create a session and return its integer ID."""
    await db.init()
    session_name = settings.runtime.session or f"domain-{domain_name}"
    session = await db.get_or_create_session(
        name=session_name,
        seed=domain_name,
        seed_type="domain",
        active_mode=settings.runtime.active,
    )
    return session.id  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# whois command
# ---------------------------------------------------------------------------

@domain.command("whois")
@click.argument("domain_name")
@click.option("--history", is_flag=True, default=False, help="Fetch historical WHOIS records.")
@click.option("--raw", is_flag=True, default=False, help="Print raw WHOIS response.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.pass_context
def whois(
    ctx: click.Context,
    domain_name: str,
    history: bool,
    raw: bool,
    fmt: str,
    output: str | None,
) -> None:
    """Retrieve WHOIS registration data for a domain."""
    from osint.modules.domain.whois_lookup import lookup_whois, format_whois_output

    # Validate
    normalized = validate_domain(domain_name)
    if not normalized:
        print_error(f"Invalid domain name: {domain_name!r}")
        raise SystemExit(1)

    settings, bus, db = _init_infra(ctx)

    async def _run() -> None:
        from osint.events import Finding, FindingType

        # Cache check
        cache_key = make_cache_key(f"whois:{normalized}")
        cached = await db.cache_get(cache_key)
        if cached:
            print_info("(cached)")
            data = json.loads(cached)
        else:
            data = await lookup_whois(normalized)
            if "error" not in data:
                await db.cache_set(
                    key=cache_key,
                    url=f"whois:{normalized}",
                    body=json.dumps(data, default=str),
                    status=200,
                    ttl=3600 * 24,  # 24 hours
                )

        # Format output
        if fmt == "json":
            from osint.output import print_json
            print_json(data, title=f"WHOIS — {normalized}")
        else:
            format_whois_output(data)

        if raw and data.get("raw"):
            from osint.output import print_panel
            print_panel("Raw WHOIS", data["raw"], style="dim")

        # Publish findings to event bus
        if "error" not in data:
            session_id = await _get_session_id(db, normalized, settings)

            # Domain finding
            await bus.publish(Finding(
                type=FindingType.DOMAIN,
                value=normalized,
                source="whois",
                confidence=95,
                session_id=session_id,
                raw_data=data,
            ))

            # Registrant email
            for email_key in ("registrant_email", "admin_email", "tech_email"):
                email = data.get(email_key)
                if email and "@" in email:
                    await bus.publish(Finding(
                        type=FindingType.EMAIL,
                        value=email,
                        source="whois",
                        confidence=80,
                        session_id=session_id,
                        tags=[email_key],
                    ))

            # Organisation
            org = data.get("registrant_org")
            if org:
                await bus.publish(Finding(
                    type=FindingType.ORG,
                    value=org,
                    source="whois",
                    confidence=75,
                    session_id=session_id,
                ))

            # Persist DB finding
            await db.add_finding(
                session_id=session_id,
                type="domain",
                value=normalized,
                source="whois",
                confidence=95,
                raw_data=data,
                tags=["whois"],
            )

        # Export JSON if requested
        if output:
            export_json(data, output)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# dns command
# ---------------------------------------------------------------------------

@domain.command("dns")
@click.argument("domain_name")
@click.option(
    "--types",
    default="A,AAAA,MX,NS,TXT,SOA,CNAME,DMARC,DKIM,SPF,CAA",
    show_default=True,
    help="Comma-separated DNS record types to query.",
)
@click.option("--resolver", default=None, help="Custom DNS resolver IP (default: system resolver).")
@click.option("--trace", is_flag=True, default=False, help="Trace delegation chain from root.")
@click.option("--dnssec", is_flag=True, default=False, help="Validate DNSSEC chain.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.pass_context
def dns(
    ctx: click.Context,
    domain_name: str,
    types: str,
    resolver: str | None,
    trace: bool,
    dnssec: bool,
    fmt: str,
    output: str | None,
) -> None:
    """Query DNS records for a domain."""
    from osint.modules.domain.dns_lookup import lookup_records, format_dns_output

    normalized = validate_domain(domain_name)
    if not normalized:
        print_error(f"Invalid domain name: {domain_name!r}")
        raise SystemExit(1)

    requested_types = [t.strip().upper() for t in types.split(",") if t.strip()]
    settings, bus, db = _init_infra(ctx)

    async def _run() -> None:
        from osint.events import Finding, FindingType

        # Cache
        cache_key = make_cache_key(f"dns:{normalized}", {"types": types, "resolver": resolver or ""})
        cached = await db.cache_get(cache_key)
        if cached:
            print_info("(cached)")
            records = json.loads(cached)
        else:
            records = await lookup_records(normalized, types=requested_types, resolver_ip=resolver)
            await db.cache_set(
                key=cache_key,
                url=f"dns:{normalized}",
                body=json.dumps(records),
                status=200,
                ttl=3600,  # 1 hour
            )

        if fmt == "json":
            from osint.output import print_json
            print_json(records, title=f"DNS — {normalized}")
        else:
            format_dns_output(normalized, records)

        # Publish findings
        if records:
            session_id = await _get_session_id(db, normalized, settings)

            # A records -> IP findings
            for ip in records.get("A", []):
                await bus.publish(Finding(
                    type=FindingType.IP,
                    value=ip,
                    source="dns_a",
                    confidence=95,
                    session_id=session_id,
                    tags=["a_record"],
                ))
                await db.add_finding(
                    session_id=session_id,
                    type="ip",
                    value=ip,
                    source="dns_a",
                    confidence=95,
                    tags=["a_record"],
                )

            # AAAA records -> IP findings
            for ip in records.get("AAAA", []):
                await bus.publish(Finding(
                    type=FindingType.IP,
                    value=ip,
                    source="dns_aaaa",
                    confidence=95,
                    session_id=session_id,
                    tags=["aaaa_record"],
                ))

            # NS records -> domain findings
            for ns in records.get("NS", []):
                ns_clean = ns.rstrip(".")
                await bus.publish(Finding(
                    type=FindingType.DOMAIN,
                    value=ns_clean,
                    source="dns_ns",
                    confidence=80,
                    session_id=session_id,
                    tags=["nameserver"],
                ))

            await db.add_finding(
                session_id=session_id,
                type="domain",
                value=normalized,
                source="dns",
                confidence=95,
                raw_data=records,
                tags=["dns"],
            )

        if output:
            export_json(records, output)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# subdomains command
# ---------------------------------------------------------------------------

@domain.command("subdomains")
@click.argument("domain_name")
@click.option(
    "--wordlist",
    type=click.Path(exists=False),
    default=None,
    help="Custom wordlist file for brute-force.",
)
@click.option("--crt-sh", "crt_sh", is_flag=True, default=True, help="Enumerate via crt.sh certificate logs.")
@click.option("--brute", "brute", is_flag=True, default=False, help="Enable DNS brute-force (active).")
@click.option("--virustotal", is_flag=True, default=False, help="Enumerate via VirusTotal API.")
@click.option("--securitytrails", is_flag=True, default=False, help="Enumerate via SecurityTrails API.")
@click.option(
    "--workers",
    default=50,
    show_default=True,
    help="Concurrent workers for DNS resolution.",
)
@click.option("--timeout", default=10, show_default=True, help="Per-request timeout in seconds.")
@click.option("--resolve", is_flag=True, default=True, help="Resolve discovered subdomains to IPs.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.pass_context
def subdomains(
    ctx: click.Context,
    domain_name: str,
    wordlist: str | None,
    crt_sh: bool,
    brute: bool,
    virustotal: bool,
    securitytrails: bool,
    workers: int,
    timeout: int,
    resolve: bool,
    fmt: str,
    output: str | None,
) -> None:
    """Enumerate subdomains for a domain."""
    from osint.modules.domain.subdomain_enum import enumerate_subdomains, format_subdomain_output

    normalized = validate_domain(domain_name)
    if not normalized:
        print_error(f"Invalid domain name: {domain_name!r}")
        raise SystemExit(1)

    # Build source list
    sources: list[str] = []
    if crt_sh:
        sources.append("crt")
    sources.append("hackertarget")
    if brute:
        settings_check, _, _ = _init_infra(ctx)
        if not settings_check.runtime.active:
            print_warning(
                "DNS brute force requires --active mode. "
                "Re-run with the --active flag to enable."
            )
        else:
            sources.append("brute")

    settings, bus, db = _init_infra(ctx)

    async def _run() -> None:
        from osint.events import Finding, FindingType

        results = await enumerate_subdomains(
            domain=normalized,
            sources=sources,
            wordlist_path=wordlist,
            workers=workers,
        )

        if fmt == "json":
            from osint.output import print_json
            print_json(results, title=f"Subdomains — {normalized}")
        else:
            format_subdomain_output(normalized, results)

        # Publish findings
        if results:
            session_id = await _get_session_id(db, normalized, settings)

            for entry in results:
                sub = entry["subdomain"]
                await bus.publish(Finding(
                    type=FindingType.SUBDOMAIN,
                    value=sub,
                    source=entry["source"],
                    confidence=90 if entry["is_active"] else 70,
                    session_id=session_id,
                    tags=["active"] if entry["is_active"] else [],
                ))
                await db.add_finding(
                    session_id=session_id,
                    type="subdomain",
                    value=sub,
                    source=entry["source"],
                    confidence=90 if entry["is_active"] else 70,
                    raw_data=entry,
                )

                # Publish IPs
                for ip in entry.get("ips", []):
                    await bus.publish(Finding(
                        type=FindingType.IP,
                        value=ip,
                        source=f"dns_subdomain:{entry['source']}",
                        confidence=90,
                        session_id=session_id,
                        tags=["subdomain_ip", sub],
                    ))

        if output:
            export_json({"domain": normalized, "subdomains": results}, output)

        print_success(f"Subdomain enumeration complete: {len(results)} found.")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# headers command
# ---------------------------------------------------------------------------

@domain.command("headers")
@click.argument("url")
@click.option("--follow-redirects", "follow_redirects", is_flag=True, default=True, help="Follow HTTP redirects.")
@click.option("--tech", is_flag=True, default=True, help="Fingerprint technologies from headers and body.")
@click.option("--screenshot", is_flag=True, default=False, help="Capture a screenshot of the page.")
@click.option("--timeout", default=10, show_default=True, help="Request timeout in seconds.")
@click.option("--user-agent", default=None, help="Override the User-Agent header.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.pass_context
def headers(
    ctx: click.Context,
    url: str,
    follow_redirects: bool,
    tech: bool,
    screenshot: bool,
    timeout: int,
    user_agent: str | None,
    fmt: str,
    output: str | None,
) -> None:
    """Fetch HTTP headers and fingerprint technologies for a URL."""
    from osint.modules.domain.tech_detect import detect_technologies, format_tech_output
    from osint.modules.domain.git_scan import scan_git_exposure, format_git_output

    settings, bus, db = _init_infra(ctx)

    # Active-mode gate
    if not settings.runtime.active:
        print_warning(
            "The headers command sends HTTP requests to the target. "
            "Enable active mode with --active to proceed."
        )
        raise SystemExit(0)

    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    async def _run() -> None:
        from osint.events import Finding, FindingType
        from urllib.parse import urlparse

        parsed = urlparse(url)
        domain_name = parsed.netloc or parsed.path

        # Technology detection
        tech_data = await detect_technologies(url, follow_redirects=follow_redirects)

        if fmt == "json":
            from osint.output import print_json
            print_json(tech_data, title=f"Headers — {url}")
        else:
            format_tech_output(tech_data)

        # Git / config exposure scan
        git_findings = await scan_git_exposure(url)
        format_git_output(url, git_findings)

        # Publish findings
        if "error" not in tech_data and domain_name:
            normalized = validate_domain(domain_name)
            if normalized:
                session_id = await _get_session_id(db, normalized, settings)

                # URL finding
                await bus.publish(Finding(
                    type=FindingType.URL,
                    value=tech_data.get("final_url", url),
                    source="tech_detect",
                    confidence=95,
                    session_id=session_id,
                    raw_data=tech_data,
                ))
                await db.add_finding(
                    session_id=session_id,
                    type="url",
                    value=tech_data.get("final_url", url),
                    source="tech_detect",
                    confidence=95,
                    raw_data=tech_data,
                    tags=["headers"],
                )

                # Detected technologies as findings
                for t in tech_data.get("technologies", []):
                    await bus.publish(Finding(
                        type=FindingType.DOMAIN,
                        value=normalized,
                        source=f"tech:{t['name']}",
                        confidence=t["confidence"],
                        session_id=session_id,
                        tags=["technology", t["name"], t.get("category", "")],
                    ))

        # Export
        combined = {
            "tech": tech_data,
            "exposed_files": git_findings,
        }
        if output:
            export_json(combined, output)

    asyncio.run(_run())
