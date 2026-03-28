"""
osint/modules/ip/commands.py

Click command group for IP/network investigation.

Sub-commands:
  geo       -- Geolocate an IP address
  asn       -- Look up ASN information
  rdns      -- Reverse DNS lookup
  portscan  -- Active TCP port scan (requires --active)
  info      -- Combined: geo + asn + rdns + reputation in one pass
"""

from __future__ import annotations

import asyncio

import click

from osint.config import get_settings
from osint.events import Finding, FindingType, get_bus
from osint.output import (
    print_error,
    print_info,
    print_panel,
    print_section,
    print_warning,
    print_success,
)
from osint.utils import parse_port_range, validate_ip


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _session_id() -> int:
    """Return the current session ID from settings, defaulting to 0."""
    try:
        return int(get_settings().runtime.session or 0)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Command group
# ---------------------------------------------------------------------------

@click.group("ip")
def ip() -> None:
    """Investigate an IP address or autonomous system."""


# ---------------------------------------------------------------------------
# geo
# ---------------------------------------------------------------------------

@ip.command("geo")
@click.argument("ip_address")
@click.option("--ipinfo", is_flag=True, default=True, help="Enrich via IPinfo API.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
def geo(
    ip_address: str,
    ipinfo: bool,
    fmt: str,
    output: str | None,
) -> None:
    """Geolocate an IP address."""

    async def _run() -> None:
        from osint.modules.ip.geo_lookup import format_geo_output, lookup_geo
        from osint.modules.ip.asn_lookup import lookup_asn

        data = await lookup_geo(ip_address)

        if fmt == "json":
            from osint.output import print_json
            print_json(data, title=f"Geo -- {ip_address}")
        else:
            format_geo_output(data)

        if output:
            from osint.output import export_json
            export_json(data, output)

        # Publish findings to event bus
        bus = get_bus()
        session = _session_id()

        if data.get("valid") and not data.get("is_private"):
            # IP finding
            await bus.publish(Finding(
                type=FindingType.IP,
                value=ip_address,
                source="geo_lookup",
                confidence=90,
                session_id=session,
                raw_data=data,
            ))

            # ASN finding
            if data.get("asn"):
                await bus.publish(Finding(
                    type=FindingType.ASN,
                    value=data["asn"],
                    source="geo_lookup",
                    confidence=80,
                    session_id=session,
                    raw_data={"asn": data["asn"], "asname": data.get("asname")},
                ))

            # Coordinates finding
            lat = data.get("latitude")
            lon = data.get("longitude")
            if lat is not None and lon is not None:
                await bus.publish(Finding(
                    type=FindingType.GEO_COORD,
                    value=f"{lat},{lon}",
                    source="geo_lookup",
                    confidence=75,
                    session_id=session,
                    raw_data={
                        "latitude": lat,
                        "longitude": lon,
                        "city": data.get("city"),
                        "country": data.get("country"),
                    },
                ))

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# asn
# ---------------------------------------------------------------------------

@ip.command("asn")
@click.argument("ip_or_asn")
@click.option("--prefixes", is_flag=True, default=False, help="List all IP prefixes announced by the ASN.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
def asn(
    ip_or_asn: str,
    prefixes: bool,
    fmt: str,
    output: str | None,
) -> None:
    """Look up ASN information for an IP address or ASN number."""

    async def _run() -> None:
        from osint.modules.ip.asn_lookup import format_asn_output, lookup_asn

        data = await lookup_asn(ip_or_asn)

        if fmt == "json":
            from osint.output import print_json
            print_json(data, title=f"ASN -- {ip_or_asn}")
        else:
            format_asn_output(data)

        if output:
            from osint.output import export_json
            export_json(data, output)

        # Publish ASN finding
        if data.get("asn_str"):
            bus = get_bus()
            await bus.publish(Finding(
                type=FindingType.ASN,
                value=data["asn_str"],
                source="asn_lookup",
                confidence=90,
                session_id=_session_id(),
                raw_data=data,
            ))

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# rdns
# ---------------------------------------------------------------------------

@ip.command("rdns")
@click.argument("ip_address")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
def rdns(
    ip_address: str,
    fmt: str,
    output: str | None,
) -> None:
    """Perform reverse DNS lookup on an IP address."""

    async def _run() -> None:
        from osint.modules.ip.rdns_lookup import format_rdns_output, lookup_rdns

        data = await lookup_rdns(ip_address)

        if fmt == "json":
            from osint.output import print_json
            print_json(data, title=f"rDNS -- {ip_address}")
        else:
            format_rdns_output(data)

        if output:
            from osint.output import export_json
            export_json(data, output)

        # Publish DOMAIN findings for each verified hostname
        verified = data.get("verified_hostnames", [])
        if verified:
            bus = get_bus()
            session = _session_id()
            for hostname in verified:
                await bus.publish(Finding(
                    type=FindingType.DOMAIN,
                    value=hostname,
                    source="rdns_lookup",
                    confidence=85,
                    session_id=session,
                    raw_data={"ip": ip_address, "hostname": hostname},
                ))

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# portscan
# ---------------------------------------------------------------------------

@ip.command("portscan")
@click.argument("host")
@click.option(
    "--ports",
    default=None,
    help=(
        "Comma-separated port list or range (e.g. 1-1024,8080). "
        "Defaults to SANS top-20 + common web/db ports."
    ),
)
@click.option(
    "--timeout",
    default=1.0,
    show_default=True,
    type=float,
    help="Per-port connect timeout in seconds.",
)
@click.option(
    "--workers",
    default=100,
    show_default=True,
    type=int,
    help="Concurrent connection workers.",
)
@click.option(
    "--reputation",
    is_flag=True,
    default=False,
    help="Run reputation check on the target after scan.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
def portscan(
    host: str,
    ports: str | None,
    timeout: float,
    workers: int,
    reputation: bool,
    fmt: str,
    output: str | None,
) -> None:
    """Scan open ports on a host. Requires --active on the parent command group."""

    settings = get_settings()
    if not settings.runtime.active:
        print_error(
            "Port scanning is an active technique. Re-run with --active to enable it."
        )
        raise SystemExit(1)

    async def _run() -> None:
        from osint.modules.ip.port_scan import format_portscan_output, scan_ports

        # Parse port specification
        port_list: list[int] | None = None
        if ports:
            try:
                port_list = parse_port_range(ports)
            except ValueError as exc:
                print_error(f"Invalid port specification: {exc}")
                return

        data = await scan_ports(host, ports=port_list, timeout=timeout, workers=workers)

        if fmt == "json":
            from osint.output import print_json
            print_json(data, title=f"Port Scan -- {host}")
        else:
            format_portscan_output(data)

        if output:
            from osint.output import export_json
            export_json(data, output)

        # Optional reputation check
        if reputation:
            from osint.modules.ip.ip_reputation import check_reputation, format_reputation_output
            resolved_ip = data.get("resolved_ip", host)
            rep_data = await check_reputation(resolved_ip)
            if fmt == "json":
                from osint.output import print_json
                print_json(rep_data, title=f"Reputation -- {resolved_ip}")
            else:
                format_reputation_output(rep_data)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# reputation (standalone)
# ---------------------------------------------------------------------------

@ip.command("reputation")
@click.argument("ip_address")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
def reputation(
    ip_address: str,
    fmt: str,
    output: str | None,
) -> None:
    """Check IP reputation via AbuseIPDB, VirusTotal, OTX, and Shodan."""

    async def _run() -> None:
        from osint.modules.ip.ip_reputation import check_reputation, format_reputation_output

        data = await check_reputation(ip_address)

        if fmt == "json":
            from osint.output import print_json
            print_json(data, title=f"Reputation -- {ip_address}")
        else:
            format_reputation_output(data)

        if output:
            from osint.output import export_json
            export_json(data, output)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# info (combined)
# ---------------------------------------------------------------------------

@ip.command("info")
@click.argument("ip_address")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
def info(
    ip_address: str,
    fmt: str,
    output: str | None,
) -> None:
    """Run geo + ASN + rDNS + reputation all at once and show a unified summary."""

    async def _run() -> None:
        from osint.modules.ip.asn_lookup import format_asn_output, lookup_asn
        from osint.modules.ip.geo_lookup import format_geo_output, lookup_geo
        from osint.modules.ip.ip_reputation import check_reputation, format_reputation_output
        from osint.modules.ip.rdns_lookup import format_rdns_output, lookup_rdns

        addr = validate_ip(ip_address)
        if addr is None:
            print_error(f"Invalid IP address: {ip_address!r}")
            return

        print_info(f"Running full intelligence gathering for {ip_address} ...")

        # Run geo + rdns + reputation concurrently; ASN depends on geo for the
        # prefix hint so we run it separately after (still fast enough).
        geo_data, rdns_data, rep_data = await asyncio.gather(
            lookup_geo(ip_address),
            lookup_rdns(ip_address),
            check_reputation(ip_address),
        )
        asn_data = await lookup_asn(ip_address)

        if fmt == "json":
            from osint.output import print_json
            combined = {
                "ip": ip_address,
                "geo": geo_data,
                "asn": asn_data,
                "rdns": rdns_data,
                "reputation": rep_data,
            }
            print_json(combined, title=f"Full Intel -- {ip_address}")
            if output:
                from osint.output import export_json
                export_json(combined, output)
            return

        # --- Render each section ---
        format_geo_output(geo_data)
        format_asn_output(asn_data)
        format_rdns_output(rdns_data)
        format_reputation_output(rep_data)

        if output:
            from osint.output import export_json
            export_json(
                {
                    "ip": ip_address,
                    "geo": geo_data,
                    "asn": asn_data,
                    "rdns": rdns_data,
                    "reputation": rep_data,
                },
                output,
            )

        # --- Unified summary panel ---
        print_section(f"Summary -- {ip_address}")

        verdict = rep_data.get("verdict", "clean")
        verdict_color = {"malicious": "red", "suspicious": "yellow", "clean": "green"}.get(verdict, "white")

        geo_loc = "—"
        city = geo_data.get("city")
        country = geo_data.get("country")
        if city and country:
            geo_loc = f"{city}, {country}"
        elif country:
            geo_loc = country

        hostnames = rdns_data.get("verified_hostnames", []) or rdns_data.get("hostnames", [])
        hostname_display = hostnames[0] if hostnames else "—"

        summary_lines = [
            f"  [bold bright_white]IP:[/]          {ip_address}",
            f"  [bold bright_white]Location:[/]    {geo_loc}",
            f"  [bold bright_white]ISP/Org:[/]     {geo_data.get('org') or geo_data.get('isp') or '—'}",
            f"  [bold bright_white]ASN:[/]         {asn_data.get('asn_str') or '—'} {asn_data.get('name') or ''}",
            f"  [bold bright_white]Reverse DNS:[/] {hostname_display}",
            f"  [bold bright_white]Reputation:[/]  [{verdict_color}]{verdict.upper()}[/{verdict_color}]  "
            f"(score {rep_data.get('overall_score', 0)}/100)",
        ]

        risk_flags: list[str] = []
        if geo_data.get("is_proxy"):
            risk_flags.append("PROXY/VPN")
        if geo_data.get("is_tor"):
            risk_flags.append("TOR EXIT")
        if geo_data.get("is_hosting"):
            risk_flags.append("DATACENTER")
        if rep_data.get("cves"):
            risk_flags.append(f"{len(rep_data['cves'])} CVEs")

        if risk_flags:
            summary_lines.append(
                f"  [bold bright_white]Flags:[/]       [bold yellow]{'  '.join(risk_flags)}[/bold yellow]"
            )

        print_panel("Intelligence Summary", "\n".join(summary_lines), style="bright_blue")

        # Publish findings
        bus = get_bus()
        session = _session_id()

        await bus.publish(Finding(
            type=FindingType.IP,
            value=ip_address,
            source="ip_info",
            confidence=90,
            session_id=session,
            raw_data=geo_data,
        ))

        if asn_data.get("asn_str"):
            await bus.publish(Finding(
                type=FindingType.ASN,
                value=asn_data["asn_str"],
                source="ip_info",
                confidence=85,
                session_id=session,
                raw_data=asn_data,
            ))

        for hostname in rdns_data.get("verified_hostnames", []):
            await bus.publish(Finding(
                type=FindingType.DOMAIN,
                value=hostname,
                source="ip_info",
                confidence=85,
                session_id=session,
                raw_data={"ip": ip_address},
            ))

        lat = geo_data.get("latitude")
        lon = geo_data.get("longitude")
        if lat is not None and lon is not None:
            await bus.publish(Finding(
                type=FindingType.GEO_COORD,
                value=f"{lat},{lon}",
                source="ip_info",
                confidence=75,
                session_id=session,
                raw_data={
                    "latitude": lat,
                    "longitude": lon,
                    "city": geo_data.get("city"),
                    "country": geo_data.get("country"),
                },
            ))

    asyncio.run(_run())
