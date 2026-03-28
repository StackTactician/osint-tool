from __future__ import annotations

import click

from osint.output import print_warning


@click.group("ip")
def ip() -> None:
    """Investigate an IP address or autonomous system."""


@ip.command("geo")
@click.argument("ip_address")
@click.option("--ipinfo", is_flag=True, default=True, help="Enrich via IPinfo API.")
@click.option("--map", "show_map", is_flag=True, default=False, help="Render a Folium map of the location.")
@click.option("--vpn-check", is_flag=True, default=False, help="Check if IP is a known VPN/proxy exit node.")
@click.option("--tor-check", is_flag=True, default=False, help="Check if IP is a known Tor exit node.")
@click.option("--abuse-check", is_flag=True, default=False, help="Check AbuseIPDB reputation score.")
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
def geo(
    ctx: click.Context,
    ip_address: str,
    ipinfo: bool,
    show_map: bool,
    vpn_check: bool,
    tor_check: bool,
    abuse_check: bool,
    fmt: str,
    output: str | None,
) -> None:
    """Geolocate an IP address and check reputation."""
    print_warning("Module not yet implemented.")


@ip.command("asn")
@click.argument("ip_or_asn")
@click.option("--prefixes", is_flag=True, default=False, help="List all IP prefixes announced by the ASN.")
@click.option("--peers", is_flag=True, default=False, help="List BGP peers for the ASN.")
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
def asn(
    ctx: click.Context,
    ip_or_asn: str,
    prefixes: bool,
    peers: bool,
    fmt: str,
    output: str | None,
) -> None:
    """Look up ASN information for an IP address or ASN number."""
    print_warning("Module not yet implemented.")


@ip.command("rdns")
@click.argument("ip_address")
@click.option("--resolver", default=None, help="Custom DNS resolver IP.")
@click.option("--all-records", "all_records", is_flag=True, default=False, help="Fetch all PTR records (not just first).")
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
def rdns(
    ctx: click.Context,
    ip_address: str,
    resolver: str | None,
    all_records: bool,
    fmt: str,
    output: str | None,
) -> None:
    """Perform reverse DNS lookup on an IP address."""
    print_warning("Module not yet implemented.")


@ip.command("portscan")
@click.argument("host")
@click.option(
    "--ports",
    default="21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,27017",
    show_default=True,
    help="Comma-separated port list or range (e.g. 1-1024). Requires --active flag on parent.",
)
@click.option("--timeout", default=3, show_default=True, help="Per-port connect timeout in seconds.")
@click.option(
    "--workers",
    default=50,
    show_default=True,
    help="Concurrent connection workers.",
)
@click.option("--banner", is_flag=True, default=False, help="Attempt to grab service banners.")
@click.option("--shodan", is_flag=True, default=False, help="Supplement with Shodan passive data.")
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
def portscan(
    ctx: click.Context,
    host: str,
    ports: str,
    timeout: int,
    workers: int,
    banner: bool,
    shodan: bool,
    fmt: str,
    output: str | None,
) -> None:
    """Scan open ports on a host. Requires --active on the parent command."""
    print_warning("Module not yet implemented.")
