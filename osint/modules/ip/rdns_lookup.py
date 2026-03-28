"""
osint/modules/ip/rdns_lookup.py

Reverse DNS lookup with forward-confirmation and multi-resolver comparison.

Queries three public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9) and compares
their answers to detect split-horizon DNS or CDN manipulation.
"""

from __future__ import annotations

import asyncio
import ipaddress

import dns.asyncresolver
import dns.exception
import dns.name
import dns.reversename

from osint.output import (
    print_error,
    print_finding,
    print_info,
    print_panel,
    print_section,
    print_table,
    print_warning,
)
from osint.utils import validate_ip

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
_DNS_TIMEOUT = 5.0


# ---------------------------------------------------------------------------
# Low-level DNS helpers
# ---------------------------------------------------------------------------

async def _resolve_ptr(ip: str, nameserver: str) -> list[str]:
    """
    Query PTR records for *ip* using the specified *nameserver*.
    Returns a list of hostnames (stripped trailing dot). Empty on failure.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.lifetime = _DNS_TIMEOUT

    try:
        ptr_name = dns.reversename.from_address(ip)
        answer = await resolver.resolve(ptr_name, "PTR")
        return [str(rr.target).rstrip(".") for rr in answer]
    except (dns.exception.DNSException, Exception):
        return []


async def _resolve_a(hostname: str, nameserver: str) -> list[str]:
    """
    Forward-lookup a hostname for A records using the specified *nameserver*.
    Returns a list of IP strings. Empty on failure.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.lifetime = _DNS_TIMEOUT

    results: list[str] = []
    try:
        answer = await resolver.resolve(hostname, "A")
        results.extend(str(rr) for rr in answer)
    except (dns.exception.DNSException, Exception):
        pass

    # Also try AAAA for IPv6 source addresses
    try:
        answer = await resolver.resolve(hostname, "AAAA")
        results.extend(str(rr) for rr in answer)
    except (dns.exception.DNSException, Exception):
        pass

    return results


# ---------------------------------------------------------------------------
# Main lookup function
# ---------------------------------------------------------------------------

async def lookup_rdns(ip: str) -> dict:
    """
    Perform reverse DNS lookup for *ip*, querying three public resolvers.

    Returns a normalized dict. Never raises.
    """
    result: dict = {
        "ip": ip,
        "hostnames": [],
        "verified_hostnames": [],
        "unverified_hostnames": [],
        "resolver_results": {},
        "consensus": False,
    }

    addr = validate_ip(ip)
    if addr is None:
        result["error"] = f"Invalid IP address: {ip!r}"
        return result

    # -----------------------------------------------------------------------
    # Query all three resolvers concurrently
    # -----------------------------------------------------------------------
    async def _query_resolver(ns: str) -> tuple[str, list[str]]:
        hostnames = await _resolve_ptr(ip, ns)
        return ns, hostnames

    resolver_tasks = [_query_resolver(ns) for ns in _RESOLVERS]
    resolver_answers: list[tuple[str, list[str]]] = await asyncio.gather(
        *resolver_tasks, return_exceptions=False
    )

    resolver_results: dict[str, list[str]] = {}
    all_hostnames: set[str] = set()

    for ns, hostnames in resolver_answers:
        resolver_results[ns] = hostnames
        all_hostnames.update(hostnames)

    result["resolver_results"] = resolver_results

    # -----------------------------------------------------------------------
    # Consensus check: all resolvers returned the same set
    # -----------------------------------------------------------------------
    non_empty = [set(h) for h in resolver_results.values() if h]
    if non_empty:
        result["consensus"] = all(s == non_empty[0] for s in non_empty)
    else:
        result["consensus"] = True  # all empty = trivially consistent

    hostnames_list = sorted(all_hostnames)
    result["hostnames"] = hostnames_list

    if not hostnames_list:
        return result

    # -----------------------------------------------------------------------
    # Forward-confirm each hostname using the first resolver
    # -----------------------------------------------------------------------
    primary_ns = _RESOLVERS[0]
    verify_tasks = [_resolve_a(hostname, primary_ns) for hostname in hostnames_list]
    forward_results: list[list[str]] = await asyncio.gather(*verify_tasks)

    verified: list[str] = []
    unverified: list[str] = []

    for hostname, forward_ips in zip(hostnames_list, forward_results):
        if ip in forward_ips:
            verified.append(hostname)
        else:
            unverified.append(hostname)

    result["verified_hostnames"] = verified
    result["unverified_hostnames"] = unverified

    return result


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def format_rdns_output(data: dict) -> None:
    """Render reverse DNS data using the osint.output helpers."""
    ip = data.get("ip", "unknown")

    if "error" in data:
        print_error(f"rDNS lookup failed: {data['error']}")
        return

    print_section(f"Reverse DNS -- {ip}")

    hostnames = data.get("hostnames", [])
    if not hostnames:
        print_info("No PTR records found for this IP.")
        return

    # --- Verified hostnames ---
    verified = data.get("verified_hostnames", [])
    unverified = data.get("unverified_hostnames", [])

    if verified:
        rows = [[h, "[bold green]verified[/bold green]"] for h in verified]
        print_table("Hostnames", ["Hostname", "Status"], rows)

    if unverified:
        print_warning(
            f"{len(unverified)} unverified hostname(s) — forward A lookup does not "
            "confirm the original IP (possible CDN or misconfigured rDNS)."
        )
        rows = [[h, "[bold yellow]unverified[/bold yellow]"] for h in unverified]
        print_table("Unverified Hostnames", ["Hostname", "Status"], rows)

    # --- Per-resolver breakdown ---
    resolver_results = data.get("resolver_results", {})
    if resolver_results:
        rows = []
        for ns, names in resolver_results.items():
            rows.append([ns, ", ".join(names) if names else "—"])
        print_table("Resolver Breakdown", ["Resolver", "PTR Records"], rows)

    # --- Consensus warning ---
    if not data.get("consensus"):
        print_warning(
            "Resolvers returned different PTR records. "
            "This may indicate a CDN, split-horizon DNS, or MITM manipulation."
        )
    else:
        print_info("All resolvers agree on PTR records.")
