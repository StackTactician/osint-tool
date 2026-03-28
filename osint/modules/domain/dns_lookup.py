"""
osint/modules/domain/dns_lookup.py

Full DNS record enumeration with email security analysis.

Supports: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, DMARC, DKIM, SPF.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from osint.output import (
    print_finding,
    print_info,
    print_section,
    print_table,
    print_warning,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Standard record types queried by default
_DEFAULT_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]

# Record types that require a custom query name
_SPECIAL_QUERIES: dict[str, str] = {
    "DMARC": "_dmarc.{domain}",
    "DKIM": "default._domainkey.{domain}",
}

# All supported record types
ALL_TYPES = _DEFAULT_TYPES + ["SRV"] + list(_SPECIAL_QUERIES.keys()) + ["SPF"]


# ---------------------------------------------------------------------------
# Core resolver
# ---------------------------------------------------------------------------

async def _query_one(
    name: str,
    rdtype: str,
    resolver: dns.asyncresolver.Resolver,
) -> list[str]:
    """
    Resolve a single name/rdtype pair.

    Returns a list of string representations of all records found.
    Returns an empty list on NXDOMAIN, NoAnswer, or timeout.
    """
    try:
        answers = await resolver.resolve(name, rdtype, raise_on_no_answer=False)
        results: list[str] = []
        for rdata in answers:
            results.append(rdata.to_text())
        return results
    except (dns.exception.DNSException, Exception):
        return []


async def lookup_records(
    domain: str,
    types: list[str] | None = None,
    resolver_ip: str | None = None,
) -> dict[str, list[str]]:
    """
    Query all requested DNS record types concurrently for *domain*.

    Args:
        domain:      The domain to query.
        types:       List of record types. Defaults to all supported types.
        resolver_ip: Optional custom resolver IP (e.g. "8.8.8.8").

    Returns:
        Dict keyed by record type, values are lists of string record data.
        Only types with at least one result are included.
    """
    if types is None:
        types = _DEFAULT_TYPES + list(_SPECIAL_QUERIES.keys()) + ["SPF"]

    # Build resolver
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 10.0
    if resolver_ip:
        resolver.nameservers = [resolver_ip]

    # Build (key, query_name, rdtype_str) tuples
    tasks: list[tuple[str, str, str]] = []

    for rtype in types:
        rtype_upper = rtype.upper()

        if rtype_upper == "SPF":
            # SPF is filtered from TXT — we query TXT and filter below
            continue
        elif rtype_upper in _SPECIAL_QUERIES:
            query_name = _SPECIAL_QUERIES[rtype_upper].format(domain=domain)
            tasks.append((rtype_upper, query_name, "TXT"))
        else:
            tasks.append((rtype_upper, domain, rtype_upper))

    # Run all queries concurrently
    coros = [_query_one(query_name, rdtype_str, resolver) for _, query_name, rdtype_str in tasks]
    raw_results = await asyncio.gather(*coros, return_exceptions=True)

    records: dict[str, list[str]] = {}

    for (key, _, _), result in zip(tasks, raw_results):
        if isinstance(result, list) and result:
            records[key] = result

    # Derive SPF from TXT if requested and TXT was queried
    if "SPF" in types and "TXT" in records:
        spf_records = [r for r in records["TXT"] if "v=spf1" in r.lower()]
        if spf_records:
            records["SPF"] = spf_records

    return records


# ---------------------------------------------------------------------------
# SPF analysis
# ---------------------------------------------------------------------------

def analyze_spf(record: str) -> dict:
    """
    Parse an SPF record string.

    Returns:
        policy:      "pass", "softfail", "fail", "neutral"
        includes:    list of domains in 'include:' mechanisms
        mechanisms:  all mechanisms found
        is_spoofable: True if ~all / ?all / no all directive
    """
    # Strip surrounding quotes that DNS TXT records often have
    clean = record.strip('"').strip()

    mechanisms: list[str] = []
    includes: list[str] = []
    policy = "neutral"
    has_all = False

    for token in clean.split():
        mechanisms.append(token)
        lower = token.lower()
        if lower.startswith("include:"):
            includes.append(token[8:])
        elif lower == "+all":
            policy = "pass"
            has_all = True
        elif lower == "-all":
            policy = "fail"
            has_all = True
        elif lower == "~all":
            policy = "softfail"
            has_all = True
        elif lower == "?all":
            policy = "neutral"
            has_all = True
        elif lower == "all":
            # bare 'all' without qualifier defaults to +
            policy = "pass"
            has_all = True

    is_spoofable = not has_all or policy in ("softfail", "neutral", "pass")

    return {
        "policy": policy,
        "includes": includes,
        "mechanisms": mechanisms,
        "is_spoofable": is_spoofable,
    }


# ---------------------------------------------------------------------------
# DMARC analysis
# ---------------------------------------------------------------------------

def analyze_dmarc(record: str) -> dict:
    """
    Parse a DMARC TXT record.

    Returns:
        policy:           "none", "quarantine", "reject"
        subdomain_policy: same (defaults to domain policy if not set)
        rua:              list of reporting URIs
        pct:              enforcement percentage (int, 0-100)
        is_weak:          True if policy is "none" or pct < 100
    """
    clean = record.strip('"').strip()
    tags: dict[str, str] = {}

    for part in clean.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "none").lower()
    subdomain_policy = tags.get("sp", policy).lower()

    rua_raw = tags.get("rua", "")
    rua = [r.strip() for r in rua_raw.split(",") if r.strip()] if rua_raw else []

    try:
        pct = int(tags.get("pct", "100"))
    except ValueError:
        pct = 100

    is_weak = policy == "none" or pct < 100

    return {
        "policy": policy,
        "subdomain_policy": subdomain_policy,
        "rua": rua,
        "pct": pct,
        "is_weak": is_weak,
    }


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

_SECTION_ORDER = [
    "A", "AAAA", "CNAME", "NS", "MX", "SOA",
    "TXT", "SPF", "DMARC", "DKIM", "CAA", "SRV",
]


def format_dns_output(domain: str, records: dict[str, list[str]]) -> None:
    """Render all DNS records using osint.output helpers."""
    print_section(f"DNS Records — {domain}")

    if not records:
        print_info("No DNS records found.")
        return

    # Display types in a defined order, then any others alphabetically
    ordered_types = [t for t in _SECTION_ORDER if t in records]
    remaining = sorted(t for t in records if t not in ordered_types)

    for rtype in ordered_types + remaining:
        values = records[rtype]
        if not values:
            continue

        rows = [[v] for v in values]
        print_table(rtype, ["Record"], rows)

        # Inline analysis for email-security record types
        if rtype == "SPF":
            for record in values:
                analysis = analyze_spf(record)
                policy_color = "red" if analysis["is_spoofable"] else "green"
                print_finding(
                    "SPF Policy",
                    f"[{policy_color}]{analysis['policy']}[/{policy_color}]",
                    source="spf_analysis",
                )
                if analysis["is_spoofable"]:
                    print_warning(
                        f"SPF policy '{analysis['policy']}' allows email spoofing."
                    )
                if analysis["includes"]:
                    print_info(f"SPF includes: {', '.join(analysis['includes'])}")

        elif rtype == "DMARC":
            for record in values:
                analysis = analyze_dmarc(record)
                policy_color = (
                    "red" if analysis["policy"] == "none"
                    else "yellow" if analysis["policy"] == "quarantine"
                    else "green"
                )
                print_finding(
                    "DMARC Policy",
                    f"[{policy_color}]{analysis['policy']}[/{policy_color}]"
                    f"  (subdomain: {analysis['subdomain_policy']}, pct: {analysis['pct']}%)",
                    source="dmarc_analysis",
                )
                if analysis["is_weak"]:
                    reason = (
                        "p=none — DMARC does nothing, email is completely spoofable."
                        if analysis["policy"] == "none"
                        else f"pct={analysis['pct']}% — DMARC not fully enforced."
                    )
                    print_warning(reason)
                if analysis["rua"]:
                    print_info(f"DMARC reporting URIs: {', '.join(analysis['rua'])}")
