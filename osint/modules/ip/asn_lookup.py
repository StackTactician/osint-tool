"""
osint/modules/ip/asn_lookup.py

ASN lookup via BGPView API.

Supports:
  - IP address  -> resolves to ASN then fetches ASN details + prefixes
  - ASN number  -> "15169" or "AS15169" -> fetches ASN details + prefixes

Also checks RPKI validity for the prefix containing the queried IP.
"""

from __future__ import annotations

import re

from osint.config import get_settings
from osint.output import (
    print_error,
    print_finding,
    print_info,
    print_panel,
    print_section,
    print_table,
    print_warning,
    severity_badge,
)
from osint.utils import make_http_client, validate_ip

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ASN_INPUT_RE = re.compile(r"^[Aa][Ss]?(\d+)$")

_BGPVIEW_BASE = "https://api.bgpview.io"
_RPKI_BASE = "https://rpki-validator.realmv6.org/api/v1/validity"


def _parse_asn_input(target: str) -> int | None:
    """
    Accept "15169", "AS15169", or "as15169".
    Returns the integer ASN, or None if target doesn't look like an ASN.
    """
    target = target.strip()
    m = _ASN_INPUT_RE.match(target)
    if m:
        return int(m.group(1))
    # Plain integer
    if target.isdigit():
        return int(target)
    return None


def _empty_result() -> dict:
    return {
        "asn": None,
        "asn_str": None,
        "name": None,
        "description": None,
        "country": None,
        "website": None,
        "abuse_contacts": [],
        "ipv4_prefixes": [],
        "ipv6_prefixes": [],
        "prefix_count_v4": 0,
        "prefix_count_v6": 0,
        "peers_count": None,
        "ip_queried": None,
        "ip_prefix": None,
        "rpki_valid": "not-found",
    }


# ---------------------------------------------------------------------------
# Main lookup function
# ---------------------------------------------------------------------------

async def lookup_asn(target: str) -> dict:
    """
    Look up ASN information for an IP address or ASN number.

    Returns a normalized dict. Never raises.
    """
    result = _empty_result()
    settings = get_settings()
    proxy = settings.effective_proxy

    asn_int: int | None = None
    ip_prefix: str | None = None
    queried_ip: str | None = None

    async with make_http_client(proxy=proxy, timeout=15) as client:

        # ---------------------------------------------------------------
        # Step 1 — resolve input to an ASN integer
        # ---------------------------------------------------------------
        maybe_asn = _parse_asn_input(target)

        if maybe_asn is not None:
            # Direct ASN input
            asn_int = maybe_asn
        else:
            # Assume it's an IP address
            addr = validate_ip(target)
            if addr is None:
                result["error"] = f"Invalid input: {target!r} is not an IP or ASN."
                return result

            queried_ip = target
            result["ip_queried"] = target

            try:
                resp = await client.get(f"{_BGPVIEW_BASE}/ip/{target}")
                resp.raise_for_status()
                payload = resp.json()

                prefixes = payload.get("data", {}).get("prefixes", [])
                if prefixes:
                    first = prefixes[0]
                    asn_info = first.get("asn", {})
                    asn_int = asn_info.get("asn")
                    ip_prefix = first.get("prefix")
                    result["ip_prefix"] = ip_prefix
            except Exception:
                pass

        if asn_int is None:
            result["error"] = f"Could not resolve ASN for: {target!r}"
            return result

        result["asn"] = asn_int
        result["asn_str"] = f"AS{asn_int}"

        # ---------------------------------------------------------------
        # Step 2 — fetch ASN details
        # ---------------------------------------------------------------
        try:
            resp = await client.get(f"{_BGPVIEW_BASE}/asn/{asn_int}")
            resp.raise_for_status()
            asn_data = resp.json().get("data", {})

            result["name"] = asn_data.get("name")
            result["description"] = asn_data.get("description_short") or asn_data.get("description_full")
            result["country"] = asn_data.get("country_code")
            result["website"] = asn_data.get("website")

            # Abuse contacts
            abuse: list[str] = []
            for email_entry in asn_data.get("abuse_contacts", []):
                if isinstance(email_entry, str):
                    abuse.append(email_entry)
                elif isinstance(email_entry, dict) and email_entry.get("email"):
                    abuse.append(email_entry["email"])
            result["abuse_contacts"] = abuse

        except Exception:
            pass

        # ---------------------------------------------------------------
        # Step 3 — fetch prefix lists
        # ---------------------------------------------------------------
        try:
            resp = await client.get(f"{_BGPVIEW_BASE}/asn/{asn_int}/prefixes")
            resp.raise_for_status()
            prefix_data = resp.json().get("data", {})

            ipv4: list[dict] = []
            for p in prefix_data.get("ipv4_prefixes", []):
                ipv4.append({
                    "prefix": p.get("prefix", ""),
                    "name": p.get("name"),
                    "country": p.get("country_code"),
                })

            ipv6: list[dict] = []
            for p in prefix_data.get("ipv6_prefixes", []):
                ipv6.append({
                    "prefix": p.get("prefix", ""),
                    "name": p.get("name"),
                    "country": p.get("country_code"),
                })

            result["ipv4_prefixes"] = ipv4
            result["ipv6_prefixes"] = ipv6
            result["prefix_count_v4"] = len(ipv4)
            result["prefix_count_v6"] = len(ipv6)

            # If we have an IP but no prefix yet, try to find it in the list
            if queried_ip and not ip_prefix and ipv4:
                result["ip_prefix"] = ipv4[0].get("prefix")
                ip_prefix = result["ip_prefix"]

        except Exception:
            pass

        # ---------------------------------------------------------------
        # Step 4 — RPKI validity for the prefix containing the queried IP
        # ---------------------------------------------------------------
        if ip_prefix:
            try:
                url = f"{_RPKI_BASE}/{asn_int}/{ip_prefix}"
                resp = await client.get(url)
                resp.raise_for_status()
                rpki_payload = resp.json()
                state = (
                    rpki_payload.get("state")
                    or rpki_payload.get("validated_route", {}).get("validity", {}).get("state")
                    or "not-found"
                )
                result["rpki_valid"] = state
            except Exception:
                result["rpki_valid"] = "not-found"

    return result


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def _rpki_badge(state: str) -> str:
    state = (state or "not-found").lower()
    if state == "valid":
        return "[bold green] VALID [/bold green]"
    if state == "invalid":
        return "[bold red] INVALID [/bold red]"
    return "[dim] NOT FOUND [/dim]"


def format_asn_output(data: dict) -> None:
    """Render ASN data using the osint.output helpers."""
    if "error" in data:
        print_error(f"ASN lookup failed: {data['error']}")
        return

    asn_str = data.get("asn_str") or f"AS{data.get('asn', '?')}"
    print_section(f"ASN -- {asn_str}")

    # --- Summary panel ---
    lines: list[str] = [
        f"  [bold bright_white]ASN:[/]         {asn_str}",
        f"  [bold bright_white]Name:[/]        {data.get('name') or '—'}",
        f"  [bold bright_white]Description:[/] {data.get('description') or '—'}",
        f"  [bold bright_white]Country:[/]     {data.get('country') or '—'}",
        f"  [bold bright_white]Website:[/]     {data.get('website') or '—'}",
        f"  [bold bright_white]RPKI:[/]        {_rpki_badge(data.get('rpki_valid', 'not-found'))}",
    ]

    if data.get("ip_queried"):
        lines.insert(1, f"  [bold bright_white]Queried IP:[/]  {data['ip_queried']}")
    if data.get("ip_prefix"):
        lines.insert(2, f"  [bold bright_white]IP Prefix:[/]   {data['ip_prefix']}")

    print_panel("ASN Information", "\n".join(lines), style="blue")

    # --- Abuse contacts ---
    abuse = data.get("abuse_contacts", [])
    if abuse:
        print_finding(
            "Abuse Contacts",
            "  ".join(abuse),
            source="bgpview",
        )

    # --- Prefix tables ---
    v4 = data.get("ipv4_prefixes", [])
    if v4:
        display = v4[:20]
        caption = f"(showing {len(display)} of {len(v4)})" if len(v4) > 20 else ""
        rows = [
            [p.get("prefix", ""), p.get("name") or "—", p.get("country") or "—"]
            for p in display
        ]
        print_table(
            f"IPv4 Prefixes ({data.get('prefix_count_v4', 0)} total)",
            ["Prefix", "Name", "Country"],
            rows,
            caption=caption,
        )

    v6 = data.get("ipv6_prefixes", [])
    if v6:
        display = v6[:20]
        caption = f"(showing {len(display)} of {len(v6)})" if len(v6) > 20 else ""
        rows = [
            [p.get("prefix", ""), p.get("name") or "—", p.get("country") or "—"]
            for p in display
        ]
        print_table(
            f"IPv6 Prefixes ({data.get('prefix_count_v6', 0)} total)",
            ["Prefix", "Name", "Country"],
            rows,
            caption=caption,
        )

    if not v4 and not v6:
        print_info("No prefix data available.")
