"""
osint/modules/ip/geo_lookup.py

Multi-source IP geolocation with fallback chain.

Priority:
  1. ip-api.com    (45 req/min free, no key)
  2. ipwho.is      (fallback, no key)
  3. ipinfo.io     (enhancement, requires token)
"""

from __future__ import annotations

import ipaddress
from typing import Any

from osint.config import get_settings
from osint.output import (
    print_error,
    print_finding,
    print_info,
    print_panel,
    print_section,
    print_warning,
    severity_badge,
)
from osint.utils import make_http_client, validate_ip

# ---------------------------------------------------------------------------
# Bogon / RFC-1918 detection
# ---------------------------------------------------------------------------

_BOGON_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]


def _is_bogon(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or any(addr in net for net in _BOGON_NETWORKS)
    )


# ---------------------------------------------------------------------------
# Empty normalized result skeleton
# ---------------------------------------------------------------------------

def _empty_result(ip: str) -> dict:
    return {
        "ip": ip,
        "valid": False,
        "is_private": False,
        "is_bogon": False,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "postal": None,
        "latitude": None,
        "longitude": None,
        "timezone": None,
        "isp": None,
        "org": None,
        "asn": None,
        "asname": None,
        "is_proxy": False,
        "is_tor": False,
        "is_hosting": False,
        "is_mobile": False,
        "reverse_dns": None,
        "sources": [],
    }


# ---------------------------------------------------------------------------
# Source normalizers
# ---------------------------------------------------------------------------

def _parse_asn_from_string(raw: str | None) -> str | None:
    """Extract 'AS12345' from strings like 'AS12345 Google LLC'."""
    if not raw:
        return None
    parts = raw.strip().split()
    if parts and parts[0].upper().startswith("AS"):
        return parts[0].upper()
    return None


def _normalize_ip_api(data: dict) -> dict:
    """Map ip-api.com JSON response to the normalized schema."""
    # ip-api encodes ASN in the "as" field: "AS15169 Google LLC"
    raw_as = data.get("as", "")
    asn_parts = raw_as.strip().split(" ", 1)
    asn = asn_parts[0].upper() if asn_parts and asn_parts[0] else None
    asname = data.get("asname") or (asn_parts[1] if len(asn_parts) > 1 else None)

    result = _empty_result(data.get("query", ""))
    result.update({
        "valid": True,
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName") or data.get("region"),
        "city": data.get("city"),
        "postal": data.get("zip"),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": asn,
        "asname": asname,
        "is_proxy": bool(data.get("proxy", False)),
        "is_hosting": bool(data.get("hosting", False)),
        "is_mobile": bool(data.get("mobile", False)),
        "reverse_dns": data.get("reverse") or None,
        "sources": ["ip-api.com"],
    })
    return result


def _normalize_ipwho(data: dict) -> dict:
    """Map ipwho.is JSON response to the normalized schema."""
    connection = data.get("connection", {})
    raw_asn = connection.get("asn")
    asn = f"AS{raw_asn}" if raw_asn else None

    result = _empty_result(data.get("ip", ""))
    result.update({
        "valid": True,
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "postal": data.get("postal"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": (data.get("timezone") or {}).get("id"),
        "isp": connection.get("isp"),
        "org": connection.get("org"),
        "asn": asn,
        "asname": connection.get("asn_description") if isinstance(connection.get("asn_description"), str) else None,
        "is_proxy": bool(data.get("is_vpn") or data.get("is_datacenter") or data.get("is_proxy")),
        "is_hosting": bool(data.get("is_datacenter")),
        "is_mobile": bool(data.get("is_mobile")),
        "reverse_dns": None,
        "sources": ["ipwho.is"],
    })
    return result


def _merge_ipinfo(result: dict, data: dict) -> dict:
    """Enrich an existing result dict with ipinfo.io data."""
    result["sources"].append("ipinfo.io")

    # ipinfo has more authoritative org/ASN data: "AS15169 Google LLC"
    raw_org = data.get("org", "")
    if raw_org:
        asn = _parse_asn_from_string(raw_org)
        if asn:
            result["asn"] = asn
        org_name = raw_org.split(" ", 1)[1].strip() if " " in raw_org else raw_org
        if org_name:
            result["org"] = org_name

    # ipinfo company/hosting flags
    privacy = data.get("privacy", {})
    if isinstance(privacy, dict):
        if privacy.get("vpn") or privacy.get("proxy") or privacy.get("tor"):
            result["is_proxy"] = True
        if privacy.get("tor"):
            result["is_tor"] = True
        if privacy.get("hosting"):
            result["is_hosting"] = True

    # Fill in gaps if primary source missed them
    for field_name, ipinfo_key in [
        ("city", "city"),
        ("region", "region"),
        ("country_code", "country"),
        ("postal", "postal"),
        ("timezone", "timezone"),
        ("reverse_dns", "hostname"),
    ]:
        if not result.get(field_name) and data.get(ipinfo_key):
            result[field_name] = data[ipinfo_key]

    # Coordinates: ipinfo returns "lat,lon" string
    loc = data.get("loc", "")
    if loc and result.get("latitude") is None:
        try:
            lat_str, lon_str = loc.split(",", 1)
            result["latitude"] = float(lat_str)
            result["longitude"] = float(lon_str)
        except (ValueError, AttributeError):
            pass

    return result


# ---------------------------------------------------------------------------
# Main lookup function
# ---------------------------------------------------------------------------

async def lookup_geo(ip: str) -> dict:
    """
    Geolocate an IP address using a multi-source fallback chain.

    Returns a normalized dict. Never raises — returns result with
    valid=False on hard failure.
    """
    addr = validate_ip(ip)
    if addr is None:
        result = _empty_result(ip)
        result["valid"] = False
        return result

    # Short-circuit private/bogon IPs — no network calls needed
    is_private = addr.is_private or addr.is_loopback or addr.is_link_local
    is_bogon_flag = _is_bogon(addr)

    if is_private or is_bogon_flag:
        result = _empty_result(ip)
        result["valid"] = True
        result["is_private"] = is_private
        result["is_bogon"] = is_bogon_flag
        return result

    settings = get_settings()
    proxy = settings.effective_proxy
    result: dict | None = None

    async with make_http_client(proxy=proxy, timeout=10) as client:
        # --- Primary: ip-api.com ---
        try:
            fields = (
                "status,message,country,countryCode,region,regionName,"
                "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,"
                "mobile,proxy,hosting,query"
            )
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": fields},
            )
            resp.raise_for_status()
            payload = resp.json()
            if payload.get("status") == "success":
                result = _normalize_ip_api(payload)
        except Exception:
            pass

        # --- Fallback: ipwho.is ---
        if result is None:
            try:
                resp = await client.get(f"https://ipwho.is/{ip}")
                resp.raise_for_status()
                payload = resp.json()
                if payload.get("success", True):
                    result = _normalize_ipwho(payload)
            except Exception:
                pass

    # If both sources failed, return a minimal valid-but-empty result
    if result is None:
        result = _empty_result(ip)
        result["valid"] = True
        return result

    # --- Enhancement: ipinfo.io (separate client, needs auth header) ---
    token = settings.keys.ipinfo_token
    if token:
        try:
            async with make_http_client(
                proxy=proxy,
                timeout=10,
                headers={"Authorization": f"Bearer {token}"},
            ) as ipinfo_client:
                resp = await ipinfo_client.get(f"https://ipinfo.io/{ip}/json")
                resp.raise_for_status()
                payload = resp.json()
                if "ip" in payload:
                    result = _merge_ipinfo(result, payload)
        except Exception:
            pass  # ipinfo enhancement is best-effort

    result["is_private"] = is_private
    result["is_bogon"] = is_bogon_flag
    return result


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

# Country code -> unicode flag emoji mapping helper
def _country_flag(code: str | None) -> str:
    """Return a flag emoji for a 2-letter country code, or empty string."""
    if not code or len(code) != 2:
        return ""
    # Regional indicator letters: A=127462, B=127463 ... Z=127487
    offset = 127397  # ord('A') - 127462 = 65 - 127462
    try:
        return chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)
    except Exception:
        return ""


def format_geo_output(data: dict) -> None:
    """Render geolocation data using the osint.output helpers."""
    ip = data.get("ip", "unknown")

    if not data.get("valid"):
        print_error(f"Invalid IP address: {ip}")
        return

    print_section(f"Geolocation -- {ip}")

    if data.get("is_private"):
        print_warning("Private/loopback address -- geolocation not applicable.")
        print_info("This IP is in an RFC-1918, loopback, or link-local range.")
        return

    if data.get("is_bogon"):
        print_warning("Bogon address -- not routable on the public internet.")
        return

    sources = data.get("sources", [])
    print_info(f"Sources: {', '.join(sources) if sources else 'none'}")

    # --- Risk badges ---
    badges: list[str] = []
    if data.get("is_proxy"):
        badges.append("[bold yellow] PROXY/VPN [/bold yellow]")
    if data.get("is_tor"):
        badges.append("[bold red] TOR EXIT NODE [/bold red]")
    if data.get("is_hosting"):
        badges.append("[bold cyan] DATACENTER/HOSTING [/bold cyan]")
    if data.get("is_mobile"):
        badges.append("[dim] MOBILE [/dim]")

    if badges:
        print_warning("Risk flags: " + "  ".join(badges))

    # --- Location panel ---
    country_code = data.get("country_code")
    flag = _country_flag(country_code)
    country_display = f"{flag} {data.get('country') or ''} ({country_code})" if country_code else "—"

    lines: list[str] = [
        f"  [bold bright_white]IP:[/]           {ip}",
        f"  [bold bright_white]Country:[/]      {country_display}",
        f"  [bold bright_white]Region:[/]       {data.get('region') or '—'}",
        f"  [bold bright_white]City:[/]         {data.get('city') or '—'}",
        f"  [bold bright_white]Postal:[/]       {data.get('postal') or '—'}",
        f"  [bold bright_white]Timezone:[/]     {data.get('timezone') or '—'}",
    ]

    lat = data.get("latitude")
    lon = data.get("longitude")
    if lat is not None and lon is not None:
        maps_url = f"https://www.google.com/maps?q={lat},{lon}"
        lines.append(
            f"  [bold bright_white]Coordinates:[/] {lat}, {lon}  "
            f"[dim][link={maps_url}]Open in Google Maps[/link][/dim]"
        )
    else:
        lines.append("  [bold bright_white]Coordinates:[/] —")

    print_panel("Location", "\n".join(lines), style="cyan")

    # --- Network panel ---
    net_lines: list[str] = [
        f"  [bold bright_white]ISP:[/]        {data.get('isp') or '—'}",
        f"  [bold bright_white]Org:[/]        {data.get('org') or '—'}",
        f"  [bold bright_white]ASN:[/]        {data.get('asn') or '—'}",
        f"  [bold bright_white]AS Name:[/]    {data.get('asname') or '—'}",
        f"  [bold bright_white]Reverse DNS:[/] {data.get('reverse_dns') or '—'}",
    ]
    print_panel("Network", "\n".join(net_lines), style="blue")
