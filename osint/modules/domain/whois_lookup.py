"""
osint/modules/domain/whois_lookup.py

WHOIS and RDAP lookup with normalized output.

Primary source: python-whois (blocking, run in thread).
Fallback:       RDAP via rdap.org if python-whois fails or returns empty.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx
import whois  # python-whois

from osint.output import (
    print_error,
    print_finding,
    print_info,
    print_panel,
    print_section,
    print_table,
    print_warning,
)

# ---------------------------------------------------------------------------
# Privacy-protection proxy strings (case-insensitive substring match)
# ---------------------------------------------------------------------------

_PRIVACY_STRINGS = [
    "domains by proxy",
    "whoisguard",
    "privacyprotect",
    "redacted for privacy",
    "contact privacy",
    "perfect privacy",
    "withheld for privacy",
    "privacy hero",
    "private by design",
    "registrant redacted",
    "data protected",
    "not disclosed",
    "gdpr masking",
]


def _is_privacy_proxy(value: str | None) -> bool:
    if not value:
        return False
    lower = value.lower()
    return any(p in lower for p in _PRIVACY_STRINGS)


# ---------------------------------------------------------------------------
# Date normalization helpers
# ---------------------------------------------------------------------------

def _to_iso(value: Any) -> str | None:
    """Convert a datetime, list[datetime], or string to ISO-8601, or None."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0]  # python-whois can return lists for dates
    if isinstance(value, datetime):
        # Attach UTC if naive
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _to_str(value: Any) -> str | None:
    """Flatten a str or list[str] to a single string."""
    if value is None:
        return None
    if isinstance(value, list):
        # Filter empties and join
        parts = [str(v).strip() for v in value if v]
        return parts[0] if parts else None
    s = str(value).strip()
    return s if s else None


def _to_list(value: Any) -> list[str]:
    """Flatten a str or list[str] to a deduplicated list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        seen: set[str] = set()
        result: list[str] = []
        for v in value:
            s = str(v).strip().lower()
            if s and s not in seen:
                seen.add(s)
                result.append(str(v).strip())
        return result
    s = str(value).strip()
    return [s] if s else []


# ---------------------------------------------------------------------------
# RDAP mapping
# ---------------------------------------------------------------------------

def _extract_rdap_entity(entities: list[dict], role: str) -> dict:
    """Pull vcardArray data out of an RDAP entity matching a given role."""
    for entity in entities:
        roles = entity.get("roles", [])
        if role not in roles:
            continue
        vcard = entity.get("vcardArray", [])
        # vcard is [type, [[field, params, type, value], ...]]
        if not vcard or len(vcard) < 2:
            return {}
        fields: dict[str, str] = {}
        for item in vcard[1]:
            if not isinstance(item, (list, tuple)) or len(item) < 4:
                continue
            field_name = item[0]
            field_val = item[3]
            if isinstance(field_val, str):
                fields[field_name] = field_val
            elif isinstance(field_val, list):
                # ADR field is a structured list; join non-empty parts
                flat = ", ".join(str(v) for v in field_val if v)
                fields[field_name] = flat
        return fields
    return {}


def _map_rdap(domain: str, rdap: dict) -> dict:
    """Map a raw RDAP response dict to our normalized schema."""
    entities: list[dict] = rdap.get("entities", [])
    registrant = _extract_rdap_entity(entities, "registrant")
    admin = _extract_rdap_entity(entities, "administrative")
    tech = _extract_rdap_entity(entities, "technical")
    registrar_entity = _extract_rdap_entity(entities, "registrar")

    # Name servers
    name_servers: list[str] = []
    for ns in rdap.get("nameservers", []):
        ldhName = ns.get("ldhName") or ns.get("unicodeName") or ""
        if ldhName:
            name_servers.append(ldhName.lower())

    # Status
    statuses = [s for s in rdap.get("status", []) if isinstance(s, str)]

    # DNSSEC
    dnssec_delegation = rdap.get("secureDNS", {})
    dnssec = bool(
        dnssec_delegation.get("delegationSigned")
        or dnssec_delegation.get("dsData")
        or dnssec_delegation.get("keyData")
    )

    # Dates from events
    creation_date = expiration_date = updated_date = None
    for event in rdap.get("events", []):
        action = event.get("eventAction", "")
        date_str = event.get("eventDate", "")
        if action == "registration":
            creation_date = date_str
        elif action == "expiration":
            expiration_date = date_str
        elif action in ("last changed", "last update of RDAP database"):
            updated_date = date_str

    registrar_name = (
        registrar_entity.get("fn")
        or rdap.get("port43")
        or None
    )

    registrant_name = registrant.get("fn")
    registrant_email = registrant.get("email")
    registrant_org = registrant.get("org")
    registrant_country = registrant.get("country")

    privacy = any(
        _is_privacy_proxy(v)
        for v in [registrant_name, registrant_email, registrant_org]
    )

    return {
        "domain": domain,
        "registrar": registrar_name,
        "registrant_name": registrant_name,
        "registrant_email": registrant_email,
        "registrant_org": registrant_org,
        "registrant_country": registrant_country,
        "admin_email": admin.get("email"),
        "tech_email": tech.get("email"),
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "updated_date": updated_date,
        "name_servers": name_servers,
        "status": statuses,
        "dnssec": dnssec,
        "privacy_protected": privacy,
        "raw": "",
        "source": "rdap",
    }


# ---------------------------------------------------------------------------
# Main lookup function
# ---------------------------------------------------------------------------

async def lookup_whois(domain: str) -> dict:
    """
    Perform a WHOIS lookup for *domain*, falling back to RDAP.

    Returns a normalized dict. Never raises — returns {"error": str} on failure.
    """
    # --- Try python-whois first ---
    try:
        w = await asyncio.to_thread(whois.whois, domain)

        # python-whois returns an object that evaluates falsy when empty
        if w and (w.domain_name or w.registrar or w.creation_date):
            registrant_name = _to_str(getattr(w, "name", None))
            registrant_email = _to_str(getattr(w, "emails", None))
            registrant_org = _to_str(getattr(w, "org", None))
            registrant_country = _to_str(getattr(w, "country", None))
            registrar = _to_str(getattr(w, "registrar", None))
            admin_email = _to_str(getattr(w, "admin_email", None))
            tech_email = _to_str(getattr(w, "tech_email", None))

            # DNSSEC
            dnssec_raw = _to_str(getattr(w, "dnssec", None)) or ""
            dnssec = dnssec_raw.lower() not in ("unsigned", "inactive", "", "false")

            # Privacy detection
            privacy = any(
                _is_privacy_proxy(v)
                for v in [registrant_name, registrant_email, registrant_org, registrar]
            )

            return {
                "domain": domain,
                "registrar": registrar,
                "registrant_name": registrant_name,
                "registrant_email": registrant_email,
                "registrant_org": registrant_org,
                "registrant_country": registrant_country,
                "admin_email": admin_email,
                "tech_email": tech_email,
                "creation_date": _to_iso(getattr(w, "creation_date", None)),
                "expiration_date": _to_iso(getattr(w, "expiration_date", None)),
                "updated_date": _to_iso(getattr(w, "updated_date", None)),
                "name_servers": _to_list(getattr(w, "name_servers", None)),
                "status": _to_list(getattr(w, "status", None)),
                "dnssec": dnssec,
                "privacy_protected": privacy,
                "raw": str(w.text) if hasattr(w, "text") and w.text else "",
                "source": "whois",
            }
    except Exception:
        pass  # Fall through to RDAP

    # --- RDAP fallback ---
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(
                f"https://rdap.org/domain/{domain}",
                headers={"Accept": "application/rdap+json"},
            )
            resp.raise_for_status()
            rdap_data = resp.json()
        return _map_rdap(domain, rdap_data)
    except Exception as exc:
        return {"error": str(exc), "domain": domain}


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def format_whois_output(data: dict) -> None:
    """Render WHOIS data using the osint.output helpers."""
    if "error" in data:
        print_error(f"WHOIS lookup failed: {data['error']}")
        return

    print_section(f"WHOIS — {data.get('domain', 'unknown')}")

    # Source badge
    source = data.get("source", "unknown").upper()
    print_info(f"Data source: {source}")

    # Privacy warning
    if data.get("privacy_protected"):
        print_warning("Registrant data is privacy-protected / masked by a proxy service.")

    # Registrant panel
    registrant_lines: list[str] = []
    field_map = [
        ("Registrar", "registrar"),
        ("Registrant Name", "registrant_name"),
        ("Registrant Org", "registrant_org"),
        ("Registrant Country", "registrant_country"),
        ("Registrant Email", "registrant_email"),
        ("Admin Email", "admin_email"),
        ("Tech Email", "tech_email"),
    ]
    for label, key in field_map:
        val = data.get(key)
        if val:
            registrant_lines.append(f"  [bold bright_white]{label}:[/]  {val}")

    if registrant_lines:
        print_panel(
            "Registrant Information",
            "\n".join(registrant_lines),
            style="cyan",
        )

    # Dates table
    now = datetime.now(timezone.utc)
    expiry_str = data.get("expiration_date") or ""
    expiry_cell = expiry_str

    # Flag domains expiring within 30 days
    if expiry_str:
        try:
            exp_dt = datetime.fromisoformat(expiry_str)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            days_left = (exp_dt - now).days
            if days_left <= 30:
                expiry_cell = f"[bold red]{expiry_str} ({days_left}d remaining)[/bold red]"
        except ValueError:
            pass

    date_rows = [
        ["Created", data.get("creation_date") or "—"],
        ["Expires", expiry_cell],
        ["Updated", data.get("updated_date") or "—"],
    ]
    print_table("Domain Dates", ["Event", "Date"], date_rows)

    # Name servers
    ns_list = data.get("name_servers", [])
    if ns_list:
        ns_rows = [[ns] for ns in ns_list]
        print_table("Name Servers", ["Nameserver"], ns_rows)

    # Status
    statuses = data.get("status", [])
    if statuses:
        status_rows = [[s] for s in statuses]
        print_table("Domain Status", ["Status"], status_rows)

    # DNSSEC
    dnssec = data.get("dnssec", False)
    print_finding(
        "DNSSEC",
        "[bold green]Enabled[/bold green]" if dnssec else "[yellow]Disabled[/yellow]",
        source=source.lower(),
    )
