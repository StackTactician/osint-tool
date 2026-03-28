"""
osint/correlations.py

Auto-correlation rules that wire the OSINT module graph together.

Each rule is an async function that:
  1. Receives a Finding that matched its trigger type
  2. Performs one or more lookups (passive by default)
  3. Returns a list of new Finding objects to publish back onto the bus

All handler exceptions are caught and result in an empty return — correlation
rules must never crash the main flow.

Blocking third-party calls (dnspython, python-whois) are dispatched via
asyncio.to_thread() so they don't stall the event loop.

Imports of heavy modules (dns, whois, httpx) are deferred to handler bodies
to avoid circular import chains at startup.

Call register_all_correlations(bus) once at CLI startup.
"""

from __future__ import annotations

from urllib.parse import urlparse

from osint.events import (
    CorrelationRule,
    EventBus,
    Finding,
    FindingType,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _child(
    parent: Finding,
    *,
    type: FindingType,
    value: str,
    source: str,
    confidence: int,
    tags: list[str] | None = None,
    raw_data: dict | None = None,
) -> Finding:
    """Construct a child Finding that records its parent's db_id."""
    return Finding(
        type=type,
        value=value,
        source=source,
        confidence=confidence,
        session_id=parent.session_id,
        parent_id=parent.db_id,
        tags=tags or [],
        raw_data=raw_data or {},
    )


# ---------------------------------------------------------------------------
# Rule handlers
# ---------------------------------------------------------------------------


async def _handle_email_to_domain(finding: Finding) -> list[Finding]:
    """
    EMAIL → DOMAIN

    Extracts the domain portion of an email address.  This is a pure string
    operation — no network call, no failure modes.
    """
    try:
        parts = finding.value.split("@", 1)
        if len(parts) != 2 or not parts[1]:
            return []
        domain = parts[1].strip().lower()
        if not domain:
            return []
        return [
            _child(
                finding,
                type=FindingType.DOMAIN,
                value=domain,
                source="email_domain_extraction",
                confidence=99,
            )
        ]
    except Exception:
        return []


async def _handle_email_to_username(finding: Finding) -> list[Finding]:
    """
    EMAIL → USERNAME (candidate)

    Extracts the local-part of an email as a probable username.  Marked with
    the "email_derived" tag so consumers know it's a guess, not a confirmed
    account.
    """
    try:
        local = finding.value.split("@", 1)[0].strip()
        if not local:
            return []
        return [
            _child(
                finding,
                type=FindingType.USERNAME,
                value=local,
                source="email_local_part",
                confidence=60,
                tags=["email_derived"],
            )
        ]
    except Exception:
        return []


async def _handle_domain_to_dns(finding: Finding) -> list[Finding]:
    """
    DOMAIN → IP (A records)

    Resolves the domain's A records.  Uses dnspython's synchronous resolver
    dispatched to a thread so the event loop stays unblocked.
    """
    import dns.resolver  # type: ignore[import-untyped]

    def _resolve(domain: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=10)
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    try:
        import asyncio
        ips = await asyncio.to_thread(_resolve, finding.value)
        results: list[Finding] = []
        for ip in ips:
            results.append(
                _child(
                    finding,
                    type=FindingType.IP,
                    value=ip,
                    source="dns_a_record",
                    confidence=99,
                )
            )
        return results
    except Exception:
        return []


async def _handle_domain_to_whois_email(finding: Finding) -> list[Finding]:
    """
    DOMAIN → EMAIL (WHOIS registrant)

    Performs a WHOIS lookup and extracts any registrant or admin email
    addresses found in the record.
    """
    import asyncio
    import whois  # type: ignore[import-untyped]

    def _whois_lookup(domain: str) -> list[str]:
        try:
            w = whois.whois(domain)
            emails: list[str] = []

            # python-whois returns emails as a string or list depending on record
            raw_emails = w.emails
            if raw_emails is None:
                return []
            if isinstance(raw_emails, str):
                raw_emails = [raw_emails]
            for e in raw_emails:
                e = e.strip().lower()
                if e and "@" in e:
                    emails.append(e)
            return emails
        except Exception:
            return []

    try:
        emails = await asyncio.to_thread(_whois_lookup, finding.value)
        results: list[Finding] = []
        for email in emails:
            results.append(
                _child(
                    finding,
                    type=FindingType.EMAIL,
                    value=email,
                    source="whois_registrant",
                    confidence=75,
                )
            )
        return results
    except Exception:
        return []


async def _handle_ip_to_geo(finding: Finding) -> list[Finding]:
    """
    IP → GEO_COORD + ASN

    Calls ip-api.com (no API key required for non-commercial use, passive).
    Publishes:
      - A GEO_COORD finding if lat/lon are present
      - An ASN finding if AS number is present

    Full geo data is stored in the GEO_COORD finding's raw_data.
    """
    import asyncio
    import httpx

    def _geo_lookup(ip: str) -> dict:
        try:
            url = (
                f"http://ip-api.com/json/{ip}"
                "?fields=status,country,countryCode,region,regionName,"
                "city,zip,lat,lon,timezone,isp,org,as,asname,query"
            )
            with httpx.Client(timeout=10) as client:
                resp = client.get(url)
                resp.raise_for_status()
                return resp.json()
        except Exception:
            return {}

    try:
        data = await asyncio.to_thread(_geo_lookup, finding.value)
        if not data or data.get("status") != "success":
            return []

        results: list[Finding] = []

        lat = data.get("lat")
        lon = data.get("lon")
        if lat is not None and lon is not None:
            results.append(
                _child(
                    finding,
                    type=FindingType.GEO_COORD,
                    value=f"{lat},{lon}",
                    source="ip_api_geo",
                    confidence=90,
                    raw_data=data,
                )
            )

        asn_raw: str = data.get("as", "")  # e.g. "AS15169 Google LLC"
        if asn_raw:
            asn_number = asn_raw.split(" ", 1)[0]  # "AS15169"
            org_name = data.get("org") or data.get("isp") or ""
            results.append(
                _child(
                    finding,
                    type=FindingType.ASN,
                    value=asn_number,
                    source="ip_api_geo",
                    confidence=90,
                    raw_data={"org": org_name, "asname": data.get("asname", "")},
                )
            )

        return results
    except Exception:
        return []


async def _handle_ip_to_rdns(finding: Finding) -> list[Finding]:
    """
    IP → DOMAIN (reverse DNS)

    Performs a PTR record lookup.  A successful rDNS entry indicates a
    hostname associated with the IP, often a useful pivot point.
    """
    import asyncio
    import dns.resolver  # type: ignore[import-untyped]
    import dns.reversename  # type: ignore[import-untyped]

    def _ptr_lookup(ip: str) -> list[str]:
        try:
            ptr_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(ptr_name, "PTR", lifetime=10)
            return [str(rdata).rstrip(".") for rdata in answers]
        except Exception:
            return []

    try:
        hostnames = await asyncio.to_thread(_ptr_lookup, finding.value)
        results: list[Finding] = []
        for hostname in hostnames:
            if hostname:
                results.append(
                    _child(
                        finding,
                        type=FindingType.DOMAIN,
                        value=hostname,
                        source="reverse_dns",
                        confidence=85,
                    )
                )
        return results
    except Exception:
        return []


async def _handle_subdomain_to_ip(finding: Finding) -> list[Finding]:
    """
    SUBDOMAIN → IP

    Resolves a subdomain's A records.  High confidence because the DNS answer
    is authoritative at time of lookup.
    """
    import asyncio
    import dns.resolver  # type: ignore[import-untyped]

    def _resolve(subdomain: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(subdomain, "A", lifetime=10)
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    try:
        ips = await asyncio.to_thread(_resolve, finding.value)
        results: list[Finding] = []
        for ip in ips:
            results.append(
                _child(
                    finding,
                    type=FindingType.IP,
                    value=ip,
                    source="subdomain_dns",
                    confidence=95,
                )
            )
        return results
    except Exception:
        return []


async def _handle_social_profile_to_username(finding: Finding) -> list[Finding]:
    """
    SOCIAL_PROFILE → USERNAME

    Extracts the username stored in the finding's raw_data by the social
    module that created it.  The username field is a convention — social
    modules must populate raw_data["username"] for this rule to fire.
    """
    try:
        username = finding.raw_data.get("username", "").strip()
        if not username:
            return []
        return [
            _child(
                finding,
                type=FindingType.USERNAME,
                value=username,
                source="social_profile_extract",
                confidence=95,
            )
        ]
    except Exception:
        return []


async def _handle_url_to_domain(finding: Finding) -> list[Finding]:
    """
    URL → DOMAIN

    Parses the URL and extracts the hostname.  Pure string operation.
    """
    try:
        parsed = urlparse(finding.value)
        hostname = parsed.hostname
        if not hostname:
            return []
        hostname = hostname.lower().strip()
        if not hostname:
            return []
        return [
            _child(
                finding,
                type=FindingType.DOMAIN,
                value=hostname,
                source="url_domain_extract",
                confidence=99,
            )
        ]
    except Exception:
        return []


async def _handle_asn_to_org(finding: Finding) -> list[Finding]:
    """
    ASN → ORG

    Extracts the org name from raw_data populated by the geo lookup rule.
    No network call — this is a pure data derivation from what ip-api.com
    already returned.
    """
    try:
        org_name = finding.raw_data.get("org", "").strip()
        if not org_name:
            return []
        return [
            _child(
                finding,
                type=FindingType.ORG,
                value=org_name,
                source="asn_org_extract",
                confidence=70,
            )
        ]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_all_correlations(bus: EventBus) -> None:
    """
    Instantiate all CorrelationRule objects and register them with the bus.

    Call this once at CLI startup, after init_bus().  Order does not matter
    since the bus dispatches by FindingType, not by insertion order.
    """
    rules: list[CorrelationRule] = [
        CorrelationRule(
            trigger_type=FindingType.EMAIL,
            handler=_handle_email_to_domain,
            name="email_to_domain",
            description="Extract the domain component of an email address.",
            requires_active=False,
            min_confidence=0,
            cooldown_seconds=0,
        ),
        CorrelationRule(
            trigger_type=FindingType.EMAIL,
            handler=_handle_email_to_username,
            name="email_to_username_guess",
            description="Derive a candidate username from the local-part of an email.",
            requires_active=False,
            min_confidence=0,
            cooldown_seconds=0,
        ),
        CorrelationRule(
            trigger_type=FindingType.DOMAIN,
            handler=_handle_domain_to_dns,
            name="domain_dns_a",
            description="Resolve the domain's A records to discover associated IPs.",
            requires_active=False,
            min_confidence=0,
            cooldown_seconds=300,
        ),
        CorrelationRule(
            trigger_type=FindingType.DOMAIN,
            handler=_handle_domain_to_whois_email,
            name="domain_whois_email",
            description="Extract registrant/admin email addresses from WHOIS records.",
            requires_active=False,
            min_confidence=0,
            cooldown_seconds=600,
        ),
        CorrelationRule(
            trigger_type=FindingType.IP,
            handler=_handle_ip_to_geo,
            name="ip_geo",
            description="Geo-locate an IP via ip-api.com; extract ASN and coordinates.",
            requires_active=False,
            min_confidence=0,
            cooldown_seconds=300,
        ),
        CorrelationRule(
            trigger_type=FindingType.IP,
            handler=_handle_ip_to_rdns,
            name="ip_rdns",
            description="Perform a reverse DNS lookup to find hostnames for an IP.",
            requires_active=False,
            min_confidence=0,
            cooldown_seconds=300,
        ),
        CorrelationRule(
            trigger_type=FindingType.SUBDOMAIN,
            handler=_handle_subdomain_to_ip,
            name="subdomain_dns_a",
            description="Resolve a subdomain's A records to its IP addresses.",
            requires_active=False,
            min_confidence=0,
            cooldown_seconds=300,
        ),
        CorrelationRule(
            trigger_type=FindingType.SOCIAL_PROFILE,
            handler=_handle_social_profile_to_username,
            name="social_profile_username",
            description="Extract the username from a social profile finding's raw_data.",
            requires_active=False,
            min_confidence=0,
            cooldown_seconds=0,
        ),
        CorrelationRule(
            trigger_type=FindingType.URL,
            handler=_handle_url_to_domain,
            name="url_to_domain",
            description="Extract the hostname from a URL and publish it as a domain.",
            requires_active=False,
            min_confidence=0,
            cooldown_seconds=0,
        ),
        CorrelationRule(
            trigger_type=FindingType.ASN,
            handler=_handle_asn_to_org,
            name="asn_to_org",
            description="Derive an ORG finding from the org name stored in ASN raw_data.",
            requires_active=False,
            min_confidence=0,
            cooldown_seconds=0,
        ),
    ]

    for rule in rules:
        bus.register_rule(rule)
