"""
osint/modules/org/email_enum.py

Corporate email pattern discovery for a domain.

Techniques used (all passive — no mail is sent):
  1. Hunter.io domain-search API (if key configured)
  2. Pattern inference from discovered emails
  3. MX record verification via dnspython
  4. Wildcard acceptance probe via a random non-existent local-part query
     (DNS-level check only — no SMTP connection is made)
"""

from __future__ import annotations

import random
import re
import string
from collections import Counter
from typing import Any

from osint.output import (
    print_finding,
    print_info,
    print_panel,
    print_section,
    print_table,
    print_warning,
)
from osint.utils import make_http_client

# ---------------------------------------------------------------------------
# Pattern inference
# ---------------------------------------------------------------------------

# Ordered list of corporate email patterns we attempt to identify.
# Each entry: (pattern_key, pattern_template, extractor_fn)
# extractor_fn(first, last) -> the local-part for that pattern.
_PATTERNS: list[tuple[str, str, Any]] = [
    ("first.last",   "{first}.{last}",   lambda f, l: f"{f}.{l}"),
    ("flast",        "{f}{last}",        lambda f, l: f"{f[0]}{l}" if f else l),
    ("first",        "{first}",          lambda f, l: f),
    ("first_last",   "{first}_{last}",   lambda f, l: f"{f}_{l}"),
    ("last",         "{last}",           lambda f, l: l),
    ("lastf",        "{last}{f}",        lambda f, l: f"{l}{f[0]}" if f else l),
    ("first-last",   "{first}-{last}",   lambda f, l: f"{f}-{l}"),
]


def _infer_pattern(emails: list[dict]) -> tuple[str | None, str | None, int]:
    """
    Score each candidate pattern against discovered emails and return the winner.

    An email dict must have "first", "last", and "email" keys.  Entries
    without first/last names are skipped.

    Returns:
        (pattern_key, pattern_template, confidence_0_to_100)
        All three are None/0 when no scoreable emails are available.
    """
    scoreable = [
        e for e in emails
        if e.get("first") and e.get("last") and e.get("email")
    ]
    if not scoreable:
        return None, None, 0

    votes: Counter[str] = Counter()

    for entry in scoreable:
        first = entry["first"].lower()
        last = entry["last"].lower()
        local = entry["email"].split("@")[0].lower()

        for key, _template, extractor in _PATTERNS:
            expected = extractor(first, last)
            if expected and local == expected:
                votes[key] += 1
                break  # first match wins for this email

    if not votes:
        return None, None, 0

    winner_key, winner_votes = votes.most_common(1)[0]
    confidence = min(100, int((winner_votes / len(scoreable)) * 100))

    # Look up the template for the winning key
    winner_template: str | None = None
    for key, template, _ in _PATTERNS:
        if key == winner_key:
            winner_template = template
            break

    return winner_key, winner_template, confidence


# ---------------------------------------------------------------------------
# MX verification
# ---------------------------------------------------------------------------

def _check_mx(domain: str) -> tuple[bool, list[str]]:
    """
    Resolve MX records for *domain* using dnspython (synchronous).

    Returns (mx_valid: bool, mx_hosts: list[str]).
    """
    try:
        import dns.resolver

        answers = dns.resolver.resolve(domain, "MX")
        hosts = sorted(str(r.exchange).rstrip(".") for r in answers)
        return bool(hosts), hosts
    except Exception:
        return False, []


# ---------------------------------------------------------------------------
# Wildcard detection
# ---------------------------------------------------------------------------

def _generate_random_local() -> str:
    """Generate a random 20-character local-part unlikely to be a real user."""
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=20))  # noqa: S311


def _check_wildcard(domain: str) -> bool:
    """
    Test whether the domain appears to accept wildcard addresses at the DNS level.

    Strategy: query an MX record for a deliberately nonsensical subdomain of
    the form <random>.{domain}.  If MX records resolve, the zone is configured
    to accept anything — typical of catch-all setups.

    This is a DNS-only probe.  No TCP/SMTP connection is made.
    Returns True if the domain appears to be a wildcard acceptor.
    """
    try:
        import dns.resolver

        probe = f"{_generate_random_local()}.{domain}"
        dns.resolver.resolve(probe, "MX")
        # If we got here, the resolver returned answers for a junk subdomain.
        return True
    except Exception:
        # NXDOMAIN, timeout, or any error == not a wildcard
        return False


# ---------------------------------------------------------------------------
# Hunter.io
# ---------------------------------------------------------------------------

async def _hunter_domain_search(client: Any, domain: str, api_key: str) -> dict:
    """
    Query the Hunter.io domain-search endpoint.

    Returns the parsed JSON body, or an empty dict on failure.
    """
    try:
        resp = await client.get(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "api_key": api_key},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


def _normalize_hunter_emails(raw: dict) -> list[dict]:
    """
    Extract and normalise email entries from a Hunter domain-search response.

    Each returned dict has:
        email, first, last, confidence, sources (list[str])
    """
    data = raw.get("data", {})
    out: list[dict] = []
    for entry in data.get("emails", []):
        email = (entry.get("value") or "").strip().lower()
        if not email:
            continue
        sources = [
            s.get("uri", "") or s.get("domain", "")
            for s in (entry.get("sources") or [])
            if isinstance(s, dict)
        ]
        out.append({
            "email": email,
            "first": (entry.get("first_name") or "").strip(),
            "last": (entry.get("last_name") or "").strip(),
            "confidence": entry.get("confidence", 0),
            "sources": [s for s in sources if s],
        })
    return out


# ---------------------------------------------------------------------------
# Main enumeration function
# ---------------------------------------------------------------------------

async def enumerate_emails(
    domain: str,
    company_name: str | None = None,
) -> dict:
    """
    Discover corporate email patterns and addresses for *domain*.

    Steps:
      1. Hunter.io lookup (requires hunter_api_key in settings)
      2. Pattern inference from discovered emails
      3. MX record verification
      4. Wildcard acceptance probe

    Returns:
        {
            "domain": str,
            "mx_valid": bool,
            "mx_hosts": list[str],
            "pattern": str | None,
            "pattern_confidence": int,
            "emails_found": list[dict],
            "total_found": int,
            "accepts_wildcard": bool,
        }
    """
    from osint.config import get_settings

    settings = get_settings()

    result: dict = {
        "domain": domain,
        "mx_valid": False,
        "mx_hosts": [],
        "pattern": None,
        "pattern_confidence": 0,
        "emails_found": [],
        "total_found": 0,
        "accepts_wildcard": False,
    }

    emails_found: list[dict] = []

    # ------------------------------------------------------------------
    # 1. Hunter.io
    # ------------------------------------------------------------------
    hunter_key = settings.keys.hunter_api_key
    if hunter_key:
        async with make_http_client(timeout=15) as client:
            hunter_raw = await _hunter_domain_search(client, domain, hunter_key)
        emails_found = _normalize_hunter_emails(hunter_raw)

        # Hunter may also return the pattern directly
        hunter_pattern = (hunter_raw.get("data") or {}).get("pattern")
        if hunter_pattern:
            # Hunter patterns use {first} / {last} style — normalise
            # e.g. "{first}.{last}" already matches our template format.
            result["pattern"] = hunter_pattern
            result["pattern_confidence"] = 90  # Hunter's own inference
    else:
        print_info(
            "Hunter.io key not configured — email discovery limited to pattern inference only. "
            "Set OSINT_KEYS__HUNTER_API_KEY or add hunter_api_key under [keys] in config.toml."
        )

    # ------------------------------------------------------------------
    # 2. Pattern inference (always run; may improve on Hunter's result)
    # ------------------------------------------------------------------
    _key, inferred_template, inferred_confidence = _infer_pattern(emails_found)
    if inferred_template and inferred_confidence > result["pattern_confidence"]:
        result["pattern"] = inferred_template
        result["pattern_confidence"] = inferred_confidence

    # ------------------------------------------------------------------
    # 3. MX verification
    # ------------------------------------------------------------------
    mx_valid, mx_hosts = _check_mx(domain)
    result["mx_valid"] = mx_valid
    result["mx_hosts"] = mx_hosts

    # ------------------------------------------------------------------
    # 4. Wildcard detection
    # ------------------------------------------------------------------
    if mx_valid:
        result["accepts_wildcard"] = _check_wildcard(domain)

    result["emails_found"] = emails_found
    result["total_found"] = len(emails_found)

    return result


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def format_email_enum_output(data: dict) -> None:
    """Render enumerate_emails() results to the console."""
    domain = data.get("domain", "unknown")
    print_section(f"Email Enumeration — {domain}")

    # Overview panel
    lines: list[str] = []

    mx_valid = data.get("mx_valid", False)
    mx_marker = "[green]yes[/]" if mx_valid else "[red]no[/]"
    lines.append(f"  [bold bright_white]MX valid[/]          {mx_marker}")

    mx_hosts = data.get("mx_hosts", [])
    if mx_hosts:
        lines.append(
            "  [bold bright_white]MX hosts[/]          "
            + "[dim], [/]".join(mx_hosts)
        )

    total = data.get("total_found", 0)
    lines.append(f"  [bold bright_white]Emails found[/]      {total}")

    pattern = data.get("pattern")
    pattern_conf = data.get("pattern_confidence", 0)
    if pattern:
        lines.append(
            f"  [bold bright_white]Pattern[/]           "
            f"[bold cyan]{pattern}@{domain}[/]  "
            f"[dim](confidence: {pattern_conf}%)[/]"
        )
    else:
        lines.append("  [bold bright_white]Pattern[/]           [dim]not determined[/]")

    wildcard = data.get("accepts_wildcard", False)
    lines.append(
        "  [bold bright_white]Wildcard accept[/]   "
        + ("[bold yellow]yes[/]" if wildcard else "[green]no[/]")
    )

    print_panel("Email Discovery Overview", "\n".join(lines), style="bright_blue")

    # Wildcard warning
    if wildcard:
        print_warning(
            "Domain appears to accept wildcard addresses — "
            "email existence cannot be confirmed via DNS probing alone."
        )

    # Emails table
    emails = data.get("emails_found", [])
    if emails:
        # Sort by confidence descending
        sorted_emails = sorted(emails, key=lambda e: e.get("confidence", 0), reverse=True)
        rows = [
            [
                e.get("email", ""),
                e.get("first", "—") or "—",
                e.get("last", "—") or "—",
                e.get("confidence", 0),
                ", ".join(e.get("sources", []))[:60] or "—",
            ]
            for e in sorted_emails
        ]
        print_table(
            "Discovered Email Addresses",
            ["Email", "First", "Last", "Confidence", "Sources"],
            rows,
            caption=f"{len(emails)} address(es) found",
        )
    else:
        print_info("No email addresses discovered.")
