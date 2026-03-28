"""
osint/modules/org/commands.py

Click command group for organisation / company reconnaissance.

Commands:
  search COMPANY_NAME  -- broad company discovery (domains, ASNs, GitHub, LinkedIn)
  emails DOMAIN        -- email pattern enumeration for a domain
  github ORG_NAME      -- deep GitHub organisation intelligence

Each command:
  1. Validates / normalises input
  2. Calls the relevant async lookup function
  3. Formats output via the module's format_* helper
  4. Publishes typed Finding objects to the event bus
  5. Optionally exports raw JSON to a file
"""

from __future__ import annotations

import asyncio
from typing import Any

import click

from osint.events import Finding, FindingType, get_bus
from osint.output import (
    export_json,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from osint.utils import validate_domain


# ---------------------------------------------------------------------------
# Command group
# ---------------------------------------------------------------------------


@click.group("org")
def org() -> None:
    """Investigate a company or organisation."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_settings() -> Any:
    from osint.config import get_settings
    return get_settings()


def _session_id() -> int:
    """Return a best-effort session ID (0 when no DB session is active)."""
    return 0


# ---------------------------------------------------------------------------
# search command
# ---------------------------------------------------------------------------


@org.command("search")
@click.argument("company_name")
@click.option(
    "--output-json",
    default=None,
    type=click.Path(),
    help="Write raw result data to this JSON file.",
)
@click.pass_context
def search(
    ctx: click.Context,
    company_name: str,
    output_json: str | None,
) -> None:
    """
    Discover domains, ASNs, LinkedIn, and GitHub for a company name.

    Performs passive lookups only: reverse WHOIS, BGPView, LinkedIn probe,
    and GitHub org detection.

    Example: osint org search "Acme Corp"
    """
    from osint.modules.org.company_lookup import search_company, format_company_output

    if not company_name.strip():
        print_error("Company name must not be empty.")
        raise SystemExit(1)

    async def _run() -> None:
        bus = get_bus()
        session_id = _session_id()

        data = await search_company(company_name.strip())
        format_company_output(data)

        # Publish findings
        # Organisation itself
        await bus.publish(Finding(
            type=FindingType.ORG,
            value=data["name"],
            source="hackertarget_reversewhois",
            confidence=80,
            session_id=session_id,
            raw_data=data,
            tags=["company_search"],
        ))

        # Associated domains
        for domain in data.get("domains", []):
            await bus.publish(Finding(
                type=FindingType.DOMAIN,
                value=domain,
                source="hackertarget_reversewhois",
                confidence=70,
                session_id=session_id,
                tags=["reverse_whois", "org_domain"],
            ))

        # ASNs
        for asn_entry in data.get("asns", []):
            asn_val = asn_entry.get("asn")
            if asn_val:
                await bus.publish(Finding(
                    type=FindingType.ASN,
                    value=f"AS{asn_val}",
                    source="bgpview",
                    confidence=80,
                    session_id=session_id,
                    raw_data=asn_entry,
                    tags=["org_asn"],
                ))

        # LinkedIn
        linkedin = data.get("linkedin_url")
        if linkedin:
            await bus.publish(Finding(
                type=FindingType.URL,
                value=linkedin,
                source="linkedin_probe",
                confidence=75,
                session_id=session_id,
                tags=["linkedin", "social"],
            ))

        # GitHub org
        github_org = data.get("github_org")
        if github_org:
            await bus.publish(Finding(
                type=FindingType.SOCIAL_PROFILE,
                value=f"https://github.com/{github_org}",
                source="github_org_probe",
                confidence=85,
                session_id=session_id,
                tags=["github", "org"],
            ))

        print_success(
            f"Search complete — "
            f"{len(data.get('domains', []))} domain(s), "
            f"{len(data.get('asns', []))} ASN(s)."
        )

        if output_json:
            export_json(data, output_json)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# emails command
# ---------------------------------------------------------------------------


@org.command("emails")
@click.argument("domain")
@click.option(
    "--company",
    default=None,
    help="Company name (used as context for pattern inference).",
)
@click.option(
    "--output-json",
    default=None,
    type=click.Path(),
    help="Write raw result data to this JSON file.",
)
@click.pass_context
def emails(
    ctx: click.Context,
    domain: str,
    company: str | None,
    output_json: str | None,
) -> None:
    """
    Discover email address patterns and known addresses for DOMAIN.

    Uses Hunter.io (if configured), infers the most likely corporate email
    pattern, verifies MX records, and checks for wildcard acceptance.

    Example: osint org emails example.com
    """
    from osint.modules.org.email_enum import enumerate_emails, format_email_enum_output

    normalized = validate_domain(domain)
    if not normalized:
        print_error(f"Invalid domain name: {domain!r}")
        raise SystemExit(1)

    async def _run() -> None:
        bus = get_bus()
        session_id = _session_id()

        data = await enumerate_emails(normalized, company_name=company)
        format_email_enum_output(data)

        # Publish findings
        for entry in data.get("emails_found", []):
            email_addr = entry.get("email", "")
            if not email_addr:
                continue
            await bus.publish(Finding(
                type=FindingType.EMAIL,
                value=email_addr,
                source="hunter_io",
                confidence=entry.get("confidence", 50),
                session_id=session_id,
                raw_data=entry,
                tags=["email_enum", normalized],
            ))

        # Domain finding with MX validity context
        await bus.publish(Finding(
            type=FindingType.DOMAIN,
            value=normalized,
            source="email_enum_mx",
            confidence=90 if data.get("mx_valid") else 50,
            session_id=session_id,
            raw_data={"mx_valid": data["mx_valid"], "mx_hosts": data["mx_hosts"]},
            tags=["email_enum"],
        ))

        total = data.get("total_found", 0)
        pattern = data.get("pattern")
        summary = f"{total} address(es) found"
        if pattern:
            summary += f", pattern: {pattern}@{normalized}"
        print_success(f"Email enumeration complete — {summary}.")

        if output_json:
            export_json(data, output_json)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# github command
# ---------------------------------------------------------------------------


@org.command("github")
@click.argument("org_name")
@click.option(
    "--output-json",
    default=None,
    type=click.Path(),
    help="Write raw result data to this JSON file.",
)
@click.pass_context
def github(
    ctx: click.Context,
    org_name: str,
    output_json: str | None,
) -> None:
    """
    Collect GitHub organisation intelligence for ORG_NAME.

    Fetches public repos, members, languages, topics, and extracts unique
    author emails from the commit history of the top 5 repos by stars.

    Example: osint org github torvalds
    """
    from osint.modules.org.company_lookup import enumerate_github_org, format_github_org_output

    org_name = org_name.strip()
    if not org_name:
        print_error("GitHub org name must not be empty.")
        raise SystemExit(1)

    async def _run() -> None:
        bus = get_bus()
        session_id = _session_id()

        data = await enumerate_github_org(org_name)
        format_github_org_output(data)

        # Publish findings
        # Org profile
        gh_url = f"https://github.com/{org_name}"
        await bus.publish(Finding(
            type=FindingType.SOCIAL_PROFILE,
            value=gh_url,
            source="github_org_enum",
            confidence=90,
            session_id=session_id,
            raw_data={
                "description": data.get("description"),
                "public_repos": data.get("public_repos"),
                "member_count": len(data.get("members", [])),
                "languages": data.get("languages"),
            },
            tags=["github", "org"],
        ))

        # Member profiles
        for member in data.get("members", []):
            profile_url = member.get("html_url", "")
            if profile_url:
                await bus.publish(Finding(
                    type=FindingType.SOCIAL_PROFILE,
                    value=profile_url,
                    source="github_org_members",
                    confidence=80,
                    session_id=session_id,
                    tags=["github", "member", org_name],
                ))

        # Commit emails
        for email_addr in data.get("commit_emails", []):
            await bus.publish(Finding(
                type=FindingType.EMAIL,
                value=email_addr,
                source="github_commits",
                confidence=75,
                session_id=session_id,
                tags=["commit_email", org_name],
            ))

        repo_count = len(data.get("repos", []))
        email_count = len(data.get("commit_emails", []))
        member_count = len(data.get("members", []))
        print_success(
            f"GitHub enumeration complete — "
            f"{repo_count} repo(s), {member_count} member(s), "
            f"{email_count} commit email(s)."
        )

        if output_json:
            export_json(data, output_json)

    asyncio.run(_run())
