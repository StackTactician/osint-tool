"""
osint/modules/org/company_lookup.py

Company and GitHub organisation intelligence gathering.

Primary lookups (all passive):
  - Reverse WHOIS via HackerTarget    -> associated domains
  - BGPView org search                -> ASN enumeration
  - LinkedIn profile probe            -> presence check
  - GitHub /orgs/{slug}               -> org metadata
  - GitHub /orgs/{slug}/repos         -> repository list, languages, topics
  - GitHub /orgs/{slug}/members       -> public member list
  - GitHub commit history             -> email address extraction
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote_plus

from osint.output import (
    print_error,
    print_finding,
    print_info,
    print_panel,
    print_section,
    print_table,
    print_warning,
)
from osint.utils import make_http_client

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_GITHUB_NOREPLY_RE = re.compile(
    r"@users\.noreply\.github\.com$|noreply@github\.com$",
    re.IGNORECASE,
)


def _company_slug(name: str) -> str:
    """Convert a company name to a lowercase hyphenated slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = slug.strip("-")
    return slug


# ---------------------------------------------------------------------------
# Reverse WHOIS
# ---------------------------------------------------------------------------

async def _reverse_whois(client: Any, name: str) -> list[str]:
    """
    Query HackerTarget reverse WHOIS by organisation name.

    Returns up to 20 unique, non-empty domain strings.
    """
    try:
        resp = await client.get(
            f"https://api.hackertarget.com/reversewhois/?q={quote_plus(name)}",
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        text = resp.text.strip()
        if not text or "no records found" in text.lower() or "error" in text.lower():
            return []
        domains: list[str] = []
        seen: set[str] = set()
        for line in text.splitlines():
            domain = line.strip().lower()
            if domain and domain not in seen:
                seen.add(domain)
                domains.append(domain)
                if len(domains) >= 20:
                    break
        return domains
    except Exception:
        return []


# ---------------------------------------------------------------------------
# BGPView ASN lookup
# ---------------------------------------------------------------------------

async def _bgpview_asns(client: Any, name: str) -> list[dict]:
    """
    Query BGPView for ASNs belonging to an organisation name.

    Returns a list of dicts with keys: asn, name, description, country_code.
    """
    try:
        resp = await client.get(
            "https://api.bgpview.io/search",
            params={"query_term": name, "query_type": "org"},
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        payload = resp.json()
        data = payload.get("data", {})
        raw_asns: list[dict] = data.get("asns", [])
        asns: list[dict] = []
        for entry in raw_asns:
            asns.append({
                "asn": entry.get("asn"),
                "name": entry.get("name", ""),
                "description": entry.get("description", ""),
                "country_code": entry.get("country_code", ""),
            })
        return asns
    except Exception:
        return []


# ---------------------------------------------------------------------------
# LinkedIn presence probe
# ---------------------------------------------------------------------------

async def _probe_linkedin(client: Any, slug: str) -> str | None:
    """
    Check whether a LinkedIn company page exists for *slug*.

    Returns the URL string on success, None otherwise.
    LinkedIn heavily throttles bots; a non-200 is treated as absent.
    """
    url = f"https://www.linkedin.com/company/{slug}"
    try:
        resp = await client.get(url, timeout=10)
        if resp.status_code == 200:
            return url
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# GitHub org metadata
# ---------------------------------------------------------------------------

async def _github_org_meta(client: Any, slug: str) -> dict | None:
    """
    Fetch GitHub organisation metadata for *slug*.

    Returns a dict on 200, None on 404 or error.
    """
    try:
        resp = await client.get(
            f"https://api.github.com/orgs/{slug}",
            headers={"Accept": "application/vnd.github+json"},
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        raw = resp.json()
        return {
            "login": raw.get("login"),
            "name": raw.get("name"),
            "description": raw.get("description"),
            "public_repos": raw.get("public_repos", 0),
            "followers": raw.get("followers", 0),
            "blog": raw.get("blog") or None,
            "email": raw.get("email") or None,
            "location": raw.get("location") or None,
            "html_url": raw.get("html_url"),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# GitHub org enumeration (repos + members + commit emails)
# ---------------------------------------------------------------------------

async def enumerate_github_org(org_name: str) -> dict:
    """
    Collect full GitHub organisation intelligence.

    Fetches:
      - Organisation metadata
      - Up to 100 repositories (sorted by updated)
      - Up to 100 public members
      - Commit author emails from the top 5 repos by stars

    Returns:
        {
            "org": str,
            "description": str | None,
            "public_repos": int,
            "members": list[dict],
            "repos": list[dict],
            "commit_emails": list[str],
            "languages": list[str],
            "topics": list[str],
        }
    """
    result: dict = {
        "org": org_name,
        "description": None,
        "public_repos": 0,
        "members": [],
        "repos": [],
        "commit_emails": [],
        "languages": [],
        "topics": [],
    }

    async with make_http_client(timeout=15) as client:
        gh_headers = {"Accept": "application/vnd.github+json"}

        # ------------------------------------------------------------------
        # Org metadata
        # ------------------------------------------------------------------
        try:
            resp = await client.get(
                f"https://api.github.com/orgs/{org_name}",
                headers=gh_headers,
            )
            if resp.status_code == 200:
                meta = resp.json()
                result["description"] = meta.get("description")
                result["public_repos"] = meta.get("public_repos", 0)
        except Exception:
            pass

        # ------------------------------------------------------------------
        # Repos
        # ------------------------------------------------------------------
        repos_raw: list[dict] = []
        try:
            resp = await client.get(
                f"https://api.github.com/orgs/{org_name}/repos",
                params={"per_page": 100, "sort": "updated"},
                headers=gh_headers,
            )
            if resp.status_code == 200:
                repos_raw = resp.json()
        except Exception:
            pass

        repos: list[dict] = []
        all_languages: set[str] = set()
        all_topics: set[str] = set()

        for repo in repos_raw:
            lang = repo.get("language")
            topics = repo.get("topics") or []
            if lang:
                all_languages.add(lang)
            all_topics.update(topics)
            repos.append({
                "name": repo.get("name", ""),
                "full_name": repo.get("full_name", ""),
                "description": repo.get("description"),
                "language": lang,
                "topics": topics,
                "stars": repo.get("stargazers_count", 0),
                "forks": repo.get("forks_count", 0),
                "last_pushed": repo.get("pushed_at"),
                "html_url": repo.get("html_url", ""),
                "archived": repo.get("archived", False),
            })

        # Sort by stars descending
        repos.sort(key=lambda r: r["stars"], reverse=True)
        result["repos"] = repos
        result["languages"] = sorted(all_languages)
        result["topics"] = sorted(all_topics)

        # ------------------------------------------------------------------
        # Members
        # ------------------------------------------------------------------
        try:
            resp = await client.get(
                f"https://api.github.com/orgs/{org_name}/members",
                params={"per_page": 100},
                headers=gh_headers,
            )
            if resp.status_code == 200:
                result["members"] = [
                    {
                        "login": m.get("login", ""),
                        "html_url": m.get("html_url", ""),
                        "avatar_url": m.get("avatar_url", ""),
                    }
                    for m in resp.json()
                ]
        except Exception:
            pass

        # ------------------------------------------------------------------
        # Commit email extraction — top 5 repos by stars
        # ------------------------------------------------------------------
        top_repos = repos[:5]
        commit_emails: set[str] = set()

        async def _collect_emails(repo_name: str) -> None:
            try:
                resp = await client.get(
                    f"https://api.github.com/repos/{org_name}/{repo_name}/commits",
                    params={"per_page": 100},
                    headers=gh_headers,
                    timeout=15,
                )
                if resp.status_code != 200:
                    return
                for commit in resp.json():
                    commit_data = commit.get("commit", {})
                    for actor_key in ("author", "committer"):
                        actor = commit_data.get(actor_key) or {}
                        email = actor.get("email", "")
                        if email and not _GITHUB_NOREPLY_RE.search(email):
                            commit_emails.add(email.lower())
            except Exception:
                pass

        await asyncio.gather(*(_collect_emails(r["name"]) for r in top_repos))
        result["commit_emails"] = sorted(commit_emails)

    return result


# ---------------------------------------------------------------------------
# Main company search
# ---------------------------------------------------------------------------

async def search_company(name: str) -> dict:
    """
    Discover company intelligence from a name string alone.

    Steps (all passive):
      1. Reverse WHOIS by org name (HackerTarget)
      2. ASN lookup by org name (BGPView)
      3. LinkedIn company page probe
      4. GitHub org metadata probe

    Returns:
        {
            "name": str,
            "domains": list[str],
            "asns": list[dict],
            "linkedin_url": str | None,
            "github_org": str | None,
            "employees_found": list[dict],
            "tech_stack_hints": list[str],
        }
    """
    slug = _company_slug(name)

    result: dict = {
        "name": name,
        "domains": [],
        "asns": [],
        "linkedin_url": None,
        "github_org": None,
        "employees_found": [],
        "tech_stack_hints": [],
    }

    async with make_http_client(timeout=15) as client:
        # Run independent lookups concurrently
        domains, asns, linkedin_url, github_meta = await asyncio.gather(
            _reverse_whois(client, name),
            _bgpview_asns(client, name),
            _probe_linkedin(client, slug),
            _github_org_meta(client, slug),
        )

    result["domains"] = domains
    result["asns"] = asns
    result["linkedin_url"] = linkedin_url

    if github_meta:
        result["github_org"] = github_meta.get("login") or slug

    return result


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def format_company_output(data: dict) -> None:
    """Render search_company() results to the console."""
    name = data.get("name", "unknown")
    print_section(f"Company Intelligence — {name}")

    # Summary panel
    lines: list[str] = []
    lines.append(f"  [bold bright_white]Company[/]    {name}")

    linkedin = data.get("linkedin_url")
    if linkedin:
        lines.append(f"  [bold bright_white]LinkedIn[/]   [link={linkedin}]{linkedin}[/link]")
    else:
        lines.append("  [bold bright_white]LinkedIn[/]   [dim]not detected[/]")

    github_org = data.get("github_org")
    if github_org:
        gh_url = f"https://github.com/{github_org}"
        lines.append(f"  [bold bright_white]GitHub org[/] [link={gh_url}]{gh_url}[/link]")
    else:
        lines.append("  [bold bright_white]GitHub org[/] [dim]not detected[/]")

    print_panel("Overview", "\n".join(lines), style="bright_blue")

    # Domains table
    domains = data.get("domains", [])
    if domains:
        print_table(
            "Associated Domains (Reverse WHOIS)",
            ["Domain"],
            [[d] for d in domains],
            caption=f"{len(domains)} domains found",
        )
    else:
        print_info("No domains found via reverse WHOIS.")

    # ASNs table
    asns = data.get("asns", [])
    if asns:
        print_table(
            "Autonomous System Numbers",
            ["ASN", "Name", "Description", "Country"],
            [
                [
                    f"AS{a['asn']}" if a.get("asn") else "—",
                    a.get("name", ""),
                    a.get("description", ""),
                    a.get("country_code", ""),
                ]
                for a in asns
            ],
        )
    else:
        print_info("No ASNs found via BGPView.")


def format_github_org_output(data: dict) -> None:
    """Render enumerate_github_org() results to the console."""
    org = data.get("org", "unknown")
    print_section(f"GitHub Organisation — {org}")

    # Overview panel
    lines: list[str] = []
    if data.get("description"):
        lines.append(f"  [bold bright_white]Description[/]    {data['description']}")
    lines.append(f"  [bold bright_white]Public repos[/]   {data.get('public_repos', 0)}")
    lines.append(f"  [bold bright_white]Members[/]        {len(data.get('members', []))}")
    lines.append(f"  [bold bright_white]Languages[/]      {', '.join(data.get('languages', [])) or '—'}")

    topics = data.get("topics", [])
    if topics:
        lines.append(f"  [bold bright_white]Topics[/]         {', '.join(topics[:15])}")

    print_panel("Overview", "\n".join(lines), style="cyan")

    # Top repos table
    repos = data.get("repos", [])
    if repos:
        top = repos[:20]
        print_table(
            "Top Repositories (by stars)",
            ["Name", "Language", "Stars", "Forks", "Last Push"],
            [
                [
                    r["name"],
                    r.get("language") or "—",
                    r.get("stars", 0),
                    r.get("forks", 0),
                    (r.get("last_pushed") or "")[:10],
                ]
                for r in top
            ],
        )

    # Members table
    members = data.get("members", [])
    if members:
        print_table(
            "Public Members",
            ["Login", "Profile"],
            [[m["login"], m.get("html_url", "")] for m in members],
        )

    # Commit emails
    emails = data.get("commit_emails", [])
    if emails:
        print_section("Emails Found in Commit History")
        for email in emails:
            print_finding("email", email, source="github_commits")
    else:
        print_info("No non-noreply emails found in top-5 repo commit history.")
