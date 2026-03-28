"""
osint/modules/domain/subdomain_enum.py

Multi-source subdomain enumeration.

Sources:
  - crt.sh  (passive, certificate transparency logs)
  - HackerTarget (passive, API)
  - DNS brute force (active, resolves wordlist entries)
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import httpx

from osint.output import (
    get_progress,
    print_error,
    print_info,
    print_section,
    print_table,
    print_warning,
)

# Path to the bundled wordlist, relative to the package root
_WORDLIST_PATH = Path(__file__).parents[3] / "data" / "subdomains.txt"


# ---------------------------------------------------------------------------
# Passive sources
# ---------------------------------------------------------------------------

async def _fetch_crt_sh(domain: str, client: httpx.AsyncClient) -> list[str]:
    """
    Enumerate subdomains from crt.sh certificate transparency logs.

    Returns a deduplicated list of bare subdomain strings (lowercased).
    """
    try:
        resp = await client.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=20,
        )
        resp.raise_for_status()
        data: list[dict] = resp.json()
    except Exception:
        return []

    found: set[str] = set()
    for entry in data:
        raw_name = entry.get("name_value", "")
        # name_value can contain newline-separated names
        for name in raw_name.split("\n"):
            name = name.strip().lower()
            # Strip wildcard prefix
            if name.startswith("*."):
                name = name[2:]
            if name.endswith(f".{domain}") or name == domain:
                found.add(name)

    return sorted(found)


async def _fetch_hackertarget(domain: str, client: httpx.AsyncClient) -> list[tuple[str, str]]:
    """
    Enumerate subdomains from HackerTarget hostsearch.

    Returns list of (subdomain, ip) tuples.
    """
    try:
        resp = await client.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=20,
        )
        resp.raise_for_status()
        text = resp.text.strip()
    except Exception:
        return []

    if "API count exceeded" in text or "error" in text.lower():
        return []

    results: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        parts = line.split(",", 1)
        sub = parts[0].strip().lower()
        ip = parts[1].strip() if len(parts) > 1 else ""
        if sub.endswith(f".{domain}") or sub == domain:
            results.append((sub, ip))

    return results


# ---------------------------------------------------------------------------
# DNS resolution helper
# ---------------------------------------------------------------------------

async def _resolve_a(name: str, resolver: dns.asyncresolver.Resolver) -> list[str]:
    """Resolve A records for *name*. Returns empty list on any failure."""
    try:
        answers = await resolver.resolve(name, "A", raise_on_no_answer=False)
        return [rdata.to_text() for rdata in answers]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Brute force source
# ---------------------------------------------------------------------------

async def _brute_force(
    domain: str,
    wordlist_path: Path,
    workers: int,
    resolver: dns.asyncresolver.Resolver,
) -> list[tuple[str, list[str]]]:
    """
    DNS brute-force using the wordlist.

    Returns list of (subdomain_fqdn, [ip, ...]) for resolved entries only.
    """
    if not wordlist_path.exists():
        print_warning(f"Wordlist not found: {wordlist_path}  — skipping brute force.")
        return []

    words = [
        line.strip()
        for line in wordlist_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

    if not words:
        return []

    semaphore = asyncio.Semaphore(workers)
    results: list[tuple[str, list[str]]] = []
    lock = asyncio.Lock()

    with get_progress("Brute forcing subdomains") as progress:
        task_id = progress.add_task("", total=len(words))

        async def probe(word: str) -> None:
            fqdn = f"{word}.{domain}"
            async with semaphore:
                ips = await _resolve_a(fqdn, resolver)
                progress.advance(task_id)
                if ips:
                    async with lock:
                        results.append((fqdn, ips))

        await asyncio.gather(*(probe(w) for w in words))

    return results


# ---------------------------------------------------------------------------
# Main enumeration function
# ---------------------------------------------------------------------------

async def enumerate_subdomains(
    domain: str,
    sources: list[str] | None = None,
    wordlist_path: str | None = None,
    workers: int = 50,
) -> list[dict]:
    """
    Enumerate subdomains from multiple sources.

    Args:
        domain:        Base domain to enumerate subdomains for.
        sources:       List of source names to use. Options: "crt", "hackertarget",
                       "brute". Defaults to ["crt", "hackertarget"].
        wordlist_path: Path to a custom wordlist file. Uses bundled list if None.
        workers:       Concurrent worker limit for brute-force resolution.

    Returns:
        Sorted, deduplicated list of dicts with keys:
            subdomain, ips, source, is_active
    """
    if sources is None:
        sources = ["crt", "hackertarget"]

    wl_path = Path(wordlist_path) if wordlist_path else _WORDLIST_PATH

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0

    # Accumulate raw findings: subdomain -> {"ips": set, "sources": set}
    aggregate: dict[str, dict[str, Any]] = {}

    def _record(subdomain: str, ips: list[str], source: str) -> None:
        subdomain = subdomain.lower()
        if subdomain not in aggregate:
            aggregate[subdomain] = {"ips": set(), "sources": set()}
        aggregate[subdomain]["ips"].update(ips)
        aggregate[subdomain]["sources"].add(source)

    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0 osint-tool/1.0"},
        follow_redirects=True,
    ) as client:

        # --- crt.sh ---
        if "crt" in sources:
            print_info("Querying crt.sh...")
            crt_names = await _fetch_crt_sh(domain, client)
            for name in crt_names:
                _record(name, [], "crt_sh")

        # --- HackerTarget ---
        if "hackertarget" in sources:
            print_info("Querying HackerTarget...")
            ht_results = await _fetch_hackertarget(domain, client)
            for sub, ip in ht_results:
                _record(sub, [ip] if ip else [], "hackertarget")

    # --- Brute force ---
    if "brute" in sources:
        print_info("Starting DNS brute force...")
        brute_results = await _brute_force(domain, wl_path, workers, resolver)
        for fqdn, ips in brute_results:
            _record(fqdn, ips, "brute_force")

    # --- Resolve IPs for passive-only findings ---
    unresolved = [sub for sub, data in aggregate.items() if not data["ips"]]
    if unresolved:
        print_info(f"Resolving {len(unresolved)} passive findings...")
        semaphore = asyncio.Semaphore(workers)

        async def resolve_one(sub: str) -> None:
            async with semaphore:
                ips = await _resolve_a(sub, resolver)
                if ips:
                    aggregate[sub]["ips"].update(ips)

        await asyncio.gather(*(resolve_one(s) for s in unresolved))

    # --- Build output list ---
    output: list[dict] = []
    for subdomain, data in sorted(aggregate.items()):
        ips = sorted(data["ips"])
        output.append({
            "subdomain": subdomain,
            "ips": ips,
            "source": ", ".join(sorted(data["sources"])),
            "is_active": bool(ips),
        })

    return output


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def format_subdomain_output(domain: str, results: list[dict]) -> None:
    """Render subdomain enumeration results as a Rich table."""
    print_section(f"Subdomains — {domain}")

    if not results:
        print_info("No subdomains found.")
        return

    active_count = sum(1 for r in results if r["is_active"])
    print_info(f"{len(results)} subdomains found, {active_count} active (resolved to IP).")

    rows: list[list[str]] = []
    for entry in results:
        ips_str = ", ".join(entry["ips"]) if entry["ips"] else "—"
        active_str = (
            "[bold green]Yes[/bold green]" if entry["is_active"] else "[dim]No[/dim]"
        )
        rows.append([entry["subdomain"], ips_str, entry["source"], active_str])

    print_table(
        f"Subdomains for {domain}",
        ["Subdomain", "IPs", "Sources", "Active"],
        rows,
    )
