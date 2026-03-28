"""
osint/modules/ip/ip_reputation.py

Aggregate IP reputation from multiple free and key-gated sources:
  - AbuseIPDB   (key required)
  - VirusTotal  (key required)
  - AlienVault OTX (no key for basic lookup)
  - Shodan      (key required)

Produces a 0-100 risk score and a verdict: "clean", "suspicious", "malicious".
"""

from __future__ import annotations

from typing import Any

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
from osint.utils import make_http_client

# ---------------------------------------------------------------------------
# Score weighting
# ---------------------------------------------------------------------------
# Each source contributes a 0-100 sub-score; the overall score is a weighted
# average over sources that returned data.

_WEIGHTS: dict[str, float] = {
    "abuseipdb": 0.35,
    "virustotal": 0.30,
    "otx": 0.20,
    "shodan": 0.15,
}


def _verdict(score: int) -> str:
    if score >= 60:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "clean"


# ---------------------------------------------------------------------------
# Per-source fetch helpers
# ---------------------------------------------------------------------------

async def _fetch_abuseipdb(client: Any, ip: str, key: str) -> dict | None:
    """Fetch AbuseIPDB reputation. Returns normalized sub-result or None."""
    try:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
        )
        resp.raise_for_status()
        d = resp.json().get("data", {})
        return {
            "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "last_reported_at": d.get("lastReportedAt"),
            "usage_type": d.get("usageType"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "is_whitelisted": bool(d.get("isWhitelisted", False)),
        }
    except Exception:
        return None


async def _fetch_virustotal(client: Any, ip: str, key: str) -> dict | None:
    """Fetch VirusTotal stats. Returns normalized sub-result or None."""
    try:
        resp = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
        )
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        return {
            "malicious": last_analysis.get("malicious", 0),
            "suspicious": last_analysis.get("suspicious", 0),
            "harmless": last_analysis.get("harmless", 0),
            "undetected": last_analysis.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "network": attrs.get("network"),
        }
    except Exception:
        return None


async def _fetch_otx(client: Any, ip: str) -> dict | None:
    """Fetch AlienVault OTX general data. Returns normalized sub-result or None."""
    try:
        resp = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        )
        resp.raise_for_status()
        d = resp.json()
        pulse_info = d.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        # Collect threat tags from pulse references
        tags: list[str] = []
        for pulse in pulses:
            for tag in pulse.get("tags", []):
                if tag and tag not in tags:
                    tags.append(tag)

        return {
            "pulse_count": pulse_info.get("count", 0),
            "reputation": d.get("reputation", 0),
            "related_tags": tags[:20],  # cap to avoid huge lists
        }
    except Exception:
        return None


async def _fetch_shodan(client: Any, ip: str, key: str) -> dict | None:
    """Fetch Shodan host data. Returns normalized sub-result or None."""
    try:
        resp = await client.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": key},
        )
        resp.raise_for_status()
        d = resp.json()
        ports = d.get("ports", [])
        vulns = list(d.get("vulns", {}).keys())
        hostnames = d.get("hostnames", [])
        return {
            "open_ports": ports,
            "vulns": vulns,
            "hostnames": hostnames,
            "org": d.get("org"),
            "isp": d.get("isp"),
            "last_update": d.get("last_update"),
            "country_code": d.get("country_code"),
            "tags": d.get("tags", []),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------

def _score_abuseipdb(data: dict) -> int:
    return min(100, data.get("abuse_confidence_score", 0))


def _score_virustotal(data: dict) -> int:
    mal = data.get("malicious", 0)
    sus = data.get("suspicious", 0)
    total = mal + sus + data.get("harmless", 0) + data.get("undetected", 0)
    if total == 0:
        return 0
    # Weighted: malicious counts 2x vs suspicious
    raw = (mal * 2 + sus) / (total + mal) * 100
    return min(100, int(raw))


def _score_otx(data: dict) -> int:
    pulses = data.get("pulse_count", 0)
    # Simple heuristic: 10+ pulses = very suspicious
    if pulses >= 10:
        return 80
    if pulses >= 5:
        return 50
    if pulses >= 1:
        return 25
    return 0


def _score_shodan(data: dict) -> int:
    # Presence of CVEs bumps the score significantly
    vulns = data.get("vulns", [])
    if len(vulns) >= 5:
        return 70
    if vulns:
        return 40
    return 0


def _compute_overall(sources: dict) -> int:
    total_weight = 0.0
    weighted_score = 0.0

    scorers = {
        "abuseipdb": _score_abuseipdb,
        "virustotal": _score_virustotal,
        "otx": _score_otx,
        "shodan": _score_shodan,
    }

    for name, scorer in scorers.items():
        src_data = sources.get(name)
        if src_data is None:
            continue
        w = _WEIGHTS[name]
        total_weight += w
        weighted_score += w * scorer(src_data)

    if total_weight == 0:
        return 0
    # Normalize to total weight present (so missing sources don't deflate score)
    return min(100, int(weighted_score / total_weight))


# ---------------------------------------------------------------------------
# Main reputation check
# ---------------------------------------------------------------------------

async def check_reputation(ip: str) -> dict:
    """
    Aggregate IP reputation from AbuseIPDB, VirusTotal, OTX, and Shodan.

    Returns a normalized dict. Never raises.
    """
    settings = get_settings()
    proxy = settings.effective_proxy

    sources: dict[str, dict | None] = {
        "abuseipdb": None,
        "virustotal": None,
        "otx": None,
        "shodan": None,
    }

    async with make_http_client(proxy=proxy, timeout=15) as client:
        # OTX: no key required
        sources["otx"] = await _fetch_otx(client, ip)

        # AbuseIPDB: key required
        abuseipdb_key = settings.keys.abuseipdb_api_key
        if abuseipdb_key:
            sources["abuseipdb"] = await _fetch_abuseipdb(client, ip, abuseipdb_key)

        # VirusTotal: key required
        vt_key = settings.keys.virustotal_api_key
        if vt_key:
            sources["virustotal"] = await _fetch_virustotal(client, ip, vt_key)

        # Shodan: key required
        shodan_key = settings.keys.shodan_api_key
        if shodan_key:
            sources["shodan"] = await _fetch_shodan(client, ip, shodan_key)

    overall_score = _compute_overall(sources)

    # Aggregate tags and CVEs
    tags: list[str] = []
    cves: list[str] = []

    otx_data = sources.get("otx")
    if otx_data:
        tags.extend(otx_data.get("related_tags", []))

    shodan_data = sources.get("shodan")
    if shodan_data:
        cves.extend(shodan_data.get("vulns", []))
        for tag in shodan_data.get("tags", []):
            if tag not in tags:
                tags.append(tag)

    return {
        "ip": ip,
        "overall_score": overall_score,
        "verdict": _verdict(overall_score),
        "sources": sources,
        "tags": tags,
        "cves": sorted(cves),
    }


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def _verdict_panel(verdict: str, score: int) -> str:
    if verdict == "malicious":
        return f"[bold white on red]  MALICIOUS  [/bold white on red]  Score: [bold red]{score}/100[/bold red]"
    if verdict == "suspicious":
        return f"[bold yellow]  SUSPICIOUS  [/bold yellow]  Score: [bold yellow]{score}/100[/bold yellow]"
    return f"[bold green]  CLEAN  [/bold green]  Score: [bold green]{score}/100[/bold green]"


def format_reputation_output(data: dict) -> None:
    """Render IP reputation data using the osint.output helpers."""
    ip = data.get("ip", "unknown")

    print_section(f"IP Reputation -- {ip}")

    # --- Overall verdict ---
    verdict = data.get("verdict", "clean")
    score = data.get("overall_score", 0)
    print_panel("Verdict", _verdict_panel(verdict, score), style="red" if verdict == "malicious" else "yellow" if verdict == "suspicious" else "green")

    # --- Per-source table ---
    sources = data.get("sources", {})
    rows: list[list[Any]] = []

    abuseipdb = sources.get("abuseipdb")
    if abuseipdb:
        abuse_score = abuseipdb.get("abuse_confidence_score", 0)
        rows.append([
            "AbuseIPDB",
            f"{abuse_score}%",
            f"{abuseipdb.get('total_reports', 0)} reports",
            abuseipdb.get("usage_type") or "—",
        ])
    else:
        rows.append(["AbuseIPDB", "—", "no key / unavailable", "—"])

    vt = sources.get("virustotal")
    if vt:
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        rows.append([
            "VirusTotal",
            f"{_score_virustotal(vt)}%",
            f"{mal} malicious, {sus} suspicious",
            vt.get("as_owner") or "—",
        ])
    else:
        rows.append(["VirusTotal", "—", "no key / unavailable", "—"])

    otx = sources.get("otx")
    if otx:
        rows.append([
            "AlienVault OTX",
            f"{_score_otx(otx)}%",
            f"{otx.get('pulse_count', 0)} threat pulses",
            ", ".join(otx.get("related_tags", [])[:3]) or "—",
        ])
    else:
        rows.append(["AlienVault OTX", "—", "unavailable", "—"])

    shodan = sources.get("shodan")
    if shodan:
        rows.append([
            "Shodan",
            f"{_score_shodan(shodan)}%",
            f"{len(shodan.get('open_ports', []))} open ports, {len(shodan.get('vulns', []))} CVEs",
            shodan.get("org") or "—",
        ])
    else:
        rows.append(["Shodan", "—", "no key / unavailable", "—"])

    print_table(
        "Source Breakdown",
        ["Source", "Risk Score", "Summary", "Detail"],
        rows,
    )

    # --- CVEs ---
    cves = data.get("cves", [])
    if cves:
        print_warning(f"{len(cves)} CVE(s) found via Shodan:")
        cve_rows = [[cve] for cve in cves]
        print_table("CVEs", ["CVE ID"], cve_rows)

    # --- Threat tags ---
    tags = data.get("tags", [])
    if tags:
        print_finding(
            "Threat Tags",
            "  ".join(f"[cyan]{t}[/cyan]" for t in tags[:15]),
            source="otx+shodan",
        )
