"""
osint/modules/domain/tech_detect.py

HTTP header + body technology fingerprinting.

Loads signatures from data/tech_signatures.json at import time.
Detection covers headers, cookies, body patterns, meta generators,
CDN/WAF signals, and favicon hash.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from pathlib import Path
from typing import Any

import httpx

from osint.output import (
    print_error,
    print_finding,
    print_info,
    print_section,
    print_table,
    print_warning,
)

# ---------------------------------------------------------------------------
# Signature data
# ---------------------------------------------------------------------------

_SIGNATURES_PATH = Path(__file__).parents[3] / "data" / "tech_signatures.json"

try:
    _SIGNATURES: dict[str, Any] = json.loads(_SIGNATURES_PATH.read_text(encoding="utf-8"))
except Exception:
    _SIGNATURES = {}

# ---------------------------------------------------------------------------
# CDN / WAF detection
# ---------------------------------------------------------------------------

# Header-based CDN/WAF signals: header name (lower) -> CDN name
_CDN_HEADERS: list[tuple[str, str]] = [
    ("cf-ray", "Cloudflare"),
    ("cf-cache-status", "Cloudflare"),
    ("x-served-by", "Fastly"),
    ("x-cache", "Varnish/CDN"),
    ("x-amz-cf-id", "CloudFront"),
    ("x-amz-request-id", "AWS"),
    ("x-nf-request-id", "Netlify"),
    ("x-vercel-id", "Vercel"),
    ("x-github-request-id", "GitHub Pages"),
    ("server: cloudflare", "Cloudflare"),
    ("server: cloudfront", "CloudFront"),
    ("server: akamaighost", "Akamai"),
    ("server: vercel", "Vercel"),
    ("server: netlify", "Netlify"),
]

# WAF signals
_WAF_HEADERS: list[tuple[str, str]] = [
    ("x-sucuri-id", "Sucuri WAF"),
    ("x-sucuri-cache", "Sucuri WAF"),
    ("x-waf-", "WAF"),
    ("x-protected-by", "WAF"),
    ("x-fortiweb-", "FortiWeb WAF"),
    ("x-distil-cs", "Distil Networks WAF"),
    ("x-imforwards", "Imperva WAF"),
    ("x-iinfo", "Imperva WAF"),
]

# Known CDN CIDR blocks (top 5 CDNs; a subset sufficient for fingerprinting)
_CDN_CIDRS: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
_CDN_CIDR_SPECS: list[tuple[str, str]] = [
    # Cloudflare
    ("103.21.244.0/22", "Cloudflare"),
    ("103.22.200.0/22", "Cloudflare"),
    ("103.31.4.0/22", "Cloudflare"),
    ("104.16.0.0/13", "Cloudflare"),
    ("104.24.0.0/14", "Cloudflare"),
    ("172.64.0.0/13", "Cloudflare"),
    ("131.0.72.0/22", "Cloudflare"),
    ("141.101.64.0/18", "Cloudflare"),
    ("162.158.0.0/15", "Cloudflare"),
    ("188.114.96.0/20", "Cloudflare"),
    ("190.93.240.0/20", "Cloudflare"),
    ("197.234.240.0/22", "Cloudflare"),
    ("198.41.128.0/17", "Cloudflare"),
    # Akamai (representative ranges)
    ("23.0.0.0/12", "Akamai"),
    ("23.192.0.0/11", "Akamai"),
    # Fastly
    ("23.235.32.0/20", "Fastly"),
    ("199.27.72.0/21", "Fastly"),
    # Amazon CloudFront
    ("13.224.0.0/14", "CloudFront"),
    ("52.84.0.0/15", "CloudFront"),
    # Google Cloud CDN
    ("34.96.0.0/20", "Google Cloud CDN"),
    ("34.104.0.0/23", "Google Cloud CDN"),
]

for _cidr, _name in _CDN_CIDR_SPECS:
    try:
        _CDN_CIDRS.append((ipaddress.ip_network(_cidr, strict=False), _name))
    except ValueError:
        pass


def _cdn_from_ip(ip_str: str) -> str | None:
    """Return CDN name if *ip_str* falls within a known CDN CIDR, else None."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for network, name in _CDN_CIDRS:
        try:
            if ip in network:
                return name
        except TypeError:
            pass
    return None


# ---------------------------------------------------------------------------
# Favicon hash (MD5-based approximation — not real Shodan MMH3)
# ---------------------------------------------------------------------------

def _favicon_hash(content: bytes) -> str:
    """
    Return a hex MD5 of the favicon bytes.

    Note: Shodan uses MurmurHash3 (mmh3). This is an MD5 approximation that
    is useful for correlation within this tool but does not match Shodan hashes.
    """
    return hashlib.md5(content).hexdigest()  # noqa: S324


# ---------------------------------------------------------------------------
# Version extraction
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(
    r"(?:v|version[:\s]*)(\d+(?:\.\d+){1,3})",
    re.IGNORECASE,
)


def _extract_version(text: str) -> str | None:
    """Try to extract a version string from a header value or body snippet."""
    match = _VERSION_RE.search(text)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Meta generator extraction
# ---------------------------------------------------------------------------

_META_GENERATOR_RE = re.compile(
    r'<meta\s[^>]*name=["\']generator["\']\s[^>]*content=["\'](.*?)["\']',
    re.IGNORECASE | re.DOTALL,
)


def _extract_meta_generators(body: str) -> list[str]:
    return _META_GENERATOR_RE.findall(body)


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def _detect_from_signatures(
    headers: dict[str, str],
    cookies: list[str],
    body: str,
    meta_generators: list[str],
) -> list[dict]:
    """
    Run the signature matching pipeline against headers, cookies, body, meta tags.

    Returns list of detection dicts with name, confidence, version, category.
    """
    detections: dict[str, dict] = {}  # name -> {confidence, version, category}

    headers_lower = {k.lower(): v for k, v in headers.items()}

    def _bump(name: str, delta: int, category: str, version: str | None = None) -> None:
        if name not in detections:
            detections[name] = {"confidence": 0, "version": None, "category": category}
        detections[name]["confidence"] = min(
            100, detections[name]["confidence"] + delta
        )
        if version and not detections[name]["version"]:
            detections[name]["version"] = version

    # Determine categories (rough heuristic)
    _CMS = {"WordPress", "Drupal", "Joomla", "Magento", "Shopify", "Wix",
             "Squarespace", "Webflow", "Ghost"}
    _FRAMEWORK = {"Django", "Rails", "Laravel", "Express", "Next.js", "Nuxt.js",
                  "React", "Vue", "Angular"}
    _SERVER = {"Nginx", "Apache", "IIS", "Python", "PHP", "Ruby", "Java"}
    _CLOUD = {"Cloudflare", "AWS S3", "CloudFront", "Vercel", "Netlify", "GitHub Pages"}

    def _category(name: str) -> str:
        if name in _CMS:
            return "CMS"
        if name in _FRAMEWORK:
            return "Framework/Library"
        if name in _SERVER:
            return "Server/Language"
        if name in _CLOUD:
            return "Cloud/CDN"
        return "Other"

    for tech_name, sig in _SIGNATURES.items():
        category = _category(tech_name)

        # Headers
        for header_sig in sig.get("headers", []):
            if ":" in header_sig:
                h_name, _, h_val = header_sig.partition(":")
                h_name = h_name.strip().lower()
                h_val = h_val.strip().lower()
                actual = headers_lower.get(h_name, "")
                if h_val in actual.lower():
                    ver = _extract_version(actual)
                    _bump(tech_name, 40, category, ver)
            else:
                # Header presence only
                if header_sig.lower() in headers_lower:
                    _bump(tech_name, 35, category)

        # X-Powered-By
        xpb = headers_lower.get("x-powered-by", "")
        if xpb:
            for header_sig in sig.get("headers", []):
                if "x-powered-by" in header_sig.lower():
                    sig_val = header_sig.split(":", 1)[-1].strip().lower()
                    if sig_val in xpb.lower():
                        ver = _extract_version(xpb)
                        _bump(tech_name, 50, category, ver)

        # Cookies
        cookie_str = " ".join(cookies).lower()
        for ck in sig.get("cookies", []):
            if ck.lower() in cookie_str:
                _bump(tech_name, 30, category)

        # Body patterns
        body_lower = body[:200_000].lower()  # limit for performance
        for pattern in sig.get("body_patterns", []):
            if pattern.lower() in body_lower:
                _bump(tech_name, 20, category)

        # Meta generators
        meta_lower = " ".join(meta_generators).lower()
        for gen in sig.get("meta_generators", []):
            if gen.lower() in meta_lower:
                ver = _extract_version(meta_lower)
                _bump(tech_name, 60, category, ver)

    return [
        {"name": name, **data}
        for name, data in detections.items()
        if data["confidence"] >= 20
    ]


# ---------------------------------------------------------------------------
# Main detect function
# ---------------------------------------------------------------------------

async def detect_technologies(
    url: str,
    follow_redirects: bool = True,
) -> dict:
    """
    Perform HTTP fingerprinting on *url*.

    Returns a dict with server info, detected technologies, CDN/WAF, and more.
    Never raises — returns {"error": str} on failure.
    """
    redirect_chain: list[str] = []
    start = time.monotonic()

    try:
        async with httpx.AsyncClient(
            follow_redirects=follow_redirects,
            timeout=httpx.Timeout(15),
            verify=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,image/avif,image/webp,*/*;q=0.8"
                ),
            },
        ) as client:
            resp = await client.get(url)

            elapsed_ms = int((time.monotonic() - start) * 1000)

            # Build redirect chain from history
            for hist_resp in resp.history:
                redirect_chain.append(str(hist_resp.url))
            final_url = str(resp.url)

            headers: dict[str, str] = dict(resp.headers)
            cookies = [f"{k}={v}" for k, v in resp.cookies.items()]
            body = resp.text

            # Meta generators from body
            meta_generators = _extract_meta_generators(body)

            # Detect technologies
            technologies = _detect_from_signatures(headers, cookies, body, meta_generators)
            technologies.sort(key=lambda t: t["confidence"], reverse=True)

            # CDN detection — header-based first
            cdn: str | None = None
            waf: str | None = None

            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
            # Check full "header: value" string for CDN signals
            headers_flat = " ".join(f"{k}: {v}" for k, v in headers_lower.items())

            for signal, cdn_name in _CDN_HEADERS:
                if ":" in signal:
                    # Full header:value match
                    h, _, v = signal.partition(":")
                    if headers_lower.get(h.strip()) is not None and v.strip() in headers_lower.get(h.strip(), ""):
                        cdn = cdn_name
                        break
                else:
                    if signal in headers_lower:
                        cdn = cdn_name
                        break

            # WAF detection
            for signal, waf_name in _WAF_HEADERS:
                for h in headers_lower:
                    if signal.rstrip("-") in h:
                        waf = waf_name
                        break
                if waf:
                    break

            # Favicon hash
            favicon_hash: str | None = None
            base_url = f"{resp.url.scheme}://{resp.url.host}"
            try:
                fav_resp = await client.get(f"{base_url}/favicon.ico", timeout=5)
                if fav_resp.status_code == 200 and fav_resp.content:
                    favicon_hash = _favicon_hash(fav_resp.content)
            except Exception:
                pass

            # Server header
            server = headers.get("server") or headers.get("Server") or None

            return {
                "url": url,
                "final_url": final_url,
                "status_code": resp.status_code,
                "server": server,
                "technologies": technologies,
                "headers": headers,
                "cookies": cookies,
                "favicon_hash": favicon_hash,
                "cdn": cdn,
                "waf": waf,
                "is_https": final_url.startswith("https://"),
                "redirect_chain": redirect_chain,
                "response_time_ms": elapsed_ms,
            }

    except Exception as exc:
        return {"error": str(exc), "url": url}


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def format_tech_output(data: dict) -> None:
    """Render technology detection results using osint.output helpers."""
    if "error" in data:
        print_error(f"Technology detection failed: {data['error']}")
        return

    print_section(f"Technology Fingerprint — {data.get('url', 'unknown')}")

    # URL / redirect chain
    redirect_chain = data.get("redirect_chain", [])
    if redirect_chain:
        print_info("Redirect chain:")
        for step in redirect_chain:
            print_info(f"  -> {step}")
    print_info(f"Final URL: {data.get('final_url', '—')}")

    # Basic info
    print_finding("Status", str(data.get("status_code", "—")), source="http")
    print_finding("Server", data.get("server") or "—", source="http")
    print_finding(
        "Response Time", f"{data.get('response_time_ms', 0)} ms", source="http"
    )
    print_finding(
        "HTTPS", "[green]Yes[/green]" if data.get("is_https") else "[red]No[/red]",
        source="http",
    )

    # CDN / WAF badges
    cdn = data.get("cdn")
    waf = data.get("waf")
    if cdn:
        print_finding("CDN", f"[bold cyan]{cdn}[/bold cyan]", source="headers")
    if waf:
        print_finding("WAF", f"[bold yellow]{waf}[/bold yellow]", source="headers")

    # Favicon hash
    fhash = data.get("favicon_hash")
    if fhash:
        print_finding("Favicon Hash (MD5)", fhash, source="favicon")

    # Technologies table
    techs = data.get("technologies", [])
    if techs:
        rows: list[list[str]] = []
        for t in techs:
            ver = t.get("version") or "—"
            rows.append([
                t["name"],
                str(t["confidence"]),
                ver,
                t.get("category", "—"),
            ])
        print_table(
            "Detected Technologies",
            ["Technology", "Confidence", "Version", "Category"],
            rows,
        )
    else:
        print_info("No technologies detected.")
