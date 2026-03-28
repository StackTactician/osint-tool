"""
osint/modules/domain/git_scan.py

Active scan for exposed version control and configuration files.

Makes concurrent HEAD (and occasionally GET) requests to a set of well-known
sensitive paths. Any 200 response is flagged as a finding.
"""

from __future__ import annotations

import asyncio

import httpx

from osint.output import (
    print_error,
    print_info,
    print_section,
    print_table,
    print_warning,
)
from osint.output import severity_badge

# ---------------------------------------------------------------------------
# Target paths with associated severity levels
# ---------------------------------------------------------------------------

_TARGETS: list[tuple[str, str]] = [
    # path, severity
    ("/.git/HEAD",               "HIGH"),
    ("/.git/config",             "HIGH"),
    ("/.git/COMMIT_EDITMSG",     "MEDIUM"),
    ("/.svn/entries",            "HIGH"),
    ("/.env",                    "CRITICAL"),
    ("/.env.local",              "CRITICAL"),
    ("/.env.production",         "CRITICAL"),
    ("/config.php.bak",          "HIGH"),
    ("/wp-config.php.bak",       "HIGH"),
    ("/.htpasswd",               "HIGH"),
    ("/web.config.bak",          "HIGH"),
    ("/backup.sql",              "CRITICAL"),
    ("/database.sql",            "CRITICAL"),
    ("/.DS_Store",               "LOW"),
    ("/composer.json",           "LOW"),
    ("/package.json",            "LOW"),
    ("/Dockerfile",              "MEDIUM"),
    ("/.dockerenv",              "MEDIUM"),
]

# Paths where we should fetch the body for content verification
_FETCH_BODY_PATHS = {"/.git/HEAD", "/.git/config"}

# Max bytes to include in content preview
_PREVIEW_MAX = 256


# ---------------------------------------------------------------------------
# Scan function
# ---------------------------------------------------------------------------

async def scan_git_exposure(base_url: str) -> list[dict]:
    """
    Check for exposed version control and configuration files at *base_url*.

    Makes concurrent HEAD requests; fetches body for /.git/HEAD and
    /.git/config to verify the content is genuinely a git artifact.

    Returns:
        List of finding dicts with keys:
            path, status, size, content_preview, severity
        Only paths that returned HTTP 200 are included.
    """
    # Normalize base URL (strip trailing slash)
    base = base_url.rstrip("/")

    findings: list[dict] = []
    lock = asyncio.Lock()

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(10),
        verify=True,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        },
    ) as client:

        async def probe(path: str, severity: str) -> None:
            url = f"{base}{path}"
            try:
                # Always do a HEAD first to avoid pulling large files
                head_resp = await client.head(url)
                if head_resp.status_code != 200:
                    return

                content_length = int(
                    head_resp.headers.get("content-length", "0") or "0"
                )
                content_preview = ""

                # For git files, verify by fetching body
                if path in _FETCH_BODY_PATHS:
                    get_resp = await client.get(url)
                    body = get_resp.text[:_PREVIEW_MAX]
                    content_preview = body.strip()

                    # Sanity checks
                    if path == "/.git/HEAD" and not content_preview.startswith("ref:"):
                        return  # Not a real git HEAD file
                    if path == "/.git/config" and '[remote "origin"]' not in get_resp.text:
                        # Still flag it — config without remote is still sensitive
                        pass

                    content_length = content_length or len(get_resp.content)
                else:
                    # For other files, do a small GET for preview
                    try:
                        get_resp = await client.get(url)
                        content_preview = get_resp.text[:_PREVIEW_MAX].strip()
                        content_length = content_length or len(get_resp.content)
                    except Exception:
                        pass

                async with lock:
                    findings.append({
                        "path": path,
                        "status": 200,
                        "size": content_length,
                        "content_preview": content_preview,
                        "severity": severity,
                    })

            except Exception:
                # Network errors, timeouts, SSL errors — silently skip
                pass

        await asyncio.gather(*(probe(path, sev) for path, sev in _TARGETS))

    # Sort by severity then path
    _SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["path"]))

    return findings


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def format_git_output(base_url: str, findings: list[dict]) -> None:
    """Render git/config exposure findings as a Rich table."""
    print_section(f"Exposed Files Scan — {base_url}")

    if not findings:
        print_info("No exposed files or version control data found.")
        return

    print_warning(f"{len(findings)} sensitive file(s) exposed!")

    rows: list[list[str]] = []
    for f in findings:
        badge = severity_badge(f["severity"])
        preview = f["content_preview"]
        if preview:
            # Truncate long previews and escape Rich markup characters
            preview = preview[:80].replace("[", "\\[")
            if len(f["content_preview"]) > 80:
                preview += "..."
        size_str = str(f["size"]) if f["size"] else "—"
        rows.append([f["path"], badge, size_str, preview])

    print_table(
        "Exposed Sensitive Files",
        ["Path", "Severity", "Size (bytes)", "Content Preview"],
        rows,
    )
