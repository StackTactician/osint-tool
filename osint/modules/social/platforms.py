"""
osint/modules/social/platforms.py

Platform definition manager for username search.

Loads platform definitions from data/platforms.json and provides the
PlatformDef dataclass that encapsulates detection logic per platform.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


# ---------------------------------------------------------------------------
# Platform definition
# ---------------------------------------------------------------------------


@dataclass
class PlatformDef:
    """
    A single social-media platform definition loaded from platforms.json.

    Detection strategy is determined by error_type:
      - status_code:   profile absent  → HTTP status matches error_code
      - body_text:     profile absent  → error_body substring found in body
      - response_url:  profile absent  → final URL matches error_url_pattern
    """

    name: str
    url_template: str
    error_type: Literal["status_code", "body_text", "response_url"]
    error_code: int = 404
    error_body: str = ""
    error_url_pattern: str = ""
    headers: dict = field(default_factory=dict)
    request_method: str = "GET"
    timeout: int = 10
    tags: list[str] = field(default_factory=list)

    def build_url(self, username: str) -> str:
        """Interpolate username into url_template."""
        return self.url_template.format(username)

    def check_found(self, status: int, body: str, final_url: str) -> tuple[bool, int]:
        """
        Determine whether a profile was found at this platform.

        Returns (found, confidence) where confidence is 0-100.
        A result is only as reliable as the platform's detection method, so
        confidence is calibrated conservatively by strategy.
        """
        if self.error_type == "status_code":
            # status 0 means a transport-level failure — treat as not found
            if status == 0 or status == self.error_code:
                return False, 0

            base_confidence = 75

            if status == 200 and body:
                # Extract username from the URL template to check body presence
                # url_template uses {} as the placeholder
                try:
                    # Build a candidate username placeholder anchor that won't
                    # appear naturally: we look for the url_template prefix to
                    # derive what part of the URL is the username — instead,
                    # callers pass the raw body and we just measure signal.
                    # Since check_found doesn't receive username, use body heuristics.
                    if len(body) > 1000:
                        base_confidence = 80
                except Exception:
                    pass

            return True, base_confidence

        if self.error_type == "body_text":
            if status == 200 and self.error_body not in body:
                return True, 85
            return False, 0

        if self.error_type == "response_url":
            if status == 200 and not re.search(self.error_url_pattern, final_url):
                return True, 80
            return False, 0

        # Unknown error_type — treat as not found
        return False, 0


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def _find_platforms_file() -> Path | None:
    """
    Search known candidate paths for platforms.json and return the first
    that exists, or None if none are found.
    """
    candidates = [
        Path(__file__).parent.parent.parent.parent / "data" / "platforms.json",
        Path(__file__).parent.parent.parent / "data" / "platforms.json",
        Path.cwd() / "data" / "platforms.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _parse_platform(raw: dict) -> PlatformDef | None:
    """
    Parse a single JSON object into a PlatformDef.

    Returns None if the object is missing required keys so that one bad
    entry does not abort the entire load.
    """
    try:
        return PlatformDef(
            name=raw["name"],
            url_template=raw["url_template"],
            error_type=raw["error_type"],
            error_code=raw.get("error_code", 404),
            # platforms.json uses "error_text"; support both key names
            error_body=raw.get("error_body", raw.get("error_text", "")),
            error_url_pattern=raw.get("error_url_pattern", ""),
            headers=raw.get("headers") or {},
            request_method=raw.get("request_method", "GET"),
            timeout=raw.get("timeout", 10),
            tags=raw.get("tags") or [],
        )
    except (KeyError, TypeError, ValueError):
        return None


def load_platforms(filter_names: list[str] | None = None) -> list[PlatformDef]:
    """
    Load all platform definitions from platforms.json.

    Args:
        filter_names: If provided, only platforms whose name matches one of
                      these strings (case-insensitive) are returned.

    Returns:
        List of PlatformDef instances, in file order.

    Raises:
        FileNotFoundError: If platforms.json cannot be located.
        ValueError: If the JSON is malformed.
    """
    path = _find_platforms_file()
    if path is None:
        raise FileNotFoundError(
            "platforms.json not found. Searched: "
            "data/platforms.json relative to the package root and cwd."
        )

    try:
        raw_list: list[dict] = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed platforms.json at {path}: {exc}") from exc

    if not isinstance(raw_list, list):
        raise ValueError(f"platforms.json must be a JSON array, got {type(raw_list).__name__}")

    platforms: list[PlatformDef] = []
    for raw in raw_list:
        platform = _parse_platform(raw)
        if platform is None:
            continue
        platforms.append(platform)

    if filter_names:
        normalized = {n.lower() for n in filter_names}
        platforms = [p for p in platforms if p.name.lower() in normalized]

    return platforms


def get_platform_names() -> list[str]:
    """Return a sorted list of all platform names from platforms.json."""
    try:
        platforms = load_platforms()
    except (FileNotFoundError, ValueError):
        return []
    return sorted(p.name for p in platforms)
