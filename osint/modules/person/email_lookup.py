from __future__ import annotations

import hashlib
import re
from typing import Any

import httpx

from osint.output import (
    get_console,
    print_error,
    print_info,
    print_panel,
    print_section,
    print_warning,
)
from osint.utils import make_http_client, validate_email_addr

# ---------------------------------------------------------------------------
# Known proxy / privacy email domains
# ---------------------------------------------------------------------------

_PRIVACY_DOMAINS: frozenset[str] = frozenset(
    {
        "maildrop.cc",
        "guerrillamail.com",
        "guerrillamail.net",
        "guerrillamail.org",
        "guerrillamail.biz",
        "guerrillamail.de",
        "guerrillamail.info",
        "sharklasers.com",
        "spam4.me",
        "mailnull.com",
        "trashmail.com",
        "trashmail.me",
        "trashmail.net",
        "trashmail.org",
        "trashmail.at",
        "trashmail.io",
        "trashmail.xyz",
        "tempmail.com",
        "temp-mail.org",
        "throwam.com",
        "throwam.net",
        "yopmail.com",
        "yopmail.fr",
        "cool.fr.nf",
        "jetable.fr.nf",
        "nospam.ze.tc",
        "nomail.xl.cx",
        "mega.zik.dj",
        "speed.1s.fr",
        "courriel.fr.nf",
        "moncourrier.fr.nf",
        "monemail.fr.nf",
        "monmail.fr.nf",
        "mailinator.com",
        "mailnesia.com",
        "spamgourmet.com",
        "spamgourmet.net",
        "spamgourmet.org",
        "dispostable.com",
        "fakeinbox.com",
        "spamevader.net",
        "discard.email",
        "spamoff.de",
        "humaility.com",
        "easytrashmail.com",
        "mt2015.com",
        "tempinbox.com",
        "spammotel.com",
        "spamfree24.org",
        "mvrht.com",
        "givmail.com",
    }
)


# ---------------------------------------------------------------------------
# Gravatar helper
# ---------------------------------------------------------------------------


def _gravatar_hash(email: str) -> str:
    """Return the MD5 hash used by Gravatar for an email address."""
    normalized = email.strip().lower()
    return hashlib.md5(normalized.encode()).hexdigest()  # noqa: S324


# ---------------------------------------------------------------------------
# Main lookup function
# ---------------------------------------------------------------------------


async def check_email(
    email: str,
    session_id: int,
    check_breaches: bool = True,
    check_disposable: bool = True,
    check_mx: bool = True,
) -> dict[str, Any]:
    """
    Run a comprehensive passive investigation on an email address.

    Returns a dict with format validation, MX records, disposable status,
    Gravatar presence, HIBP breaches, and HIBP pastes.
    """
    from osint.config import get_settings

    settings = get_settings()

    result: dict[str, Any] = {
        "email": email,
        "valid_format": False,
        "disposable": None,
        "mx_valid": False,
        "mx_records": [],
        "breaches": [],
        "pastes": [],
        "breach_count": 0,
        "paste_count": 0,
        "gravatar_url": None,
        "gravatar_exists": False,
        "domain": "",
        "username": "",
        "privacy_protected": False,
    }

    # ------------------------------------------------------------------
    # 1. Format validation
    # ------------------------------------------------------------------
    normalized = validate_email_addr(email)
    if normalized is None:
        return result

    result["valid_format"] = True
    result["email"] = normalized

    local, domain = normalized.split("@", 1)
    result["username"] = local
    result["domain"] = domain
    result["privacy_protected"] = domain.lower() in _PRIVACY_DOMAINS

    timeout = settings.scan.default_timeout

    async with make_http_client(timeout=timeout) as client:
        # ------------------------------------------------------------------
        # 2. Disposable check via Kickbox
        # ------------------------------------------------------------------
        if check_disposable:
            try:
                resp = await client.get(
                    f"https://open.kickbox.com/v1/disposable/{domain}",
                    timeout=timeout,
                )
                if resp.status_code == 200:
                    payload = resp.json()
                    result["disposable"] = bool(payload.get("disposable", False))
            except Exception:
                result["disposable"] = None

        # ------------------------------------------------------------------
        # 3. MX check via dnspython
        # ------------------------------------------------------------------
        if check_mx:
            try:
                import dns.resolver

                mx_answers = dns.resolver.resolve(domain, "MX")
                mx_records = sorted(
                    str(r.exchange).rstrip(".") for r in mx_answers
                )
                result["mx_records"] = mx_records
                result["mx_valid"] = len(mx_records) > 0
            except Exception:
                result["mx_valid"] = False
                result["mx_records"] = []

        # ------------------------------------------------------------------
        # 4. Gravatar
        # ------------------------------------------------------------------
        gh = _gravatar_hash(normalized)
        gravatar_url = f"https://www.gravatar.com/avatar/{gh}"
        try:
            resp = await client.get(
                f"{gravatar_url}?d=404",
                timeout=timeout,
            )
            if resp.status_code == 200:
                result["gravatar_exists"] = True
                result["gravatar_url"] = gravatar_url
        except Exception:
            pass

        # ------------------------------------------------------------------
        # 5 & 6. HIBP — breaches and pastes
        # ------------------------------------------------------------------
        if check_breaches:
            hibp_key = settings.keys.hibp_api_key
            if not hibp_key:
                print_warning(
                    "HIBP API key not configured — breach/paste checks skipped. "
                    "Set OSINT_KEYS__HIBP_API_KEY or add hibp_api_key under [keys] in config.toml."
                )
            else:
                hibp_headers = {
                    "hibp-api-key": hibp_key,
                    "User-Agent": "osint-tool",
                    "Accept": "application/json",
                }

                # Breaches
                try:
                    resp = await client.get(
                        f"https://haveibeenpwned.com/api/v3/breachedaccount/{normalized}"
                        "?truncateResponse=false",
                        headers=hibp_headers,
                        timeout=timeout,
                    )
                    if resp.status_code == 200:
                        raw_breaches: list[dict] = resp.json()
                        result["breaches"] = [
                            {
                                "Name": b.get("Name", ""),
                                "Domain": b.get("Domain", ""),
                                "BreachDate": b.get("BreachDate", ""),
                                "AddedDate": b.get("AddedDate", ""),
                                "PwnCount": b.get("PwnCount", 0),
                                "Description": b.get("Description", ""),
                                "DataClasses": b.get("DataClasses", []),
                                "IsVerified": b.get("IsVerified", False),
                                "IsSensitive": b.get("IsSensitive", False),
                            }
                            for b in raw_breaches
                        ]
                    # 404 = not found in any breach, which is the happy path
                except Exception as exc:
                    print_warning(f"HIBP breach lookup failed: {exc}")

                # Pastes
                try:
                    resp = await client.get(
                        f"https://haveibeenpwned.com/api/v3/pasteaccount/{normalized}",
                        headers=hibp_headers,
                        timeout=timeout,
                    )
                    if resp.status_code == 200:
                        result["pastes"] = resp.json()
                except Exception as exc:
                    print_warning(f"HIBP paste lookup failed: {exc}")

    result["breach_count"] = len(result["breaches"])
    result["paste_count"] = len(result["pastes"])

    return result


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------


def format_email_output(data: dict[str, Any]) -> None:
    """Render the result of check_email() to the console."""
    from rich import box
    from rich.table import Table
    from rich.text import Text

    console = get_console()

    if not data.get("valid_format"):
        print_error(f"Invalid email format: {data['email']}")
        return

    # ------------------------------------------------------------------
    # Summary panel
    # ------------------------------------------------------------------
    lines: list[str] = []

    def _tick(cond: bool | None) -> str:
        if cond is True:
            return "[green]yes[/]"
        if cond is False:
            return "[red]no[/]"
        return "[dim]unknown[/]"

    lines.append(f"  [bold bright_white]Email[/]         {data['email']}")
    lines.append(f"  [bold bright_white]Username[/]      {data['username']}")
    lines.append(f"  [bold bright_white]Domain[/]        {data['domain']}")
    lines.append(f"  [bold bright_white]Format valid[/]  [green]yes[/]")

    mx_val = _tick(data["mx_valid"])
    lines.append(f"  [bold bright_white]MX valid[/]      {mx_val}")

    if data["mx_records"]:
        lines.append(
            "  [bold bright_white]MX records[/]    "
            + "[dim], [/]".join(data["mx_records"])
        )

    disp = data.get("disposable")
    if disp is True:
        lines.append("  [bold bright_white]Disposable[/]    [bold red]yes[/]")
    elif disp is False:
        lines.append("  [bold bright_white]Disposable[/]    [green]no[/]")
    else:
        lines.append("  [bold bright_white]Disposable[/]    [dim]unchecked[/]")

    priv = data.get("privacy_protected", False)
    lines.append(
        f"  [bold bright_white]Privacy proxy[/] "
        + ("[bold yellow]yes[/]" if priv else "[dim]no[/]")
    )

    if data.get("gravatar_exists") and data.get("gravatar_url"):
        url = data["gravatar_url"]
        lines.append(
            f"  [bold bright_white]Gravatar[/]      [link={url}]{url}[/link]"
        )
    else:
        lines.append("  [bold bright_white]Gravatar[/]      [dim]none[/]")

    lines.append(
        f"  [bold bright_white]Breaches[/]      {data['breach_count']}"
    )
    lines.append(
        f"  [bold bright_white]Pastes[/]        {data['paste_count']}"
    )

    print_panel("Email Investigation", "\n".join(lines), style="bright_blue")

    # ------------------------------------------------------------------
    # Warnings
    # ------------------------------------------------------------------
    if data.get("disposable"):
        print_warning("This is a disposable / throwaway email address.")
    if data.get("privacy_protected"):
        print_warning("Domain is a known email proxy — real identity is masked.")

    # ------------------------------------------------------------------
    # Breaches table
    # ------------------------------------------------------------------
    if data["breaches"]:
        print_section("Breaches")

        sorted_breaches = sorted(
            data["breaches"],
            key=lambda b: b.get("BreachDate") or "",
            reverse=True,
        )

        table = Table(
            title="[bold]Have I Been Pwned — Breaches[/]",
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold bright_white",
            border_style="bright_black",
        )
        table.add_column("Name", no_wrap=True)
        table.add_column("Domain")
        table.add_column("Date", no_wrap=True)
        table.add_column("Records", justify="right")
        table.add_column("Data Exposed")
        table.add_column("V", justify="center")

        for b in sorted_breaches:
            count = b.get("PwnCount", 0)
            if count >= 1_000_000:
                count_str = f"[red]{count:,}[/]"
            elif count >= 100_000:
                count_str = f"[yellow]{count:,}[/]"
            else:
                count_str = f"[green]{count:,}[/]"

            data_classes = ", ".join(b.get("DataClasses", []))
            if len(data_classes) > 60:
                data_classes = data_classes[:57] + "..."

            verified = "[green]Y[/]" if b.get("IsVerified") else "[dim]N[/]"

            table.add_row(
                b.get("Name", ""),
                b.get("Domain", ""),
                b.get("BreachDate", ""),
                count_str,
                data_classes,
                verified,
            )

        console.print(table)

        # Aggregate unique data classes
        all_classes: list[str] = []
        seen_classes: set[str] = set()
        for b in data["breaches"]:
            for dc in b.get("DataClasses", []):
                if dc not in seen_classes:
                    seen_classes.add(dc)
                    all_classes.append(dc)

        if all_classes:
            tag_text = Text("  Exposed data classes:  ")
            for dc in sorted(all_classes):
                tag_text.append(f" {dc} ", style="bold black on bright_white")
                tag_text.append("  ")
            console.print(tag_text)
            console.print()

    # ------------------------------------------------------------------
    # Pastes table
    # ------------------------------------------------------------------
    if data["pastes"]:
        print_section("Pastes")

        table = Table(
            title="[bold]Have I Been Pwned — Pastes[/]",
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold bright_white",
            border_style="bright_black",
        )
        table.add_column("Source", no_wrap=True)
        table.add_column("Title")
        table.add_column("Date", no_wrap=True)
        table.add_column("Emails", justify="right")

        for p in data["pastes"]:
            table.add_row(
                p.get("Source", ""),
                p.get("Title") or "[dim]—[/]",
                p.get("Date") or "[dim]—[/]",
                str(p.get("EmailCount", "")),
            )

        console.print(table)
