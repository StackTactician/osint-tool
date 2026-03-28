from __future__ import annotations

from typing import Any

import phonenumbers
from phonenumbers import (
    NumberParseException,
    PhoneNumberFormat,
    PhoneNumberType,
    carrier,
    geocoder,
    timezone,
)

from osint.output import get_console, print_error, print_panel, print_warning

# ---------------------------------------------------------------------------
# Line-type mapping
# ---------------------------------------------------------------------------

_LINE_TYPE_NAMES: dict[int, str] = {
    PhoneNumberType.FIXED_LINE: "FIXED_LINE",
    PhoneNumberType.MOBILE: "MOBILE",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
    PhoneNumberType.TOLL_FREE: "TOLL_FREE",
    PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
    PhoneNumberType.SHARED_COST: "SHARED_COST",
    PhoneNumberType.VOIP: "VOIP",
    PhoneNumberType.PERSONAL_NUMBER: "PERSONAL_NUMBER",
    PhoneNumberType.PAGER: "PAGER",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "VOICEMAIL",
    PhoneNumberType.UNKNOWN: "UNKNOWN",
}


# ---------------------------------------------------------------------------
# Main lookup
# ---------------------------------------------------------------------------


def lookup_phone(
    phone_str: str,
    default_country: str = "US",
) -> dict[str, Any]:
    """
    Parse and enrich a phone number using the phonenumbers library.

    All processing is offline — no network requests are made.
    """
    result: dict[str, Any] = {
        "input": phone_str,
        "valid": False,
        "possible": False,
        "e164": None,
        "national": None,
        "international": None,
        "country_code": None,
        "country": None,
        "region": None,
        "carrier": None,
        "line_type": None,
        "timezones": [],
        "is_possible": False,
        "number_type_raw": int(PhoneNumberType.UNKNOWN),
    }

    try:
        parsed = phonenumbers.parse(phone_str, default_country)
    except NumberParseException as exc:
        result["parse_error"] = str(exc)
        return result

    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)

    result["valid"] = is_valid
    result["possible"] = is_possible
    result["is_possible"] = is_possible

    if not is_possible:
        return result

    # Formatted representations
    result["e164"] = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
    result["national"] = phonenumbers.format_number(
        parsed, PhoneNumberFormat.NATIONAL
    )
    result["international"] = phonenumbers.format_number(
        parsed, PhoneNumberFormat.INTERNATIONAL
    )

    result["country_code"] = parsed.country_code

    # Geographic data
    region = phonenumbers.region_code_for_number(parsed)
    result["country"] = geocoder.description_for_number(parsed, "en") or None
    result["region"] = region or None

    # Carrier (populated for mobile numbers in supported regions)
    carrier_name = carrier.name_for_number(parsed, "en")
    result["carrier"] = carrier_name if carrier_name else None

    # Line type
    raw_type = phonenumbers.number_type(parsed)
    result["number_type_raw"] = int(raw_type)
    result["line_type"] = _LINE_TYPE_NAMES.get(raw_type, "UNKNOWN")

    # Timezones
    tz_list = list(timezone.time_zones_for_number(parsed))
    result["timezones"] = tz_list

    return result


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------


def format_phone_output(data: dict[str, Any]) -> None:
    """Render the result of lookup_phone() to the console."""
    console = get_console()

    lines: list[str] = []

    def _row(label: str, value: str | None, style: str = "white") -> None:
        if value:
            lines.append(f"  [bold bright_white]{label:<20}[/] [{style}]{value}[/{style}]")
        else:
            lines.append(f"  [bold bright_white]{label:<20}[/] [dim]—[/]")

    _row("Input", data["input"])

    if data.get("parse_error"):
        lines.append(f"\n  [red]Parse error:[/] {data['parse_error']}")
        print_panel("Phone Lookup", "\n".join(lines), style="red")
        print_error("Could not parse phone number.")
        return

    valid = data.get("valid", False)
    possible = data.get("possible", False)

    if not possible:
        lines.append("  [bold bright_white]Status[/]               [red]impossible[/]")
        print_panel("Phone Lookup", "\n".join(lines), style="red")
        print_warning(
            "Number is not a possible phone number — it may be too short, "
            "too long, or use an unallocated country code."
        )
        return

    status_str = "[green]valid[/]" if valid else "[yellow]possible (not verified valid)[/]"
    lines.append(f"  [bold bright_white]{'Status':<20}[/] {status_str}")

    _row("E.164", data.get("e164"))
    _row("National", data.get("national"))
    _row("International", data.get("international"))
    _row("Country code", f"+{data['country_code']}" if data.get("country_code") else None)
    _row("Country", data.get("country"))
    _row("Region", data.get("region"))

    carrier_name = data.get("carrier")
    _row("Carrier", carrier_name if carrier_name else "unknown / not available")

    line_type = data.get("line_type", "UNKNOWN")
    if line_type == "VOIP":
        lines.append(
            f"  [bold bright_white]{'Line type':<20}[/] [bold yellow]VOIP[/] "
            "[dim](often used for privacy or virtual numbers)[/]"
        )
    elif line_type == "MOBILE":
        lines.append(f"  [bold bright_white]{'Line type':<20}[/] [cyan]MOBILE[/]")
    elif line_type in ("FIXED_LINE", "FIXED_LINE_OR_MOBILE"):
        lines.append(f"  [bold bright_white]{'Line type':<20}[/] [white]{line_type}[/]")
    elif line_type == "TOLL_FREE":
        lines.append(f"  [bold bright_white]{'Line type':<20}[/] [blue]TOLL_FREE[/]")
    else:
        lines.append(f"  [bold bright_white]{'Line type':<20}[/] [dim]{line_type}[/]")

    timezones = data.get("timezones", [])
    if timezones:
        _row("Timezone(s)", ", ".join(timezones))
    else:
        _row("Timezone(s)", None)

    panel_style = "bright_blue" if valid else "yellow"
    print_panel("Phone Lookup", "\n".join(lines), style=panel_style)

    if line_type == "VOIP":
        print_warning(
            "VOIP line detected — this number may be a virtual or privacy number "
            "registered through a VoIP provider (e.g. Google Voice, TextNow, Hushed)."
        )

    if not valid and possible:
        print_warning(
            "Number is structurally possible but not confirmed valid. "
            "It may be unallocated or from a region with incomplete number data."
        )
