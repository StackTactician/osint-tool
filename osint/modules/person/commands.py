from __future__ import annotations

import asyncio
import json

import click
from rich import box
from rich.live import Live
from rich.table import Table

from osint.events import Finding, FindingType, get_bus
from osint.output import get_console, print_error, print_info, print_warning


# ---------------------------------------------------------------------------
# Group definition
# ---------------------------------------------------------------------------


@click.group("person")
def person() -> None:
    """Investigate a person by email, username, or phone number."""


# ---------------------------------------------------------------------------
# email
# ---------------------------------------------------------------------------


@person.command("email")
@click.argument("email_address")
@click.option(
    "--check-breaches/--no-check-breaches",
    default=True,
    show_default=True,
    help="Check Have I Been Pwned for breaches and pastes.",
)
@click.option(
    "--check-disposable/--no-check-disposable",
    default=True,
    show_default=True,
    help="Query Kickbox to detect disposable / throwaway addresses.",
)
@click.option(
    "--check-mx/--no-check-mx",
    default=True,
    show_default=True,
    help="Perform a live MX record lookup for the email domain.",
)
@click.option(
    "--output-json",
    default=None,
    type=click.Path(),
    help="Write raw result data to this JSON file.",
)
@click.pass_context
def email_cmd(
    ctx: click.Context,
    email_address: str,
    check_breaches: bool,
    check_disposable: bool,
    check_mx: bool,
    output_json: str | None,
) -> None:
    """Investigate an email address (format, MX, Gravatar, HIBP breaches)."""
    from osint.modules.person.email_lookup import check_email, format_email_output

    async def _run() -> None:
        data = await check_email(
            email_address,
            session_id=0,
            check_breaches=check_breaches,
            check_disposable=check_disposable,
            check_mx=check_mx,
        )
        format_email_output(data)

        bus = get_bus()
        finding = Finding(
            type=FindingType.EMAIL,
            value=email_address,
            source="user_input",
            confidence=100,
            session_id=0,
        )
        await bus.publish(finding)

        if output_json:
            from osint.output import export_json

            export_json(data, output_json)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# phone
# ---------------------------------------------------------------------------


@person.command("phone")
@click.argument("phone")
@click.option(
    "--country",
    default="US",
    show_default=True,
    help="Default country code for parsing numbers without a + prefix (ISO 3166-1 alpha-2).",
)
@click.option(
    "--output-json",
    default=None,
    type=click.Path(),
    help="Write raw result data to this JSON file.",
)
@click.pass_context
def phone_cmd(
    ctx: click.Context,
    phone: str,
    country: str,
    output_json: str | None,
) -> None:
    """Investigate a phone number (carrier, region, line type, timezones)."""
    from osint.modules.person.phone_lookup import format_phone_output, lookup_phone

    data = lookup_phone(phone, default_country=country.upper())
    format_phone_output(data)

    if output_json:
        from osint.output import export_json

        export_json(data, output_json)


# ---------------------------------------------------------------------------
# username
# ---------------------------------------------------------------------------


def _build_live_table(username: str, results: list[dict]) -> Table:
    """Build a Rich table from the current result snapshot for the live display."""
    table = Table(
        title=f"[bold]Username search — [cyan]{username}[/][/]",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_black",
        expand=True,
    )
    table.add_column("Platform", no_wrap=True, min_width=14)
    table.add_column("Status", no_wrap=True, min_width=10)
    table.add_column("URL")
    table.add_column("Confidence", justify="right", min_width=10)

    for r in results:
        status = r.get("status", "pending")
        found = r.get("found", False)
        conf = r.get("confidence", 0)
        url = r.get("url", "")

        if status == "pending":
            status_str = "[dim]checking...[/]"
            conf_str = "[dim]—[/]"
            url_str = f"[dim]{url}[/]"
        elif found:
            status_str = "[bold green]found[/]"
            if conf >= 90:
                conf_str = f"[bold green]{conf}%[/]"
            elif conf >= 70:
                conf_str = f"[green]{conf}%[/]"
            else:
                conf_str = f"[yellow]{conf}%[/]"
            url_str = f"[link={url}]{url}[/link]"
        elif status == "not_found":
            status_str = "[dim]not found[/]"
            conf_str = "[dim]—[/]"
            url_str = f"[dim]{url}[/]"
        elif status == "timeout":
            status_str = "[yellow]timeout[/]"
            conf_str = "[dim]—[/]"
            url_str = f"[dim]{url}[/]"
        else:
            status_str = "[red]error[/]"
            conf_str = "[dim]—[/]"
            url_str = f"[dim]{url}[/]"

        table.add_row(r["platform"], status_str, url_str, conf_str)

    return table


@person.command("username")
@click.argument("username")
@click.option(
    "--platforms",
    default=None,
    help="Comma-separated list of platforms to check (default: all).",
)
@click.option(
    "--workers",
    default=20,
    show_default=True,
    help="Number of concurrent workers for platform checks.",
)
@click.option(
    "--timeout",
    default=10,
    show_default=True,
    help="Per-request timeout in seconds.",
)
@click.option(
    "--found-only",
    is_flag=True,
    default=False,
    help="Only show platforms where the username was found.",
)
@click.option(
    "--output-json",
    default=None,
    type=click.Path(),
    help="Write raw result data to this JSON file.",
)
@click.pass_context
def username_cmd(
    ctx: click.Context,
    username: str,
    platforms: str | None,
    workers: int,
    timeout: int,
    found_only: bool,
    output_json: str | None,
) -> None:
    """Search for a username across platforms (GitHub, Reddit, Twitter, and more)."""
    from osint.modules.person.username_search import (
        format_username_output,
        search_username,
        _load_platforms,
    )

    platform_list: list[str] | None = None
    if platforms:
        platform_list = [p.strip() for p in platforms.split(",") if p.strip()]

    # Pre-populate the results list with "pending" entries so the live table
    # shows all platforms from the start and updates in place.
    all_platforms = _load_platforms()
    if platform_list:
        normalized = {p.lower() for p in platform_list}
        target_platforms = [p for p in all_platforms if p["name"].lower() in normalized]
    else:
        target_platforms = all_platforms

    results: list[dict] = [
        {
            "platform": p["name"],
            "url": p["url_template"].format(username),
            "found": False,
            "confidence": 0,
            "status": "pending",
            "tags": p.get("tags", []),
        }
        for p in target_platforms
    ]

    # Index by platform name for O(1) updates from the callback
    result_index: dict[str, int] = {r["platform"]: i for i, r in enumerate(results)}

    console = get_console()

    def on_result(r: dict) -> None:
        idx = result_index.get(r["platform"])
        if idx is not None:
            results[idx] = r

    async def _run() -> list[dict]:
        return await search_username(
            username,
            platforms=platform_list,
            timeout=timeout,
            workers=workers,
            on_result=on_result,
        )

    with Live(
        _build_live_table(username, results),
        console=console,
        refresh_per_second=8,
        transient=True,
    ) as live:

        async def _run_with_refresh() -> list[dict]:
            task = asyncio.create_task(_run())
            while not task.done():
                live.update(_build_live_table(username, results))
                await asyncio.sleep(0.12)
            return await task

        final_results = asyncio.run(_run_with_refresh())

    # Render final grouped output (replaces the transient live table)
    format_username_output(username, final_results, found_only=found_only)

    if output_json:
        from osint.output import export_json

        export_json({"username": username, "results": final_results}, output_json)
