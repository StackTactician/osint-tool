from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from osint import __version__

console = Console()


def _print_banner(active: bool, stealth: bool, tor: bool) -> None:
    mode_parts: list[str] = []
    if active:
        mode_parts.append("[bold red]ACTIVE[/bold red]")
    else:
        mode_parts.append("[bold green]PASSIVE[/bold green]")
    if stealth:
        mode_parts.append("[bold yellow]STEALTH[/bold yellow]")
    if tor:
        mode_parts.append("[bold cyan]TOR[/bold cyan]")

    mode_str = "  ".join(mode_parts)
    title = Text(f"OSINT Tool  v{__version__}", style="bold white")
    body = f"Mode: {mode_str}"

    console.print(
        Panel(
            body,
            title=str(title),
            subtitle="Unified modular passive-first OSINT framework",
            border_style="bright_blue",
            padding=(0, 2),
        )
    )


# ---------------------------------------------------------------------------
# Submodule registration
# ---------------------------------------------------------------------------

def _register_modules(cli_group: click.Group) -> None:
    modules = [
        ("osint.modules.person.commands", "person"),
        ("osint.modules.domain.commands", "domain"),
        ("osint.modules.ip.commands", "ip"),
        ("osint.modules.social.commands", "social"),
        ("osint.modules.org.commands", "org"),
    ]
    for module_path, attr in modules:
        try:
            import importlib
            mod = importlib.import_module(module_path)
            cli_group.add_command(getattr(mod, attr))
        except ImportError as exc:
            console.print(
                f"[yellow]Warning:[/yellow] Could not load module [bold]{module_path}[/bold]: {exc}"
            )
        except AttributeError as exc:
            console.print(
                f"[yellow]Warning:[/yellow] Module [bold]{module_path}[/bold] has no command [bold]{attr}[/bold]: {exc}"
            )


# ---------------------------------------------------------------------------
# Main CLI group
# ---------------------------------------------------------------------------

@click.group(invoke_without_command=True)
@click.option(
    "--config",
    "config_path",
    type=click.Path(),
    default=str(Path.home() / ".osint" / "config.toml"),
    show_default=True,
    help="Path to config TOML file.",
    envvar="OSINT_CONFIG",
)
@click.option(
    "--output-json",
    "output_json",
    type=click.Path(),
    default=None,
    help="Write full results to a JSON file.",
)
@click.option(
    "--no-color",
    "no_color",
    is_flag=True,
    default=False,
    help="Disable color output.",
)
@click.option("--verbose", "verbosity", flag_value="verbose", default=False, help="Verbose output.")
@click.option("--quiet", "verbosity", flag_value="quiet", help="Suppress non-essential output.")
@click.option(
    "--active",
    is_flag=True,
    default=False,
    help="Enable active scanning (sends traffic to target). Off by default.",
)
@click.option(
    "--stealth",
    is_flag=True,
    default=False,
    help="Enable stealth mode (randomized delays, minimal footprint).",
)
@click.option(
    "--tor",
    is_flag=True,
    default=False,
    help="Route all traffic through Tor (requires Tor daemon running).",
)
@click.option(
    "--session",
    "session_name",
    type=str,
    default=None,
    help="Named session for result persistence and resumption.",
)
@click.option(
    "--proxy",
    "proxy_url",
    type=str,
    default=None,
    help="Custom proxy URL (e.g. http://user:pass@host:port).",
)
@click.pass_context
def cli(
    ctx: click.Context,
    config_path: str,
    output_json: str | None,
    no_color: bool,
    verbosity: str | None,
    active: bool,
    stealth: bool,
    tor: bool,
    session_name: str | None,
    proxy_url: str | None,
) -> None:
    """Unified modular passive-first OSINT framework."""
    ctx.ensure_object(dict)
    ctx.obj: dict[str, Any] = {
        "config_path": config_path,
        "output_json": output_json,
        "no_color": no_color,
        "verbosity": verbosity,
        "active": active,
        "stealth": stealth,
        "tor": tor,
        "session_name": session_name,
        "proxy_url": proxy_url,
    }

    if no_color:
        global console
        console = Console(no_color=True)

    if ctx.invoked_subcommand is None:
        _print_banner(active, stealth, tor)
        click.echo(ctx.get_help())
    else:
        if verbosity != "quiet":
            _print_banner(active, stealth, tor)


# ---------------------------------------------------------------------------
# Sessions command group
# ---------------------------------------------------------------------------

@cli.group("sessions")
def sessions() -> None:
    """Manage named scan sessions."""


@sessions.command("list")
@click.pass_context
def sessions_list(ctx: click.Context) -> None:
    """List all saved sessions."""
    import asyncio
    from osint.sessions import list_sessions, format_sessions_list

    sessions_data = asyncio.run(list_sessions())
    format_sessions_list(sessions_data)


@sessions.command("resume")
@click.argument("name")
@click.pass_context
def sessions_resume(ctx: click.Context, name: str) -> None:
    """Resume a saved session by name."""
    import asyncio
    from osint.sessions import get_session_findings, format_session_detail

    data = asyncio.run(get_session_findings(name))
    format_session_detail(data)


@sessions.command("diff")
@click.argument("session_a")
@click.argument("session_b")
@click.pass_context
def sessions_diff(ctx: click.Context, session_a: str, session_b: str) -> None:
    """Show differences between two sessions."""
    import asyncio
    from osint.sessions import diff_sessions, format_diff

    diff = asyncio.run(diff_sessions(session_a, session_b))
    format_diff(diff)


# ---------------------------------------------------------------------------
# Cache command group
# ---------------------------------------------------------------------------

@cli.group("cache")
def cache() -> None:
    """Manage the local result cache."""


@cache.command("list")
@click.pass_context
def cache_list(ctx: click.Context) -> None:
    """List cached results."""
    console.print("[yellow]Coming soon:[/yellow] cache list")


@cache.command("clear")
@click.option("--all", "clear_all", is_flag=True, default=False, help="Clear entire cache.")
@click.argument("key", required=False)
@click.pass_context
def cache_clear(ctx: click.Context, clear_all: bool, key: str | None) -> None:
    """Clear cached results."""
    console.print("[yellow]Coming soon:[/yellow] cache clear")


# ---------------------------------------------------------------------------
# Top-level stub commands
# ---------------------------------------------------------------------------

@cli.command("report")
@click.option("--session", "session_name", required=True, help="Session name to report on.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["html", "pdf", "json"]),
    default="html",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", default=None, help="Output file path (default: auto-named).")
@click.pass_context
def report_cmd(ctx: click.Context, session_name: str, fmt: str, output: str | None) -> None:
    """Generate a report from scan results."""
    import asyncio
    from osint.reports.html_report import generate_html_report
    from osint.reports.pdf_report import generate_pdf_report
    from osint.reports.builder import build_report_data
    from osint.output import print_success, print_error, export_json

    if output is None:
        output = f"osint-report-{session_name}.{fmt}"

    async def run() -> None:
        if fmt == "html":
            path = await generate_html_report(session_name, output)
            print_success(f"HTML report saved: {path}")
        elif fmt == "pdf":
            path = await generate_pdf_report(session_name, output)
            print_success(f"PDF report saved: {path}")
        elif fmt == "json":
            data = await build_report_data(session_name)
            export_json(data, output)
            print_success(f"JSON report saved: {output}")

    asyncio.run(run())


@cli.command("graph")
@click.option("--session", "session_name", required=True, help="Session to visualize.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["gephi", "mermaid", "d3", "ascii"]),
    default="ascii",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path.")
def graph_cmd(session_name: str, fmt: str, output: str | None) -> None:
    """Export an entity relationship graph from a saved session."""
    import asyncio
    from osint.graph import export_session_graph
    from osint.output import print_success

    try:
        path = asyncio.run(export_session_graph(session_name, fmt, output))
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1)

    if path:
        print_success(f"Graph exported: {path}")


@cli.command("watch")
@click.option("--target", "target", required=True, help="Target to monitor (domain, IP, email, username).")
@click.option("--module", "module", required=True, help="Module to run (e.g. domain.dns, ip.geo).")
@click.option("--interval", "interval", default="6h", show_default=True, help="Check interval, e.g. 30m, 6h, 1d.")
@click.option("--notify-webhook", "notify_webhook", default=None, help="Webhook URL to POST change alerts to.")
@click.option("--session", "session_base", default=None, help="Base name for watch sessions (default: <target>-watch).")
@click.pass_context
def watch(
    ctx: click.Context,
    target: str,
    module: str,
    interval: str,
    notify_webhook: str | None,
    session_base: str | None,
) -> None:
    """Continuously monitor a target for changes."""
    import asyncio
    from rich.panel import Panel as _Panel
    from osint.watch import WatchTarget, watch_loop, parse_interval

    try:
        interval_seconds = parse_interval(interval)
    except (ValueError, AttributeError):
        console.print(f"[bold red]Error:[/bold red] Invalid interval '{interval}'. Use e.g. 30m, 6h, 1d, 90s.")
        raise SystemExit(1)

    base = session_base or f"{target.replace('.', '-')}-watch"

    # Infer target_type from module prefix as a reasonable default
    _type_map = {"domain": "domain", "ip": "ip", "person": "email", "social": "username"}
    target_type = _type_map.get(module.split(".")[0], "domain")

    wt = WatchTarget(
        target=target,
        target_type=target_type,
        module=module,
        interval_seconds=interval_seconds,
        session_base=base,
        notify_webhook=notify_webhook,
    )

    # Startup banner
    webhook_line = f"\n  [bold]Webhook:[/bold]   {notify_webhook}" if notify_webhook else ""
    console.print(
        _Panel(
            f"  [bold]Target:[/bold]    [cyan]{target}[/cyan]  ([dim]{target_type}[/dim])\n"
            f"  [bold]Module:[/bold]    {module}\n"
            f"  [bold]Interval:[/bold]  {interval}  ({interval_seconds}s)\n"
            f"  [bold]Session:[/bold]   {base}-<timestamp>"
            f"{webhook_line}",
            title="[bold]Watch Mode[/bold]",
            subtitle="[dim]Press Ctrl+C to stop[/dim]",
            border_style="bright_blue",
            padding=(0, 2),
        )
    )

    stop_event = asyncio.Event()
    try:
        asyncio.run(watch_loop([wt], stop_event))
    except KeyboardInterrupt:
        console.print("\n[dim]Watch mode stopped.[/dim]")


@cli.command("server")
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind host.")
@click.option("--port", default=8080, show_default=True, type=int, help="Bind port.")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload (dev only).")
def server_cmd(host: str, port: int, reload: bool) -> None:
    """Launch the REST API server."""
    from osint.server import start_server
    from osint.output import print_panel

    print_panel(
        "OSINT Tool API Server",
        f"Starting on http://{host}:{port}\nDocs: http://{host}:{port}/docs",
    )
    start_server(host=host, port=port, reload=reload)


@cli.command("update-platforms")
@click.option(
    "--source",
    default=None,
    help="URL or file path to fetch updated platform definitions from.",
)
@click.pass_context
def update_platforms(ctx: click.Context, source: str | None) -> None:
    """Update the social platform definitions database."""
    console.print("[yellow]Coming soon:[/yellow] update-platforms")


# ---------------------------------------------------------------------------
# Register submodule command groups
# ---------------------------------------------------------------------------

_register_modules(cli)


if __name__ == "__main__":
    cli()
