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
    console.print("[yellow]Coming soon:[/yellow] sessions list")


@sessions.command("resume")
@click.argument("name")
@click.pass_context
def sessions_resume(ctx: click.Context, name: str) -> None:
    """Resume a saved session by name."""
    console.print("[yellow]Coming soon:[/yellow] sessions resume")


@sessions.command("diff")
@click.argument("session_a")
@click.argument("session_b")
@click.pass_context
def sessions_diff(ctx: click.Context, session_a: str, session_b: str) -> None:
    """Show differences between two sessions."""
    console.print("[yellow]Coming soon:[/yellow] sessions diff")


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
@click.option("--session", "session_name", default=None, help="Session to generate report from.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["html", "pdf", "json", "markdown"]),
    default="html",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path.")
@click.pass_context
def report(ctx: click.Context, session_name: str | None, fmt: str, output: str | None) -> None:
    """Generate a report from scan results."""
    console.print("[yellow]Coming soon:[/yellow] report generation")


@cli.command("graph")
@click.option("--session", "session_name", default=None, help="Session to visualize.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["html", "png", "json"]),
    default="html",
    show_default=True,
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path.")
@click.pass_context
def graph(ctx: click.Context, session_name: str | None, fmt: str, output: str | None) -> None:
    """Generate an entity relationship graph from scan results."""
    console.print("[yellow]Coming soon:[/yellow] graph visualization")


@cli.command("watch")
@click.argument("target")
@click.option("--interval", default=3600, show_default=True, help="Check interval in seconds.")
@click.option("--alert-email", default=None, help="Email address to notify on change.")
@click.pass_context
def watch(ctx: click.Context, target: str, interval: int, alert_email: str | None) -> None:
    """Continuously monitor a target for changes."""
    console.print("[yellow]Coming soon:[/yellow] watch / continuous monitoring")


@cli.command("server")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host.")
@click.option("--port", default=8000, show_default=True, help="Bind port.")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload (dev only).")
@click.pass_context
def server(ctx: click.Context, host: str, port: int, reload: bool) -> None:
    """Launch the REST API server."""
    console.print("[yellow]Coming soon:[/yellow] REST API server")


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
