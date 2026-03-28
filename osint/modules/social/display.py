"""
osint/modules/social/display.py

Live and static display helpers for username search results.

UsernameSearchDisplay manages a Rich Live context that updates in real time
as ProbeResult values arrive via on_result().  format_username_output is the
static counterpart used when results are already complete (file output, quiet
mode, etc.).
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from osint.modules.social.username_search import ProbeResult
from osint.output import get_console, print_section, print_success, print_info, print_warning


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------


def _status_style(result: ProbeResult) -> str:
    mapping = {
        "found": "bold green",
        "not_found": "dim",
        "timeout": "yellow",
        "rate_limited": "bold yellow",
        "error": "red",
    }
    return mapping.get(result.status, "white")


def _confidence_markup(confidence: int) -> str:
    if confidence >= 90:
        return f"[bold bright_green]{confidence}%[/]"
    if confidence >= 75:
        return f"[green]{confidence}%[/]"
    if confidence >= 50:
        return f"[yellow]{confidence}%[/]"
    if confidence > 0:
        return f"[red]{confidence}%[/]"
    return "[dim]-[/]"


def _status_label(result: ProbeResult) -> str:
    labels = {
        "found": "[bold green]FOUND[/]",
        "not_found": "[dim]not found[/]",
        "timeout": "[yellow]timeout[/]",
        "rate_limited": "[bold yellow]rate limited[/]",
        "error": "[red]error[/]",
    }
    return labels.get(result.status, result.status)


def _time_markup(ms: int) -> str:
    if ms >= 5000:
        return f"[yellow]{ms}ms[/]"
    if ms >= 2000:
        return f"[dim yellow]{ms}ms[/]"
    return f"[dim]{ms}ms[/]"


# ---------------------------------------------------------------------------
# Live display
# ---------------------------------------------------------------------------


class UsernameSearchDisplay:
    """
    Rich Live display that renders progress and a live result table during
    username search.

    Use as a context manager::

        with UsernameSearchDisplay(username, total) as display:
            results = await search_username(..., on_result=display.on_result)

    on_result() is thread-safe when called from within the same event loop
    because Rich's Live update is driven by the refresh timer, not by the
    caller's thread.
    """

    def __init__(self, username: str, total_platforms: int) -> None:
        self.username = username
        self.total = total_platforms

        self._found: list[ProbeResult] = []
        self._not_found: list[ProbeResult] = []
        self._errors: list[ProbeResult] = []
        self._completed = 0

        self._console: Console = get_console()
        self._progress = self._make_progress()
        self._task_id = self._progress.add_task(
            f"Searching [bold cyan]{username}[/]...",
            total=total_platforms,
        )
        self._result_rows: list[tuple[str, ...]] = []
        self._live: Live | None = None

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _make_progress(self) -> Progress:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            MofNCompleteColumn(),
            TextColumn("[dim]|[/]"),
            TextColumn("{task.percentage:>3.0f}%"),
            console=self._console,
            transient=False,
        )

    def _make_result_table(self) -> Table:
        t = Table(
            show_header=True,
            header_style="bold cyan",
            box=box.SIMPLE_HEAD,
            expand=True,
            border_style="bright_black",
            show_edge=False,
        )
        t.add_column("Platform", min_width=15, style="white")
        t.add_column("URL", overflow="fold", style="bright_black")
        t.add_column("Status", width=12, justify="center")
        t.add_column("Conf.", width=8, justify="right")
        t.add_column("Time", width=9, justify="right")
        return t

    def _make_counters_text(self) -> Text:
        found_count = len(self._found)
        not_found_count = len(self._not_found)
        error_count = len(self._errors)
        pending = self.total - self._completed

        t = Text()
        t.append("  Found: ", style="dim")
        t.append(str(found_count), style="bold green")
        t.append("  |  Not Found: ", style="dim")
        t.append(str(not_found_count), style="dim")
        t.append("  |  Pending: ", style="dim")
        t.append(str(pending), style="bold cyan" if pending > 0 else "dim")
        t.append("  |  Errors: ", style="dim")
        t.append(str(error_count), style="bold red" if error_count > 0 else "dim")
        return t

    def _build_renderable(self) -> Panel:
        """Assemble the full live renderable from current state."""
        table = self._make_result_table()

        # Only show found rows in the live table to keep it readable under load;
        # found results are what the operator cares about during a live run.
        for row in self._result_rows:
            table.add_row(*row)

        group = Group(
            self._progress,
            self._make_counters_text(),
            table,
        )
        return Panel(
            group,
            title=f"[bold bright_white]Username Search: {self.username}[/]",
            border_style="bright_blue",
            padding=(0, 1),
        )

    # ------------------------------------------------------------------
    # Result callback (called by search_username via on_result)
    # ------------------------------------------------------------------

    def on_result(self, result: ProbeResult) -> None:
        """
        Register one completed ProbeResult and refresh the live display.

        This is called synchronously from within search_username's on_result
        callback, which runs in the async event loop thread.
        """
        self._completed += 1
        self._progress.advance(self._task_id)

        if result.found:
            self._found.append(result)
        elif result.status in ("error", "rate_limited", "timeout"):
            self._errors.append(result)
        else:
            self._not_found.append(result)

        # Build the row regardless of status so the live table is complete,
        # but only add found + error rows to keep the display manageable.
        if result.status in ("found", "error", "rate_limited", "timeout"):
            row = (
                result.platform,
                result.url,
                _status_label(result),
                _confidence_markup(result.confidence),
                _time_markup(result.response_time_ms),
            )
            self._result_rows.append(row)

        if self._live is not None:
            self._live.update(self._build_renderable())

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "UsernameSearchDisplay":
        self._live = Live(
            self._build_renderable(),
            console=self._console,
            refresh_per_second=10,
            vertical_overflow="visible",
        )
        self._live.__enter__()
        return self

    def __exit__(self, *args: object) -> None:
        if self._live is not None:
            self._live.__exit__(*args)
        self._print_final_summary()

    # ------------------------------------------------------------------
    # Final summary (printed after Live context closes)
    # ------------------------------------------------------------------

    def _print_final_summary(self) -> None:
        found_count = len(self._found)
        total = self.total
        error_count = len(self._errors)

        print_section(f"Results: {self.username}")

        if found_count == 0:
            print_info(f"No profiles found across {total} platforms.")
        else:
            print_success(
                f"Found {found_count} profile{'s' if found_count != 1 else ''} "
                f"across {total} platforms."
            )

        if self._found:
            table = Table(
                show_header=True,
                header_style="bold bright_white",
                box=box.SIMPLE_HEAD,
                border_style="bright_black",
                expand=False,
            )
            table.add_column("Platform", min_width=14, style="bold white")
            table.add_column("URL", overflow="fold")
            table.add_column("Conf.", width=8, justify="right")
            table.add_column("Time", width=9, justify="right")

            for r in sorted(self._found, key=lambda x: x.platform.lower()):
                table.add_row(
                    r.platform,
                    f"[link={r.url}]{r.url}[/link]",
                    _confidence_markup(r.confidence),
                    _time_markup(r.response_time_ms),
                )

            self._console.print(table)

        if error_count > 0:
            print_warning(
                f"{error_count} platform{'s' if error_count != 1 else ''} "
                "returned errors or were unreachable."
            )


# ---------------------------------------------------------------------------
# Static formatter
# ---------------------------------------------------------------------------


def format_username_output(
    username: str,
    results: list[ProbeResult],
    found_only: bool = False,
) -> None:
    """
    Print a completed result set as a static Rich table.

    Used when results are already collected (e.g. after asyncio.run()) and
    the caller wants a clean tabular view rather than a live-updating one.
    This is also the path taken for file output and quiet-mode invocations.

    Args:
        username:   The searched username (used for section header).
        results:    The full list of ProbeResult values from search_username.
        found_only: When True, omit not_found rows from the table.
    """
    console = get_console()

    print_section(f"Username Search Results: {username}")

    display_results = [r for r in results if not found_only or r.found]

    if not display_results:
        print_info("No results to display.")
        return

    table = Table(
        show_header=True,
        header_style="bold bright_white",
        box=box.SIMPLE_HEAD,
        border_style="bright_black",
        expand=True,
    )
    table.add_column("Platform", min_width=14, style="white")
    table.add_column("URL", overflow="fold")
    table.add_column("Status", width=12, justify="center")
    table.add_column("Conf.", width=8, justify="right")
    table.add_column("Time", width=9, justify="right")

    for r in display_results:
        style = _status_style(r)
        table.add_row(
            f"[{style}]{r.platform}[/]",
            f"[{style}]{r.url}[/]" if r.found else f"[dim]{r.url}[/]",
            _status_label(r),
            _confidence_markup(r.confidence),
            _time_markup(r.response_time_ms),
        )

    console.print(table)

    found_count = sum(1 for r in results if r.found)
    if found_count:
        print_success(f"Found {found_count} of {len(results)} platforms checked.")
    else:
        print_info(f"No profiles found across {len(results)} platforms.")
