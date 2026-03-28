from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

# ---------------------------------------------------------------------------
# Console singleton
# ---------------------------------------------------------------------------

_console: Console | None = None


def get_console(force_no_color: bool = False) -> Console:
    """Return the module-level Console singleton, creating it if needed."""
    global _console
    if _console is None:
        _console = Console(no_color=force_no_color)
    return _console


def init_console(color: bool = True) -> None:
    """(Re-)initialize the console singleton. Call once at startup."""
    global _console
    _console = Console(no_color=not color)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _confidence_color(confidence: int) -> str:
    if confidence <= 30:
        return "red"
    if confidence <= 60:
        return "yellow"
    if confidence <= 85:
        return "green"
    return "bright_green"


def _is_numeric(value: Any) -> bool:
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        try:
            float(value)
            return True
        except ValueError:
            return False
    return False


# ---------------------------------------------------------------------------
# Public rendering API
# ---------------------------------------------------------------------------

def print_banner(version: str) -> None:
    """Print the styled ASCII art banner panel."""
    console = get_console()
    art = (
        "[bold bright_cyan] ██████╗ ███████╗██╗███╗   ██╗████████╗[/]\n"
        "[bold cyan]██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝[/]\n"
        "[bold blue]██║   ██║███████╗██║██╔██╗ ██║   ██║   [/]\n"
        "[bold bright_blue]██║   ██║╚════██║██║██║╚██╗██║   ██║   [/]\n"
        "[bold blue] ██████╔╝███████║██║██║ ╚████║   ██║   [/]\n"
        "[bold cyan] ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   [/]\n"
        f"\n[dim]  OSINT TOOL[/]  [bold white]v{version}[/]\n"
        "[dim italic]  Passive-first intelligence framework[/]"
    )
    console.print(
        Panel(
            art,
            border_style="bright_blue",
            box=box.DOUBLE_EDGE,
            padding=(1, 4),
            subtitle="[dim]Use --help for available commands[/]",
        )
    )


def print_panel(title: str, content: str, style: str = "blue") -> None:
    """Render a Rich Panel with the given title and content."""
    get_console().print(
        Panel(
            content,
            title=f"[bold]{title}[/]",
            border_style=style,
            padding=(0, 2),
        )
    )


def print_table(
    title: str,
    columns: list[str],
    rows: list[list[Any]],
    caption: str = "",
) -> None:
    """Render a Rich Table. Auto-colors Confidence column and right-aligns numerics."""
    table = Table(
        title=f"[bold]{title}[/]" if title else None,
        caption=caption if caption else None,
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold bright_white",
        border_style="bright_black",
        title_style="bold white",
    )

    # Determine which columns are numeric by sampling first row
    numeric_cols: set[int] = set()
    if rows:
        for idx, cell in enumerate(rows[0]):
            if _is_numeric(cell):
                numeric_cols.add(idx)

    confidence_col: int | None = None
    for idx, col in enumerate(columns):
        is_confidence = col.strip().lower() == "confidence"
        if is_confidence:
            confidence_col = idx
        justify = "right" if idx in numeric_cols or is_confidence else "left"
        table.add_column(col, justify=justify, no_wrap=False)

    for row in rows:
        rendered: list[str] = []
        for idx, cell in enumerate(row):
            cell_str = str(cell)
            if idx == confidence_col:
                try:
                    val = int(cell)
                    color = _confidence_color(val)
                    cell_str = f"[{color}]{val}%[/{color}]"
                except (ValueError, TypeError):
                    pass
            rendered.append(cell_str)
        table.add_row(*rendered)

    get_console().print(table)


def print_finding(
    label: str,
    value: str,
    confidence: int = -1,
    source: str = "",
    tags: list[str] = [],
) -> None:
    """Print a single key-value finding line with optional confidence and source."""
    console = get_console()
    text = Text()
    text.append(f"  \u25cf {label.upper()}", style="bold bright_white")
    text.append("  ")
    text.append(value, style="white")
    if source:
        text.append(f"  ({source})", style="dim")
    if tags:
        for tag in tags:
            text.append(f" [{tag}]", style="dim cyan")
    if confidence >= 0:
        color = _confidence_color(confidence)
        text.append(f"  \u25cf {confidence}%", style=color)
    console.print(text)


def print_section(title: str) -> None:
    """Print a styled section header separator."""
    console = get_console()
    console.print()
    console.rule(f"[bold bright_white] {title} [/]", style="bright_blue")


def print_error(message: str) -> None:
    """Print a red error message with an x prefix."""
    get_console().print(f"[bold red]\u2717[/] [red]{message}[/]")


def print_warning(message: str) -> None:
    """Print a yellow warning with a warning-sign prefix."""
    get_console().print(f"[bold yellow]\u26a0[/] [yellow]{message}[/]")


def print_success(message: str) -> None:
    """Print a green success message with a check prefix."""
    get_console().print(f"[bold green]\u2713[/] [green]{message}[/]")


def print_info(message: str) -> None:
    """Print a dim informational message with an info prefix."""
    get_console().print(f"[dim]\u2139 {message}[/]")


def get_progress(description: str = "Working...") -> Progress:
    """Return a configured Progress context manager."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=get_console(),
        transient=False,
    )


def print_json(data: dict | list, title: str = "") -> None:
    """Pretty-print JSON using Rich Syntax highlighting."""
    console = get_console()
    raw = json.dumps(data, indent=2, default=str)
    syntax = Syntax(raw, "json", theme="monokai", line_numbers=False)
    if title:
        console.print(Panel(syntax, title=f"[bold]{title}[/]", border_style="bright_black"))
    else:
        console.print(syntax)


def print_graph_tree(
    nodes: list[dict],
    edges: list[dict],
    root_value: str,
) -> None:
    """Build and print a Rich Tree from graph node/edge data. Depth limited to 4."""
    console = get_console()

    # Index nodes by id for quick lookup
    node_by_id: dict[str, dict] = {n["id"]: n for n in nodes if "id" in n}

    # Build adjacency list (parent -> list of child ids)
    children_of: dict[str, list[str]] = {}
    for edge in edges:
        src = edge.get("source") or edge.get("from") or edge.get("src")
        tgt = edge.get("target") or edge.get("to") or edge.get("dst")
        if src and tgt:
            children_of.setdefault(src, []).append(tgt)

    # Find root node
    root_node: dict | None = None
    for n in nodes:
        if n.get("value") == root_value or n.get("label") == root_value:
            root_node = n
            break
    if root_node is None and nodes:
        root_node = nodes[0]

    if root_node is None:
        print_warning("print_graph_tree: no nodes to display")
        return

    def _node_label(node: dict) -> str:
        ntype = node.get("type", "unknown")
        value = node.get("value") or node.get("label") or node.get("id", "?")
        conf = node.get("confidence", -1)
        label = f"[bold cyan]{ntype}[/]  [white]{value}[/]"
        if isinstance(conf, int) and conf >= 0:
            color = _confidence_color(conf)
            label += f"  [{color}]{conf}%[/{color}]"
        return label

    def _build(tree_node: Tree, node: dict, depth: int, visited: set[str]) -> None:
        if depth > 4:
            return
        node_id = node.get("id", "")
        for child_id in children_of.get(node_id, []):
            if child_id in visited:
                continue
            child = node_by_id.get(child_id)
            if child is None:
                continue
            visited.add(child_id)
            branch = tree_node.add(_node_label(child))
            _build(branch, child, depth + 1, visited)

    root_id = root_node.get("id", "")
    tree = Tree(_node_label(root_node))
    visited: set[str] = {root_id}
    _build(tree, root_node, 1, visited)
    console.print(tree)


def export_json(data: dict, path: str) -> None:
    """Write data to a JSON file with tool metadata envelope."""
    from osint import __version__

    payload = {
        "tool": "osint-tool",
        "version": __version__,
        "exported_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "data": data,
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    print_success(f"Results exported to {out.resolve()}")


def format_datetime(dt: datetime) -> str:
    """Format a datetime using the configured output date format."""
    try:
        from osint.config import get_settings  # type: ignore[import]
        fmt = get_settings().output.date_format
    except Exception:
        fmt = "%Y-%m-%d %H:%M:%S UTC"
    return dt.strftime(fmt)


def severity_badge(level: str) -> str:
    """Return a Rich markup badge string for a severity level."""
    mapping: dict[str, tuple[str, str]] = {
        "CRITICAL": ("bold white on red", "CRITICAL"),
        "HIGH":     ("bold red",          "HIGH"),
        "MEDIUM":   ("bold yellow",       "MEDIUM"),
        "LOW":      ("bold blue",         "LOW"),
        "INFO":     ("dim",               "INFO"),
    }
    key = level.upper()
    style, label = mapping.get(key, ("dim", key))
    return f"[{style}] {label} [/{style}]"
