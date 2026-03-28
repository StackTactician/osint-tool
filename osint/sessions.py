"""
osint/sessions.py

Session management logic — query, format, and diff named scan sessions.

This module contains pure business logic.  Click commands live in main.py
and delegate here.  All DB access goes through the Database singleton from
osint.db; all display goes through osint.output.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from osint.db import get_db
from osint.output import (
    get_console,
    print_error,
    print_info,
    print_panel,
    print_section,
    print_success,
    print_table,
    print_warning,
)


# ---------------------------------------------------------------------------
# Data access
# ---------------------------------------------------------------------------


def _finding_to_dict(f: Any) -> dict:
    """Convert a db.Finding row to a plain dict suitable for display/diffing."""
    return {
        "id": f.id,
        "session_id": f.session_id,
        "type": f.type,
        "value": f.value,
        "source": f.source,
        "confidence": f.confidence,
        "created_at": f.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if f.created_at else "",
        "tags": json.loads(f.tags_json) if f.tags_json else [],
        "raw_data": json.loads(f.raw_data_json) if f.raw_data_json else {},
        "parent_finding_id": f.parent_finding_id,
    }


def _edge_to_dict(e: Any) -> dict:
    """Convert a db.GraphEdge row to a plain dict."""
    return {
        "id": e.id,
        "from_finding_id": e.from_finding_id,
        "to_finding_id": e.to_finding_id,
        "relationship": e.relationship,
        "created_at": e.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if e.created_at else "",
    }


async def list_sessions() -> list[dict]:
    """
    Return all sessions from the DB, newest first.

    Each dict contains the fields expected by format_sessions_list().
    """
    db = get_db()
    await db.init()
    rows = await db.list_sessions()

    result: list[dict] = []
    for s in rows:
        result.append(
            {
                "id": s.id,
                "name": s.name,
                "seed": s.seed,
                "seed_type": s.seed_type,
                "created_at": s.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if s.created_at
                else "",
                "updated_at": s.updated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if s.updated_at
                else "",
                "finding_count": s.finding_count,
                "active_mode": s.active_mode,
            }
        )
    return result


async def get_session_findings(session_name: str) -> dict:
    """
    Return session metadata, its findings, and its graph edges.

    Raises SystemExit (via print_error) if the session does not exist so
    callers do not need to handle None.
    """
    db = get_db()
    await db.init()

    session = await db.get_session_by_name(session_name)
    if session is None:
        print_error(f"Session '{session_name}' not found.")
        raise SystemExit(1)

    findings_rows, edges_rows = await db.get_graph(session.id)  # type: ignore[arg-type]

    session_dict = {
        "id": session.id,
        "name": session.name,
        "seed": session.seed,
        "seed_type": session.seed_type,
        "created_at": session.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if session.created_at
        else "",
        "updated_at": session.updated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if session.updated_at
        else "",
        "finding_count": session.finding_count,
        "active_mode": session.active_mode,
    }

    return {
        "session": session_dict,
        "findings": [_finding_to_dict(f) for f in findings_rows],
        "edges": [_edge_to_dict(e) for e in edges_rows],
    }


async def diff_sessions(name_a: str, name_b: str) -> dict:
    """
    Compare two sessions by their findings.

    Identity: (type, value) pair.  Confidence differences on the same identity
    are reported separately from additions/removals.

    Returns a dict with keys: session_a, session_b, added, removed,
    confidence_changes, summary.
    """
    db = get_db()
    await db.init()

    sess_a = await db.get_session_by_name(name_a)
    if sess_a is None:
        print_error(f"Session '{name_a}' not found.")
        raise SystemExit(1)

    sess_b = await db.get_session_by_name(name_b)
    if sess_b is None:
        print_error(f"Session '{name_b}' not found.")
        raise SystemExit(1)

    findings_a = await db.get_findings(sess_a.id)  # type: ignore[arg-type]
    findings_b = await db.get_findings(sess_b.id)  # type: ignore[arg-type]

    # Index by (type, value)
    index_a: dict[tuple[str, str], Any] = {(f.type, f.value): f for f in findings_a}
    index_b: dict[tuple[str, str], Any] = {(f.type, f.value): f for f in findings_b}

    keys_a = set(index_a)
    keys_b = set(index_b)

    added_keys = keys_b - keys_a
    removed_keys = keys_a - keys_b
    common_keys = keys_a & keys_b

    added = [_finding_to_dict(index_b[k]) for k in sorted(added_keys)]
    removed = [_finding_to_dict(index_a[k]) for k in sorted(removed_keys)]

    confidence_changes: list[dict] = []
    for key in sorted(common_keys):
        fa = index_a[key]
        fb = index_b[key]
        if fa.confidence != fb.confidence:
            confidence_changes.append(
                {
                    "type": key[0],
                    "value": key[1],
                    "confidence_a": fa.confidence,
                    "confidence_b": fb.confidence,
                    "delta": fb.confidence - fa.confidence,
                }
            )

    # Build a human-readable summary
    parts: list[str] = []
    if added:
        parts.append(f"{len(added)} added")
    if removed:
        parts.append(f"{len(removed)} removed")
    if confidence_changes:
        parts.append(f"{len(confidence_changes)} confidence change(s)")
    summary = ", ".join(parts) if parts else "No differences found"

    return {
        "session_a": name_a,
        "session_b": name_b,
        "added": added,
        "removed": removed,
        "confidence_changes": confidence_changes,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Display formatters
# ---------------------------------------------------------------------------


def format_sessions_list(sessions: list[dict]) -> None:
    """Render a Rich table of all sessions."""
    if not sessions:
        print_info("No sessions found. Run a scan with --session <name> to create one.")
        return

    rows = [
        [
            s["name"],
            s["seed"],
            s["seed_type"],
            str(s["finding_count"]),
            s["created_at"],
            "[bold red]YES[/bold red]" if s["active_mode"] else "[dim]no[/dim]",
        ]
        for s in sessions
    ]

    print_table(
        title="Saved Sessions",
        columns=["Name", "Seed", "Type", "Findings", "Created", "Active Mode"],
        rows=rows,
        caption=f"{len(sessions)} session(s) total",
    )


def format_session_detail(data: dict) -> None:
    """
    Show a full session: metadata panel followed by findings grouped by type.
    """
    session = data["session"]
    findings: list[dict] = data["findings"]
    edges: list[dict] = data["edges"]

    # --- metadata panel ---
    mode_label = (
        "[bold red]ACTIVE[/bold red]" if session["active_mode"] else "[bold green]PASSIVE[/bold green]"
    )
    meta_lines = [
        f"[bold]Name:[/bold]         {session['name']}",
        f"[bold]Seed:[/bold]         {session['seed']}  ([dim]{session['seed_type']}[/dim])",
        f"[bold]Mode:[/bold]         {mode_label}",
        f"[bold]Findings:[/bold]     {session['finding_count']}",
        f"[bold]Graph edges:[/bold]  {len(edges)}",
        f"[bold]Created:[/bold]      {session['created_at']}",
        f"[bold]Updated:[/bold]      {session['updated_at']}",
    ]
    print_panel(
        title=f"Session: {session['name']}",
        content="\n".join(meta_lines),
        style="bright_blue",
    )

    if not findings:
        print_info("No findings recorded in this session.")
        return

    # --- group findings by type ---
    by_type: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_type[f["type"]].append(f)

    for ftype in sorted(by_type):
        group = by_type[ftype]
        print_section(f"{ftype.upper()}  ({len(group)})")

        rows = [
            [
                f["value"],
                str(f["confidence"]),
                f["source"],
                ", ".join(f["tags"]) if f["tags"] else "",
                f["created_at"],
            ]
            for f in group
        ]
        print_table(
            title="",
            columns=["Value", "Confidence", "Source", "Tags", "Discovered"],
            rows=rows,
        )


def format_diff(diff: dict) -> None:
    """Three-section display: Added, Removed, Changed confidence. Summary at top."""
    console = get_console()

    # Summary banner
    console.print()
    console.print(
        f"[bold white]Diff:[/bold white]  "
        f"[cyan]{diff['session_a']}[/cyan]  [dim]vs[/dim]  "
        f"[cyan]{diff['session_b']}[/cyan]"
    )
    console.print(f"[dim]{diff['summary']}[/dim]")
    console.print()

    # --- Added (green) ---
    added: list[dict] = diff["added"]
    if added:
        print_section(f"Added in {diff['session_b']}  (+{len(added)})")
        rows = [
            [
                f["type"],
                f["value"],
                str(f["confidence"]),
                f["source"],
            ]
            for f in added
        ]
        print_table(
            title="",
            columns=["Type", "Value", "Confidence", "Source"],
            rows=[[
                f"[bold green]{r[0]}[/bold green]",
                f"[green]{r[1]}[/green]",
                r[2],
                r[3],
            ] for r in rows],
        )
    else:
        console.print("[dim]  No findings added.[/dim]")

    # --- Removed (red) ---
    removed: list[dict] = diff["removed"]
    if removed:
        print_section(f"Removed since {diff['session_a']}  (-{len(removed)})")
        rows = [
            [
                f"[bold red]{f['type']}[/bold red]",
                f"[red]{f['value']}[/red]",
                str(f["confidence"]),
                f["source"],
            ]
            for f in removed
        ]
        print_table(
            title="",
            columns=["Type", "Value", "Confidence", "Source"],
            rows=rows,
        )
    else:
        console.print("[dim]  No findings removed.[/dim]")

    # --- Confidence changes (yellow) ---
    changes: list[dict] = diff["confidence_changes"]
    if changes:
        print_section(f"Confidence Changes  ({len(changes)})")
        rows_c = []
        for c in changes:
            delta = c["delta"]
            delta_str = (
                f"[green]+{delta}[/green]" if delta > 0 else f"[red]{delta}[/red]"
            )
            rows_c.append(
                [
                    f"[yellow]{c['type']}[/yellow]",
                    c["value"],
                    str(c["confidence_a"]),
                    str(c["confidence_b"]),
                    delta_str,
                ]
            )
        print_table(
            title="",
            columns=["Type", "Value", f"Conf ({diff['session_a']})", f"Conf ({diff['session_b']})", "Delta"],
            rows=rows_c,
        )
    else:
        console.print("[dim]  No confidence changes.[/dim]")

    console.print()
