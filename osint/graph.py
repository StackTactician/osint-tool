"""
osint/graph.py

Graph export utilities for the OSINT tool.

Used by both the CLI `osint graph` command and the reporting engine.
Converts session findings and edges into NetworkX directed graphs, then
exports them in the requested format.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx

# ---------------------------------------------------------------------------
# Type-to-group mapping for D3 force-directed graphs
# ---------------------------------------------------------------------------

_TYPE_GROUP: dict[str, int] = {
    "email":          0,
    "ip":             1,
    "domain":         2,
    "username":       3,
    "org":            4,
    "url":            5,
    "hash":           6,
    "phone":          7,
    "asn":            8,
    "person_name":    9,
    "credential":     10,
    "certificate":    11,
    "subdomain":      12,
    "social_profile": 13,
    "geo_coord":      14,
}


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_networkx_graph(nodes: list[dict], edges: list[dict]) -> nx.DiGraph:
    """
    Build a directed NetworkX graph from node and edge dicts.

    Args:
        nodes: Each dict has keys: id (int), type (str), value (str),
               confidence (int), source (str).
        edges: Each dict has keys: from (int), to (int), relationship (str).

    Returns:
        A nx.DiGraph with node attributes (type, value, confidence, source)
        and edge attribute (relationship).
    """
    G: nx.DiGraph = nx.DiGraph()

    for node in nodes:
        node_id = node["id"]
        G.add_node(
            node_id,
            type=node.get("type", ""),
            value=node.get("value", ""),
            confidence=node.get("confidence", 0),
            source=node.get("source", ""),
        )

    for edge in edges:
        G.add_edge(
            edge["from"],
            edge["to"],
            relationship=edge.get("relationship", ""),
        )

    return G


# ---------------------------------------------------------------------------
# Export: Gephi GEXF
# ---------------------------------------------------------------------------


def export_gephi(G: nx.DiGraph, output_path: str) -> str:
    """
    Write a GEXF file suitable for opening in Gephi.

    Args:
        G:           A directed graph produced by build_networkx_graph().
        output_path: Destination file path. The .gexf extension is expected
                     but not enforced.

    Returns:
        The resolved absolute path that was written.
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    nx.write_gexf(G, str(out))
    return str(out.resolve())


# ---------------------------------------------------------------------------
# Export: Mermaid
# ---------------------------------------------------------------------------


def export_mermaid(G: nx.DiGraph) -> str:
    """
    Generate a Mermaid ``graph LR`` diagram from the directed graph.

    Caps at 50 nodes to keep the diagram renderable.  Node values longer
    than 25 characters are truncated with an ellipsis.  Node types are used
    as subgraph labels to group related entities visually.

    Returns:
        A Mermaid diagram string ready to be embedded in Markdown.
    """
    # Gather nodes, capping at 50
    node_ids = list(G.nodes())[:50]
    included: set[Any] = set(node_ids)

    # Group node ids by type
    type_groups: dict[str, list[Any]] = {}
    for nid in node_ids:
        attrs = G.nodes[nid]
        ntype = attrs.get("type", "unknown")
        type_groups.setdefault(ntype, []).append(nid)

    def _safe_label(nid: Any) -> str:
        attrs = G.nodes[nid]
        value = attrs.get("value", str(nid))
        if len(value) > 25:
            value = value[:22] + "..."
        # Mermaid node ids must be alphanumeric; use n<id>
        return f'n{nid}["{value}"]'

    lines: list[str] = ["graph LR"]

    # Emit subgraphs per type
    for ntype, nids in type_groups.items():
        lines.append(f"    subgraph {ntype}")
        for nid in nids:
            lines.append(f"        {_safe_label(nid)}")
        lines.append("    end")

    # Emit edges (only between nodes in the cap)
    for src, dst, data in G.edges(data=True):
        if src in included and dst in included:
            rel = data.get("relationship", "")
            label = f"|{rel}|" if rel else ""
            lines.append(f"    n{src} -->{label} n{dst}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Export: D3.js
# ---------------------------------------------------------------------------


def export_d3(G: nx.DiGraph) -> dict:
    """
    Return a dict compatible with the D3.js force-directed graph format.

    Nodes include a ``group`` integer derived from the node type so that
    D3 colour scales can assign distinct colours to each entity category.

    Returns:
        {
          "nodes": [{"id": str, "type": str, "value": str,
                     "confidence": int, "group": int}, ...],
          "links": [{"source": str, "target": str, "relationship": str}, ...]
        }
    """
    nodes: list[dict] = []
    for nid, attrs in G.nodes(data=True):
        ntype = attrs.get("type", "")
        nodes.append({
            "id":         str(nid),
            "type":       ntype,
            "value":      attrs.get("value", ""),
            "confidence": attrs.get("confidence", 0),
            "group":      _TYPE_GROUP.get(ntype, 99),
        })

    links: list[dict] = []
    for src, dst, data in G.edges(data=True):
        links.append({
            "source":       str(src),
            "target":       str(dst),
            "relationship": data.get("relationship", ""),
        })

    return {"nodes": nodes, "links": links}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def compute_stats(G: nx.DiGraph) -> dict:
    """
    Compute summary statistics for the graph.

    Returns:
        node_count              — total number of nodes
        edge_count              — total number of directed edges
        density                 — graph density (0.0–1.0)
        weakly_connected_components — count of weakly connected components
        most_connected_node     — {"value": str, "degree": int} for the
                                  highest-degree node (in + out), or None
        node_types              — {"type": count, ...}
    """
    node_count = G.number_of_nodes()
    edge_count = G.number_of_edges()
    density = nx.density(G)

    wcc = nx.number_weakly_connected_components(G) if node_count > 0 else 0

    most_connected_node: dict | None = None
    if node_count > 0:
        # degree() returns a DegreeView of (node, degree) pairs
        top_id, top_deg = max(G.degree(), key=lambda kv: kv[1])  # type: ignore[arg-type]
        top_attrs = G.nodes[top_id]
        most_connected_node = {
            "value":  top_attrs.get("value", str(top_id)),
            "degree": top_deg,
        }

    node_types: dict[str, int] = {}
    for _, attrs in G.nodes(data=True):
        ntype = attrs.get("type", "unknown")
        node_types[ntype] = node_types.get(ntype, 0) + 1

    return {
        "node_count":                   node_count,
        "edge_count":                   edge_count,
        "density":                      density,
        "weakly_connected_components":  wcc,
        "most_connected_node":          most_connected_node,
        "node_types":                   node_types,
    }


# ---------------------------------------------------------------------------
# Session-level export
# ---------------------------------------------------------------------------


async def export_session_graph(
    session_name: str,
    fmt: str,
    output_path: str | None = None,
) -> str:
    """
    Load a session from the database, build a NetworkX graph, and export it.

    Args:
        session_name: Name of the session to load.
        fmt:          One of "gephi", "mermaid", "d3", "ascii".
        output_path:  Destination file path.  Auto-generated if None (not
                      used for "ascii" format).

    Returns:
        The path written, or "" for "ascii" (which prints to stdout directly).

    Raises:
        ValueError: If the session does not exist.
    """
    from osint.db import get_db
    from osint.output import print_graph_tree, print_warning

    db = get_db()
    await db.init()

    session = await db.get_session_by_name(session_name)
    if session is None:
        raise ValueError(f"Session '{session_name}' not found in database.")

    findings, edges = await db.get_graph(session.id)  # type: ignore[arg-type]

    # Translate DB objects into plain dicts for build_networkx_graph
    nodes: list[dict] = [
        {
            "id":         f.id,
            "type":       f.type,
            "value":      f.value,
            "confidence": f.confidence,
            "source":     f.source,
        }
        for f in findings
        if f.id is not None
    ]

    edge_dicts: list[dict] = [
        {
            "from":         e.from_finding_id,
            "to":           e.to_finding_id,
            "relationship": e.relationship,
        }
        for e in edges
    ]

    G = build_networkx_graph(nodes, edge_dicts)

    if fmt == "ascii":
        root_value = session.seed if session.seed else (nodes[0]["value"] if nodes else "")
        # print_graph_tree expects edges with "from"/"to" keys, which is what
        # edge_dicts already provides.
        print_graph_tree(nodes, edge_dicts, root_value)
        return ""

    # Derive a default output path if none supplied
    if output_path is None:
        ext_map = {"gephi": ".gexf", "mermaid": ".md", "d3": ".json"}
        ext = ext_map.get(fmt, ".txt")
        output_path = str(Path.cwd() / f"{session_name}_graph{ext}")

    if fmt == "gephi":
        return export_gephi(G, output_path)

    if fmt == "mermaid":
        content = export_mermaid(G)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
        return str(out.resolve())

    if fmt == "d3":
        data = export_d3(G)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return str(out.resolve())

    raise ValueError(f"Unknown graph format: '{fmt}'")
