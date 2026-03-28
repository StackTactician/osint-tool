"""
osint/modules/ip/port_scan.py

Async TCP port scanner using asyncio.open_connection only.
No Nmap, no subprocess.

Banner grabbing, service identification, and risk-flag analysis included.
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
from typing import Any

from osint.output import (
    get_progress,
    print_error,
    print_finding,
    print_info,
    print_panel,
    print_section,
    print_table,
    print_warning,
    severity_badge,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090,
    27017, 5432, 6379, 11211, 2181, 9200, 9300,
]

SERVICE_NAMES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    2181: "ZooKeeper",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev",
    9090: "HTTP-Mgmt",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Transport",
    11211: "Memcached",
    27017: "MongoDB",
}

# Ports that warrant a risk flag if open without auth indicators
_HIGH_RISK_PORTS: dict[int, str] = {
    23: "Telnet — cleartext protocol, should be disabled",
    3389: "RDP — verify authentication and network exposure",
    27017: "MongoDB — often unauthenticated by default",
    6379: "Redis — often unauthenticated by default",
    11211: "Memcached — no built-in authentication",
    9200: "Elasticsearch — verify authentication",
    2181: "ZooKeeper — often unauthenticated",
    5900: "VNC — verify authentication strength",
}

# HTTP-family ports for which we send a real GET request
_HTTP_PORTS: set[int] = {80, 443, 8080, 8443, 8888, 9090}

# Regex for common version strings in banners
_VERSION_RE = re.compile(
    r"(?:version|ver|v)[\s:/]*([\d]+(?:\.[\d]+){1,3})"
    r"|(?:[\w\-]+)[\s/]([\d]+(?:\.[\d]+){1,3})",
    re.IGNORECASE,
)

_BANNER_READ_BYTES = 1024
_BANNER_TIMEOUT = 2.0


# ---------------------------------------------------------------------------
# Low-level probe helpers
# ---------------------------------------------------------------------------

async def _grab_banner(host: str, port: int, timeout: float) -> str | None:
    """
    Attempt to grab a service banner.

    For HTTP/HTTPS ports sends a minimal HEAD request; for everything else
    sends CRLF and reads whatever the service sends back.

    Returns the decoded banner string, or None on failure.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError, ConnectionRefusedError):
        return None

    try:
        banner: bytes = b""

        if port in _HTTP_PORTS:
            # Send a minimal HTTP/1.0 GET to capture the response line + headers
            request = (
                f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                "User-Agent: curl/7.81.0\r\nAccept: */*\r\n\r\n"
            )
            writer.write(request.encode())
            await asyncio.wait_for(writer.drain(), timeout=_BANNER_TIMEOUT)
            # Read headers only — stop at double CRLF
            try:
                raw = await asyncio.wait_for(
                    reader.read(_BANNER_READ_BYTES), timeout=_BANNER_TIMEOUT
                )
                # Trim to headers
                header_end = raw.find(b"\r\n\r\n")
                banner = raw[:header_end] if header_end != -1 else raw
            except asyncio.TimeoutError:
                pass
        else:
            # Generic probe: send CRLF, read whatever comes back
            writer.write(b"\r\n")
            await asyncio.wait_for(writer.drain(), timeout=_BANNER_TIMEOUT)
            try:
                banner = await asyncio.wait_for(
                    reader.read(_BANNER_READ_BYTES), timeout=_BANNER_TIMEOUT
                )
            except asyncio.TimeoutError:
                pass

    except Exception:
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass

    if not banner:
        return None

    # Decode leniently; replace non-UTF8 bytes with replacement char
    text = banner.decode("utf-8", errors="replace").strip()
    # Keep only printable ASCII + common whitespace; collapse control chars
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    return cleaned[:256] if cleaned else None


async def _probe_port(
    host: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
    grab_banner: bool,
) -> dict | None:
    """
    Probe a single port.

    Returns an open-port dict, or None if the port is closed/filtered.
    Uses sentinel string "TIMEOUT" to distinguish filtered from closed.
    """
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass

            banner: str | None = None
            if grab_banner:
                banner = await _grab_banner(host, port, timeout)

            return {
                "port": port,
                "service": SERVICE_NAMES.get(port, "unknown"),
                "banner": banner,
                "protocol": "tcp",
                "state": "open",
            }

        except asyncio.TimeoutError:
            return {"port": port, "state": "filtered"}
        except (ConnectionRefusedError, OSError):
            return {"port": port, "state": "closed"}


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

async def scan_ports(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 1.0,
    workers: int = 100,
) -> dict:
    """
    Scan TCP ports on *host* using asyncio.open_connection.

    Args:
        host:     Hostname or IP address to scan.
        ports:    List of port numbers. Defaults to the SANS top-20 + common set.
        timeout:  Per-port connection timeout in seconds.
        workers:  Maximum concurrent connection attempts.

    Returns a normalized result dict. Never raises.
    """
    if ports is None:
        ports = list(DEFAULT_PORTS)

    # Resolve hostname to IP for reporting
    resolved_ip = host
    try:
        info = await asyncio.get_event_loop().getaddrinfo(
            host, None, type=socket.SOCK_STREAM
        )
        if info:
            resolved_ip = info[0][4][0]
    except Exception:
        pass

    semaphore = asyncio.Semaphore(workers)
    start_time = time.monotonic()

    open_ports: list[dict] = []
    filtered_ports: list[int] = []
    closed_count = 0

    # Run scan with a progress bar
    with get_progress("Scanning ports...") as progress:
        task = progress.add_task("Scanning", total=len(ports))

        probe_tasks = [
            _probe_port(host, port, timeout, semaphore, grab_banner=True)
            for port in ports
        ]

        for coro in asyncio.as_completed(probe_tasks):
            result = await coro
            progress.advance(task)

            if result is None:
                closed_count += 1
                continue

            state = result.get("state")
            if state == "open":
                open_ports.append({
                    "port": result["port"],
                    "service": result["service"],
                    "banner": result.get("banner"),
                    "protocol": "tcp",
                })
            elif state == "filtered":
                filtered_ports.append(result["port"])
            else:
                closed_count += 1

    # Sort open ports by number for deterministic output
    open_ports.sort(key=lambda p: p["port"])
    filtered_ports.sort()

    scan_time = time.monotonic() - start_time

    return {
        "host": host,
        "resolved_ip": resolved_ip,
        "scan_time_seconds": round(scan_time, 2),
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "filtered_ports": filtered_ports,
        "closed_ports_count": closed_count,
    }


# ---------------------------------------------------------------------------
# Banner analysis helpers
# ---------------------------------------------------------------------------

def _extract_version(banner: str | None) -> str | None:
    if not banner:
        return None
    m = _VERSION_RE.search(banner)
    if m:
        return m.group(1) or m.group(2)
    return None


def _risk_flags(open_ports: list[dict]) -> list[str]:
    flags: list[str] = []
    open_port_nums = {p["port"] for p in open_ports}
    for port, reason in _HIGH_RISK_PORTS.items():
        if port in open_port_nums:
            flags.append(f"Port {port} ({SERVICE_NAMES.get(port, '?')}): {reason}")
    return flags


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def format_portscan_output(data: dict) -> None:
    """Render port scan results using the osint.output helpers."""
    host = data.get("host", "unknown")
    resolved = data.get("resolved_ip", host)

    print_section(f"Port Scan -- {host}")
    print_info(
        f"Resolved to {resolved}  |  "
        f"Scanned {data.get('ports_scanned', 0)} ports in "
        f"{data.get('scan_time_seconds', 0):.1f}s"
    )

    open_ports = data.get("open_ports", [])
    filtered = data.get("filtered_ports", [])
    closed = data.get("closed_ports_count", 0)

    print_finding(
        "Results",
        f"{len(open_ports)} open  |  {len(filtered)} filtered  |  {closed} closed",
    )

    if not open_ports:
        print_info("No open ports found.")
    else:
        rows: list[list[Any]] = []
        high_risk_nums = set(_HIGH_RISK_PORTS.keys())

        for port_info in open_ports:
            port = port_info["port"]
            service = port_info.get("service", "unknown")
            banner = port_info.get("banner")
            banner_display = (banner[:60] + "...") if banner and len(banner) > 60 else (banner or "—")
            version = _extract_version(banner)

            risk_tag = ""
            if port in high_risk_nums:
                risk_tag = " [bold red][HIGH RISK][/bold red]"

            port_cell = f"[bold red]{port}[/bold red]{risk_tag}" if port in high_risk_nums else str(port)
            service_cell = f"[bold]{service}[/bold]"
            version_cell = version or ""

            rows.append([port_cell, service_cell, version_cell, banner_display])

        print_table(
            f"Open Ports ({len(open_ports)})",
            ["Port", "Service", "Version", "Banner"],
            rows,
        )

    # --- Risk flags ---
    flags = _risk_flags(open_ports)
    if flags:
        print_warning("High-risk services detected:")
        for flag in flags:
            print_warning(f"  {flag}")

    # --- Filtered note ---
    if filtered:
        print_info(
            f"{len(filtered)} port(s) timed out (possibly filtered by firewall): "
            f"{', '.join(str(p) for p in filtered[:10])}"
            + ("..." if len(filtered) > 10 else "")
        )
