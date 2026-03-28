"""
osint/server.py

FastAPI REST API server wrapping all OSINT modules.

Run via:
    osint server --host 0.0.0.0 --port 8080

Or programmatically:
    from osint.server import start_server
    start_server(host="0.0.0.0", port=8080)

Auth:
    Set [server] api_key in config.toml or OSINT_SERVER__API_KEY env var.
    If api_key is empty, the auth check is skipped.

Job system:
    Slow operations (username search, subdomain enumeration) return a job_id
    immediately.  Poll GET /jobs/{job_id} until status == "done" or "error".
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, UTC
from typing import Any, Optional

import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from osint.config import get_settings

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="OSINT Tool API",
    description="REST API for the passive-first OSINT framework",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


async def verify_api_key(x_api_key: str = Header(default="")) -> None:
    """
    Dependency that enforces API-key auth when one is configured.

    If settings.server.api_key is empty, every request is allowed through.
    """
    settings = get_settings()
    if settings.server.api_key and x_api_key != settings.server.api_key:
        raise HTTPException(status_code=403, detail="Invalid API key")


# ---------------------------------------------------------------------------
# In-memory job store
# ---------------------------------------------------------------------------

_jobs: dict[str, dict] = {}  # job_id -> {"status", "result", "created_at"}


def create_job() -> str:
    """Create a new pending job entry and return its id."""
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "status":     "pending",
        "result":     None,
        "created_at": datetime.now(UTC).isoformat(),
    }
    return job_id


async def run_job(job_id: str, coro: Any) -> None:
    """
    Execute *coro*, update the job record on completion or failure.

    Intended to be passed to BackgroundTasks.add_task().
    """
    _jobs[job_id]["status"] = "running"
    try:
        result = await coro
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["result"] = result
    except Exception as exc:
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["result"] = {"error": str(exc)}


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class EmailRequest(BaseModel):
    email: str
    check_breaches: bool = True


class PhoneRequest(BaseModel):
    phone: str
    country: str = "US"


class UsernameRequest(BaseModel):
    username: str
    platforms: Optional[list[str]] = None
    workers: int = 20


class DomainRequest(BaseModel):
    domain: str


class DnsRequest(BaseModel):
    domain: str
    types: Optional[list[str]] = None


class SubdomainRequest(BaseModel):
    domain: str
    sources: Optional[list[str]] = None


class HeadersRequest(BaseModel):
    url: str


class IpRequest(BaseModel):
    ip: str


class AsnRequest(BaseModel):
    ip_or_asn: str


class PortScanRequest(BaseModel):
    host: str
    ports: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_ports(ports_str: str) -> list[int] | None:
    """
    Parse a comma-separated / range port string into a sorted list of ints.

    Examples:
        "80,443,8080"   -> [80, 443, 8080]
        "1-1024"        -> [1, 2, ..., 1024]
        ""              -> None  (caller uses module default)

    Raises HTTPException(400) on invalid input.
    """
    if not ports_str.strip():
        return None

    result: list[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                lo_i, hi_i = int(lo), int(hi)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid port range: '{part}'")
            if lo_i > hi_i or lo_i < 1 or hi_i > 65535:
                raise HTTPException(status_code=400, detail=f"Port range out of bounds: '{part}'")
            result.extend(range(lo_i, hi_i + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid port: '{part}'")
            if p < 1 or p > 65535:
                raise HTTPException(status_code=400, detail=f"Port out of range: {p}")
            result.append(p)

    return sorted(set(result))


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": "0.1.0"}


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


@app.get("/sessions")
async def list_sessions(_: None = Depends(verify_api_key)) -> list[dict]:
    """Return all sessions ordered by creation time (newest first)."""
    from osint.db import get_db

    db = get_db()
    await db.init()
    sessions = await db.list_sessions()
    return [
        {
            "id":            s.id,
            "name":          s.name,
            "seed":          s.seed,
            "seed_type":     s.seed_type,
            "created_at":    s.created_at.isoformat(),
            "updated_at":    s.updated_at.isoformat(),
            "finding_count": s.finding_count,
            "active_mode":   s.active_mode,
            "stealth_mode":  s.stealth_mode,
        }
        for s in sessions
    ]


@app.get("/sessions/{name}")
async def get_session(name: str, _: None = Depends(verify_api_key)) -> dict:
    """Return session detail plus all findings."""
    from osint.db import get_db

    db = get_db()
    await db.init()
    session = await db.get_session_by_name(name)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session '{name}' not found")

    findings = await db.get_findings(session.id)  # type: ignore[arg-type]
    return {
        "id":            session.id,
        "name":          session.name,
        "seed":          session.seed,
        "seed_type":     session.seed_type,
        "created_at":    session.created_at.isoformat(),
        "updated_at":    session.updated_at.isoformat(),
        "finding_count": session.finding_count,
        "active_mode":   session.active_mode,
        "stealth_mode":  session.stealth_mode,
        "findings": [
            {
                "id":         f.id,
                "type":       f.type,
                "value":      f.value,
                "source":     f.source,
                "confidence": f.confidence,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ],
    }


@app.get("/sessions/{name}/graph")
async def get_session_graph(name: str, _: None = Depends(verify_api_key)) -> dict:
    """Return graph nodes and edges for a session."""
    from osint.db import get_db

    db = get_db()
    await db.init()
    session = await db.get_session_by_name(name)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session '{name}' not found")

    findings, edges = await db.get_graph(session.id)  # type: ignore[arg-type]

    return {
        "nodes": [
            {
                "id":         f.id,
                "type":       f.type,
                "value":      f.value,
                "confidence": f.confidence,
                "source":     f.source,
            }
            for f in findings
            if f.id is not None
        ],
        "edges": [
            {
                "from":         e.from_finding_id,
                "to":           e.to_finding_id,
                "relationship": e.relationship,
            }
            for e in edges
        ],
    }


# ---------------------------------------------------------------------------
# Person — email
# ---------------------------------------------------------------------------


@app.post("/person/email")
async def person_email(body: EmailRequest, _: None = Depends(verify_api_key)) -> dict:
    """Run a passive email investigation."""
    from osint.modules.person.email_lookup import check_email

    # session_id 0 — API callers don't get an auto-created session; they can
    # create one via the sessions endpoints or let the module skip persistence.
    try:
        result = await check_email(
            body.email,
            session_id=0,
            check_breaches=body.check_breaches,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# Person — phone
# ---------------------------------------------------------------------------


@app.post("/person/phone")
async def person_phone(body: PhoneRequest, _: None = Depends(verify_api_key)) -> dict:
    """Parse and enrich a phone number (offline, no network calls)."""
    from osint.modules.person.phone_lookup import lookup_phone

    try:
        result = lookup_phone(body.phone, default_country=body.country)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# Person — username  (background job)
# ---------------------------------------------------------------------------


@app.post("/person/username")
async def person_username(
    body: UsernameRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(verify_api_key),
) -> dict:
    """
    Search for a username across social platforms.

    Returns a job_id immediately — poll GET /jobs/{job_id} for results.
    """
    from osint.modules.person.username_search import search_username

    job_id = create_job()
    background_tasks.add_task(
        run_job,
        job_id,
        search_username(
            body.username,
            platforms=body.platforms,
            workers=body.workers,
        ),
    )
    return {"job_id": job_id, "status": "pending", "poll_url": f"/jobs/{job_id}"}


# ---------------------------------------------------------------------------
# Domain — WHOIS
# ---------------------------------------------------------------------------


@app.post("/domain/whois")
async def domain_whois(body: DomainRequest, _: None = Depends(verify_api_key)) -> dict:
    """Run a WHOIS / RDAP lookup for a domain."""
    from osint.modules.domain.whois_lookup import lookup_whois

    try:
        result = await lookup_whois(body.domain)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# Domain — DNS
# ---------------------------------------------------------------------------


@app.post("/domain/dns")
async def domain_dns(body: DnsRequest, _: None = Depends(verify_api_key)) -> dict:
    """Query DNS records for a domain."""
    from osint.modules.domain.dns_lookup import lookup_records

    try:
        result = await lookup_records(body.domain, types=body.types)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# Domain — subdomains  (background job)
# ---------------------------------------------------------------------------


@app.post("/domain/subdomains")
async def domain_subdomains(
    body: SubdomainRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(verify_api_key),
) -> dict:
    """
    Enumerate subdomains for a domain.

    Returns a job_id immediately — poll GET /jobs/{job_id} for results.
    """
    from osint.modules.domain.subdomain_enum import enumerate_subdomains

    job_id = create_job()
    background_tasks.add_task(
        run_job,
        job_id,
        enumerate_subdomains(body.domain, sources=body.sources),
    )
    return {"job_id": job_id, "status": "pending", "poll_url": f"/jobs/{job_id}"}


# ---------------------------------------------------------------------------
# Domain — headers / tech fingerprint  (ACTIVE)
# ---------------------------------------------------------------------------


@app.post("/domain/headers")
async def domain_headers(body: HeadersRequest, _: None = Depends(verify_api_key)) -> dict:
    """
    Fetch HTTP headers and fingerprint technologies for a URL.

    This endpoint sends a live HTTP request to the target — it is an ACTIVE
    operation and should only be used with explicit operator consent.
    """
    from osint.modules.domain.tech_detect import detect_technologies

    try:
        result = await detect_technologies(body.url)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# IP — geo
# ---------------------------------------------------------------------------


@app.post("/ip/geo")
async def ip_geo(body: IpRequest, _: None = Depends(verify_api_key)) -> dict:
    """Geolocate an IP address."""
    from osint.modules.ip.geo_lookup import lookup_geo

    try:
        result = await lookup_geo(body.ip)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# IP — ASN
# ---------------------------------------------------------------------------


@app.post("/ip/asn")
async def ip_asn(body: AsnRequest, _: None = Depends(verify_api_key)) -> dict:
    """Look up ASN information for an IP address or AS number."""
    from osint.modules.ip.asn_lookup import lookup_asn

    try:
        result = await lookup_asn(body.ip_or_asn)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# IP — rDNS
# ---------------------------------------------------------------------------


@app.post("/ip/rdns")
async def ip_rdns(body: IpRequest, _: None = Depends(verify_api_key)) -> dict:
    """Perform reverse DNS lookup for an IP address."""
    from osint.modules.ip.rdns_lookup import lookup_rdns

    try:
        result = await lookup_rdns(body.ip)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# IP — reputation
# ---------------------------------------------------------------------------


@app.post("/ip/reputation")
async def ip_reputation(body: IpRequest, _: None = Depends(verify_api_key)) -> dict:
    """Check IP reputation across AbuseIPDB, VirusTotal, OTX, and Shodan."""
    from osint.modules.ip.ip_reputation import check_reputation

    try:
        result = await check_reputation(body.ip)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# IP — port scan  (ACTIVE)
# ---------------------------------------------------------------------------


@app.post("/ip/portscan")
async def ip_portscan(body: PortScanRequest, _: None = Depends(verify_api_key)) -> dict:
    """
    TCP port scan a host.

    This endpoint establishes live TCP connections to the target — it is an
    ACTIVE operation and should only be used with explicit operator consent.

    The ``ports`` field accepts comma-separated ports or ranges, e.g.
    ``"22,80,443"`` or ``"1-1024"``.  Leave empty to use the module default
    (SANS top-20 + common ports).
    """
    from osint.modules.ip.port_scan import scan_ports

    port_list = _parse_ports(body.ports)

    try:
        result = await scan_ports(body.host, ports=port_list)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


@app.get("/jobs/{job_id}")
async def get_job(job_id: str, _: None = Depends(verify_api_key)) -> dict:
    """
    Return the current status (and result when complete) of a background job.

    Status values: "pending" | "running" | "done" | "error"
    """
    job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    return {"job_id": job_id, **job}


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------


def start_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    reload: bool = False,
) -> None:
    """
    Start the uvicorn server.

    Args:
        host:   Bind address.
        port:   Bind port.
        reload: Enable auto-reload (development only — do not use in production).
    """
    uvicorn.run(app, host=host, port=port, reload=reload, log_level="info")
