# osint-tool

A unified, modular OSINT framework for Python. Correlates intelligence across people, domains, IPs, organizations, and social media into a single structured profile — passive by default, graph-native, session-persistent.

---

## What makes it different

- **Passive-first** — zero direct contact with the target unless you pass `--active`
- **Correlation engine** — findings from one module automatically trigger follow-up lookups in others, building a connected entity graph
- **Confidence scoring** — every finding carries a 0–100% confidence rating based on source reliability and cross-source corroboration
- **Session-based investigations** — work persists to SQLite; resume later, diff between runs, track changes over time
- **Operator-grade stealth** — Tor routing, proxy support, randomized headers, human-paced request delays
- **Graph export** — entity relationships export to Gephi, D3.js, Mermaid, or render as ASCII trees in the terminal

---

## Modules at a glance

| Module | What it covers |
|---|---|
| `person` | Email breaches, username search, phone parsing, PGP/Keybase, Gravatar |
| `domain` | WHOIS/RDAP, full DNS, subdomain enumeration, tech fingerprinting, git exposure, Wayback |
| `ip` | Geolocation, ASN/BGP, RPKI, reverse DNS, port scanning, reputation aggregation |
| `social` | Username search across 29 platforms, false-positive elimination, per-platform confidence |
| `org` | Reverse WHOIS, employee enumeration, GitHub org intelligence, job posting analysis |

---

## Installation

### Recommended: pipx

```bash
pipx install osint-tool
```

### pip

```bash
pip install osint-tool
```

### Development install

```bash
git clone https://github.com/your-org/osint-tool.git
cd osint-tool
pip install -e ".[dev]"
```

### Playwright browsers (required for active web scraping)

Only needed if you use `--active` mode or any module that performs headless browser scraping.

```bash
playwright install chromium
```

**Requirements:** Python 3.12+

---

## Quick start

### Check an email address

```bash
osint person email target@example.com
```

Runs breach lookup (HIBP), disposable domain detection, MX validation, and Gravatar lookup. Outputs a structured profile with confidence scores per finding.

### Search a username across platforms

```bash
osint social username johndoe
```

Searches 29 platforms in parallel. Results stream to the terminal via Rich as they arrive. False positives are filtered with multi-signal validation.

```
Platform          Status     Confidence   URL
─────────────────────────────────────────────────────────────
GitHub            Found      94%          https://github.com/johndoe
Reddit            Found      88%          https://reddit.com/u/johndoe
Twitter/X         Found      81%          https://x.com/johndoe
HackerNews        Not found  —
Instagram         Found      76%          https://instagram.com/johndoe
```

### Enumerate a domain

```bash
osint domain dns example.com
osint domain subdomains example.com
```

`dns` runs A, MX, NS, TXT, DMARC, SPF, and DKIM lookups. `subdomains` queries crt.sh and HackerTarget, then optionally brute-forces with a wordlist when `--active` is set.

### Investigate an IP address

```bash
osint ip geo 8.8.8.8
osint ip asn AS15169
osint ip portscan 192.168.1.1 --ports 1-1024
```

`portscan` is always `--active` only and runs async TCP scanning with banner grabbing on open ports.

### Resume a previous session and diff

```bash
osint sessions list
osint sessions resume abc123
osint sessions diff abc123 def456
```

`diff` highlights findings that appeared, disappeared, or changed confidence between two sessions — useful for monitoring targets over time.

### Export a graph

```bash
osint graph --format mermaid
osint graph --format gephi --out investigation.gexf
osint graph --format d3 --out graph.json
```

---

## Configuration

### Config file

Copy the example config and edit it:

```bash
cp config.example.toml ~/.osint/config.toml
```

`~/.osint/config.toml` structure:

```toml
[keys]
hibp_api_key         = ""
shodan_api_key       = ""
censys_api_id        = ""
censys_api_secret    = ""
ipinfo_token         = ""
hunter_api_key       = ""
virustotal_api_key   = ""
abuseipdb_api_key    = ""
securitytrails_key   = ""
alienvault_otx_key   = ""
anthropic_api_key    = ""   # enables AI analysis layer

[network]
tor_proxy            = "socks5h://127.0.0.1:9050"
request_timeout      = 15    # seconds
max_retries          = 3
stealth_delay_min    = 1.5   # seconds between requests in stealth mode
stealth_delay_max    = 4.0

[output]
default_format       = "rich"   # rich | json | plain
session_dir          = "~/.osint/sessions"
graph_dir            = "~/.osint/graphs"
```

### Environment variables

All config values can be set via environment variables prefixed with `OSINT_`. Use double underscores to represent nested keys:

```bash
export OSINT_KEYS__HIBP_API_KEY=your-key-here
export OSINT_KEYS__SHODAN_API_KEY=your-key-here
export OSINT_NETWORK__TOR_PROXY=socks5h://127.0.0.1:9050
```

Environment variables override `config.toml` values.

### Which keys unlock which features

| API key | Free tier | Used by |
|---|---|---|
| HIBP | Yes (rate-limited) | `person email` — breach lookup |
| Shodan | Yes (limited) | `ip` — banner data, open ports |
| Censys | Yes (limited) | `ip` — certificate and service data |
| ipinfo.io | Yes (50k req/mo) | `ip geo` — geolocation |
| Hunter.io | Yes (25 req/mo) | `org` — employee email enumeration |
| VirusTotal | Yes (500 req/day) | `ip`, `domain` — reputation |
| AbuseIPDB | Yes (1000 req/day) | `ip` — abuse reports |
| SecurityTrails | Yes (50 req/mo) | `domain subdomains` — passive DNS |
| AlienVault OTX | Yes | `ip`, `domain` — threat intelligence |
| Anthropic | Yes (trial) | All modules — AI-assisted analysis |

All modules degrade gracefully when keys are missing: they skip the keyed source and note it in the output. No key is required to run the tool.

---

## Module reference

### `person`

```
osint person email EMAIL [OPTIONS]
osint person username USERNAME [OPTIONS]
osint person phone PHONE [OPTIONS]
```

| Subcommand | What it does |
|---|---|
| `email` | HIBP breach lookup, disposable domain check, MX validation, Gravatar fetch |
| `username` | Cross-platform username search (delegates to `social username`), PGP/Keybase lookup |
| `phone` | E.164 parsing, carrier/region lookup, phone reputation check |

Options:

| Flag | Description |
|---|---|
| `--no-breach` | Skip HIBP lookup |
| `--no-gravatar` | Skip Gravatar fetch |
| `--pgp` | Force PGP/Keybase lookup even in passive mode |

---

### `domain`

```
osint domain whois DOMAIN [OPTIONS]
osint domain dns DOMAIN [OPTIONS]
osint domain subdomains DOMAIN [OPTIONS]
osint domain headers URL [OPTIONS]
```

| Subcommand | What it does |
|---|---|
| `whois` | WHOIS + RDAP lookup, registrar, dates, registrant (where not privacy-protected) |
| `dns` | A, AAAA, MX, NS, TXT, CNAME, SOA, DMARC, SPF, DKIM record enumeration |
| `subdomains` | crt.sh + HackerTarget passive enum; brute-force wordlist with `--active` |
| `headers` | HTTP response headers, server tech fingerprinting, git exposure check (`/.git/HEAD`), Wayback availability |

Options:

| Flag | Description |
|---|---|
| `--wordlist PATH` | Custom subdomain wordlist (used with `--active`) |
| `--depth INT` | Subdomain brute-force depth (default: 1) |
| `--wayback` | Fetch Wayback Machine snapshots |
| `--screenshot` | Capture screenshot via headless browser (requires `--active` and Playwright) |

---

### `ip`

```
osint ip geo IP [OPTIONS]
osint ip asn IP_OR_ASN [OPTIONS]
osint ip rdns IP [OPTIONS]
osint ip portscan HOST [OPTIONS]
```

| Subcommand | What it does |
|---|---|
| `geo` | Geolocation from multiple sources (ipinfo.io, ip-api, MaxMind), confidence-averaged |
| `asn` | ASN and BGP info, RPKI validation, prefix list, upstream peers |
| `rdns` | Reverse DNS lookup, forward-confirmed reverse DNS (FCrDNS) check |
| `portscan` | Async TCP port scan with banner grabbing. **Always requires `--active`.** |

Options for `portscan`:

| Flag | Default | Description |
|---|---|---|
| `--ports` | `1-1024` | Port range or comma-separated list |
| `--concurrency` | `200` | Max concurrent connections |
| `--timeout` | `3` | Per-port timeout in seconds |
| `--banner` | `true` | Grab service banners on open ports |

---

### `social`

```
osint social username USERNAME [OPTIONS]
```

Searches 29 platforms. Results stream live. False positives are eliminated using multi-signal checks: HTTP status, response body content, and redirect analysis.

| Flag | Description |
|---|---|
| `--platforms LIST` | Comma-separated platform list (default: all) |
| `--timeout INT` | Per-platform timeout in seconds (default: 10) |
| `--no-stream` | Wait for all results before displaying |

Supported platforms include: GitHub, GitLab, Reddit, Twitter/X, Instagram, TikTok, YouTube, LinkedIn, HackerNews, Keybase, Mastodon, Telegram, Steam, Twitch, Medium, Dev.to, Pastebin, and others. Run `osint social username --list-platforms` for the full current list.

---

### `org`

```
osint org whois DOMAIN [OPTIONS]
osint org employees DOMAIN [OPTIONS]
osint org github ORG_NAME [OPTIONS]
osint org jobs COMPANY_NAME [OPTIONS]
```

| Subcommand | What it does |
|---|---|
| `whois` | Reverse WHOIS — finds other domains registered to the same registrant |
| `employees` | Employee email pattern enumeration via Hunter.io; LinkedIn scraping with `--active` |
| `github` | GitHub org members, public repos, languages, contributor graph |
| `jobs` | Job posting analysis — extracts tech stack signals from job descriptions |

Note: supply chain mapping (`osint org supply-chain`) is listed as coming soon and is not available in the current release.

---

### `sessions`

```
osint sessions list [OPTIONS]
osint sessions resume SESSION_ID [OPTIONS]
osint sessions diff SESSION_ID_1 SESSION_ID_2 [OPTIONS]
```

Sessions are stored as SQLite databases under `~/.osint/sessions/`. Every run creates a session automatically unless `--no-session` is passed.

| Flag | Description |
|---|---|
| `--limit INT` | Number of sessions to list (default: 20) |
| `--format` | `table` or `json` |

---

### `report`

```
osint report [OPTIONS]
```

Generates a structured report from the current or specified session.

| Flag | Description |
|---|---|
| `--session SESSION_ID` | Session to report on (default: most recent) |
| `--format` | `markdown`, `html`, `json`, or `pdf` |
| `--out PATH` | Output file path |
| `--min-confidence INT` | Only include findings at or above this confidence threshold |

---

### `graph`

```
osint graph [OPTIONS]
```

Renders the entity relationship graph for the current or specified session.

| Flag | Description |
|---|---|
| `--session SESSION_ID` | Session to graph (default: most recent) |
| `--format` | `ascii`, `mermaid`, `d3`, `gephi` |
| `--out PATH` | Output file (not needed for `ascii`) |

---

### `watch`

```
osint watch TARGET [OPTIONS]
```

Runs a target on a schedule and diffs each run against the previous. Useful for monitoring domains, IPs, or usernames for changes.

| Flag | Description |
|---|---|
| `--interval` | Cron expression or shorthand (`1h`, `6h`, `daily`) |
| `--notify` | Notification method: `email`, `webhook`, `stdout` |
| `--webhook-url URL` | URL to POST diff payloads to |
| `--min-change INT` | Only notify if confidence delta exceeds this threshold |

---

### `server`

```
osint server [OPTIONS]
```

Starts a FastAPI REST server exposing all modules as HTTP endpoints. Useful for integrating the tool into pipelines or other applications.

| Flag | Default | Description |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `8000` | Port |
| `--reload` | `false` | Auto-reload on code changes (dev mode) |

API reference is served at `http://localhost:8000/docs` (Swagger UI) when the server is running.

---

### `cache`

```
osint cache list [OPTIONS]
osint cache clear [OPTIONS]
```

| Flag | Description |
|---|---|
| `--module` | Filter by module name |
| `--older-than` | Clear entries older than this duration (e.g., `7d`, `24h`) |

---

## Global options

These flags apply to all commands:

| Flag | Description |
|---|---|
| `--config PATH` | Path to config file (default: `~/.osint/config.toml`) |
| `--output-json` | Output all results as JSON regardless of module default |
| `--no-color` | Disable Rich formatting |
| `--verbose` | Show debug-level output including HTTP requests and module decisions |
| `--quiet` | Suppress all output except findings and errors |
| `--active` | Enable active reconnaissance (direct contact with target). Off by default. |
| `--stealth` | Enable human-paced delays and randomized headers |
| `--tor` | Route all requests through Tor (requires local Tor daemon) |
| `--session NAME` | Name the session created for this run |
| `--no-session` | Do not persist this run to a session |
| `--proxy URL` | HTTP/HTTPS/SOCKS proxy URL |

---

## Architecture

### Passive-first model

By default, the tool only queries third-party passive sources (WHOIS APIs, DNS resolvers, breach databases, certificate transparency logs, etc.). It does not connect to target infrastructure. Pass `--active` to permit direct connections: HTTP requests to target domains, TCP port scans, headless browser rendering.

This distinction matters for both legal compliance and operational security. Passive queries leave no trace on the target. Active queries do.

### Correlation engine

Modules communicate through an internal event bus. When a finding is produced — say, an email address found in a WHOIS record — the correlation engine evaluates which other modules have registered interest in that entity type and enqueues follow-up lookups automatically. A domain investigation can therefore surface associated email addresses, which trigger breach lookups, which surface usernames, which trigger social searches — all from a single initial query.

The correlation graph is stored in the session database as a directed entity graph (nodes = entities, edges = how one entity produced another). This is what `osint graph` renders.

### Confidence scoring

Every finding has a confidence score from 0–100 computed from:
1. **Source reliability** — first-party sources (registrar WHOIS) score higher than aggregators
2. **Cross-source corroboration** — a finding confirmed by multiple independent sources gets a confidence boost
3. **Signal strength** — for social lookups, the number and quality of signals (status code, body content, profile metadata) that confirmed the hit

Scores below 40% are flagged as low-confidence and suppressed from reports by default (override with `--min-confidence 0`).

### Session system

Each run creates a session: a SQLite database containing all findings, their confidence scores, provenance (which source produced the finding), and the correlation graph. Sessions are identified by a short hash and an optional human-readable name.

The `diff` subcommand compares two sessions entity-by-entity: new findings, dropped findings, and confidence changes. This makes the tool suitable for ongoing monitoring, not just one-shot investigations.

---

## Contributing

1. Fork the repository and create a feature branch from `main`
2. Install the development dependencies: `pip install -e ".[dev]"`
3. Run the test suite: `pytest`
4. Run the linter: `ruff check . && ruff format --check .`
5. Run type checking: `mypy osint_tool/`
6. Open a pull request against `main` with a clear description of the change

### Adding a module

Each module lives in `osint_tool/modules/<name>/`. A module consists of:
- `commands.py` — Click command definitions
- `runner.py` — async business logic
- `models.py` — Pydantic models for findings
- `sources/` — one file per external source queried

Register new modules in `osint_tool/modules/__init__.py` and add correlation subscriptions in `osint_tool/correlation/registry.py`. See `CONTRIBUTING.md` for the full module development guide.

### Reporting issues

Open an issue with the command you ran (redact any sensitive targets), the full error output with `--verbose`, and your Python and OS versions.

---

## Legal and ethical use

This tool is intended for authorized security research, penetration testing engagements, journalistic investigations, and personal OSINT on yourself.

**You are responsible for how you use it.**

- Do not use this tool against targets you do not have explicit authorization to investigate
- Laws governing OSINT, data collection, and computer access vary by jurisdiction — know the laws that apply to your location and your target's location
- Passive mode queries third-party sources that have their own terms of service; review them before use
- Active mode (`--active`) makes direct network contact with target infrastructure — this is illegal against systems you do not own or have written authorization to test
- Some APIs used by this tool (e.g., HIBP) have their own usage restrictions; your API key use constitutes acceptance of their terms

The authors provide this tool for legitimate use only and accept no liability for misuse. If you find yourself asking whether a particular use is authorized — it probably isn't.

---

## License

MIT — see `LICENSE` for details.
