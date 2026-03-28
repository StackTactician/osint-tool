# OSINT Tool — Feature Specification

## Vision

A unified, modular, passive-first OSINT framework that correlates intelligence across
all target types (people, domains, IPs, orgs, social media) into a single structured
profile. Designed to be the tool professionals actually want to use — fast, accurate,
stealthy, and extensible.

---

## Core Principles

- **Passive-first**: never touch the target directly unless `--active` is explicitly passed
- **Confidence-scored**: every finding carries a 0–100% confidence rating
- **Correlation-driven**: findings feed each other automatically
- **Zero false positives as a goal**: multi-signal verification on every claim
- **Operator-aware**: built-in OPSEC — rate limits, stealth headers, Tor support

---

## Module 1 — Person / Identity

### Standard Features
- Email: syntax validation, MX check, disposable detection, breach lookup (HIBP), paste lookup
- Username: cross-platform search (25+ platforms) with multi-signal verification
- Phone: offline parsing (Google libphonenumber), carrier, region, line type, timezone

### Advanced Features
- **Gravatar hash lookup** — MD5 the email, query Gravatar for a profile photo + linked accounts
- **Email pattern inference** — given a name + domain, guess corporate email format
  (`first.last@`, `flast@`, `firstl@`) and verify with MX ping, not SMTP
- **Password breach analysis** — beyond "was breached": what fields were exposed,
  what hash format was used, cross-breach pattern detection (do passwords share a base word?)
- **Alias graph** — detect when two usernames likely belong to the same person
  (shared bio text, avatar hash, writing style, linked accounts in profile fields)
- **PGP/Keybase lookup** — search public keyservers (keys.openpgp.org, keybase.io)
  for email → identity binding, extract UID metadata
- **Document authorship** — extract authorship metadata from PDFs and Office files
  linked to the target (author field, last-modified-by, revision history)

---

## Module 2 — Domain / Website

### Standard Features
- WHOIS + RDAP with registrant history
- Full DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, DMARC, DKIM, SPF)
- Subdomain enumeration: crt.sh, HackerTarget, brute force
- HTTP headers + tech stack fingerprinting

### Advanced Features
- **DNS zone transfer attempt** — try AXFR against all NS records, safe and passive-legal
- **DMARC / SPF policy analysis** — detect email spoofability, misconfigured policies,
  `~all` vs `-all` vs `+all`
- **Certificate pinning & TLS fingerprinting** — JA3/JA3S hashes, cipher suite analysis,
  certificate chain inspection, SANs extraction (often reveals hidden subdomains)
- **Historical subdomain resurrection** — combine crt.sh history + Wayback CDX API to find
  subdomains that existed in the past but were removed; flag any that resolve again
- **Cloud asset detection** — identify S3 buckets, Azure blobs, GCP storage linked to the domain;
  check for misconfigured public access
- **WAF / CDN fingerprinting** — detect Cloudflare, Akamai, Fastly, AWS CloudFront from
  headers and IP ranges; identify the real origin IP via historical DNS, SecurityTrails, Shodan
- **Git exposure scanner** — check for `/.git/HEAD`, `/.git/config`, `/.svn/entries`,
  `/.env`, `/config.php.bak` and other common sensitive path leaks
- **Favicon hash (Shodan Shodan MMH3)** — hash the favicon, search Shodan for other hosts
  serving the same favicon (reveals related infrastructure even on different IPs)
- **Wayback Machine full crawl** — enumerate all URLs ever indexed for a domain,
  extract emails, API keys, internal paths, old endpoints
- **Google dork automation** — programmatically construct and fire targeted dorks:
  `site:`, `filetype:`, `inurl:`, `intitle:`, `cache:` — parse results without hitting Google
  directly (SerpAPI / SearXNG self-hosted)

---

## Module 3 — IP / Network

### Standard Features
- Geolocation (ip-api, ipwho.is, ipinfo.io)
- ASN / BGP info (BGPView)
- Reverse DNS
- TCP port scan (asyncio)

### Advanced Features
- **Shodan / Censys integration** — pull banner data, open ports, vulnerabilities (CVEs),
  SSL certs, running services — without touching the target directly
- **Network topology mapping** — traceroute + ASN correlation to map the path to the target
  and identify upstream providers, IXPs, transit networks
- **IPv6 enumeration** — AAAA records, IPv6 scan via EUI-64 prediction, DHCPv6 snooping
- **BGP hijack detection** — compare announced prefixes against historical RPKI/ROA data;
  flag route leaks or suspicious origin changes
- **Passive DNS (pDNS)** — query CIRCL pDNS, Farsight DNSDB (free tier) for historical
  resolution data: what domains has this IP served? What IPs has this domain resolved to?
- **IP reputation aggregation** — check against AbuseIPDB, Talos Intelligence, VirusTotal,
  AlienVault OTX, Spamhaus, and aggregate into a single reputation score with source breakdown
- **Autonomous System relationship graph** — map the peering relationships of the target ASN,
  identify upstream providers and potential choke points
- **CDN origin IP discovery** — bypass CDN by checking historical DNS, old certificates,
  direct IPv6 address, mail server IPs, favicon hash on Shodan

---

## Module 4 — Social Media

### Standard Features
- Username search across 25+ platforms
- Multi-signal false-positive elimination

### Advanced Features
- **Social graph extraction** — for public profiles: followers, following, mutual connections,
  reconstruct the target's social network as a graph
- **Post/activity timeline** — aggregate public posts chronologically; detect timezone
  from posting patterns (when do they post?), infer location or work schedule
- **Writing style fingerprinting** — extract linguistic features (vocabulary richness,
  punctuation habits, sentence length distribution, common phrases) for cross-platform
  authorship attribution
- **Image EXIF extraction** — download profile photos and public images, strip EXIF data:
  GPS coordinates, device model, software used, original timestamp
- **Reverse image search automation** — submit profile photos to Google Images, Yandex Images,
  TinEye programmatically; return all matching URLs and pages
- **Avatar perceptual hash** — pHash the profile photo; search for the same photo used on
  other platforms even if cropped, resized, or recompressed
- **Cross-platform correlation** — when a username is found on multiple platforms, automatically
  cross-reference bio text, linked URLs, profile photos, and display names for consistency
  and additional pivot points
- **Deleted content recovery** — check Wayback Machine for cached versions of now-deleted
  profiles or posts

---

## Module 5 — Organization / Company

### Standard Features (new module)
- Company name → associated domains (reverse WHOIS by org name)
- ASN lookup by org name
- LinkedIn presence detection

### Advanced Features
- **Employee enumeration** — discover employee names and emails via:
  - LinkedIn scraping (public profiles)
  - Hunter.io free tier
  - GitHub org member listing
  - Email pattern inference + MX verification
- **GitHub org intelligence** — enumerate public repos, extract contributor emails from
  git history, find secrets in code (API keys, passwords) using regex patterns,
  identify internal tooling and infrastructure clues
- **Job posting analysis** — scrape job listings for the company; extract tech stack clues,
  internal team structure, security tool names, cloud providers used
- **Supply chain mapping** — identify third-party services embedded in the company's web
  properties (analytics, CDN, payment processors, support tools) — each is a potential
  pivot or risk point
- **Leaked credential search** — search public paste sites, DeHashed (free tier), and
  breach compilation indexes for credentials containing the company domain
- **Trademark / patent / legal filing lookup** — USPTO, Companies House, SEC EDGAR —
  extract officer names, addresses, subsidiary relationships

---

## Module 6 — Dark Web / Underground

### Advanced Features
- **Tor hidden service reachability check** — given a .onion address, verify it's live
  (routes through local Tor if available)
- **Paste site monitoring** — Pastebin, Ghostbin, Rentry, PrivateBin — search for
  mentions of a target email, domain, or username
- **Breach compilation indexing** — check local breach compilation databases (if operator
  has them) against target identifiers without uploading data to third parties
- **Dark web mention scan** — via Ahmia.fi (public Tor search engine) search for
  target identifiers across indexed .onion content

---

## Module 7 — Image / Media Intelligence

### Advanced Features
- **EXIF metadata extraction** — GPS, device, timestamp, software (ExifTool wrapper)
- **Steganography detection** — run stegdetect / zsteg against images to flag potential
  hidden data
- **Facial recognition hooks** — integrate with local face recognition library (no cloud);
  flag if the same face appears across different uploaded images
- **Document metadata** — PDF author, creator app, company, revision count; DOCX last-author,
  template path (often reveals internal hostnames or usernames)
- **Video metadata** — ffprobe wrapper: encoding settings, GPS data in MP4 atoms,
  device fingerprint from codec parameters

---

## Cross-Cutting / Platform Features

### Correlation Engine
- Every finding (email, IP, domain, username, org name) is a **node**
- Every module that connects two findings creates an **edge**
- The engine auto-queues follow-up lookups: WHOIS email → person/email,
  WHOIS nameserver → domain/dns, IP from port scan → ip/geo + ip/asn
- Produces a full **entity relationship graph** at session end
- Detectable cycles are flagged (e.g., two personas sharing infrastructure)

### Confidence Scoring System
- Every finding: `{ value, source, confidence: 0-100, timestamp, method }`
- Score factors: data source reliability, corroboration by other sources,
  age of data, active vs passive verification
- Aggregated per-module and per-target profile score

### Unified Target Profile
- `osint profile --target johndoe@example.com` — runs a curated subset of all modules
- Produces a single deduplicated, cross-referenced JSON profile
- Export to: JSON, HTML report, PDF (via WeasyPrint), Markdown

### Caching Layer (SQLite)
- All API responses cached locally with configurable TTL per source type
- `osint cache list` — show cached entries
- `osint cache clear --older-than 7d`
- Cache is transparently consulted before every API call

### Watch Mode / Change Detection
- `osint watch --target example.com --interval 6h --notify webhook`
- Re-runs a saved scan profile on a schedule
- Diffs results against previous run
- Notifications: webhook, email, desktop notification, file append

### Stealth / OPSEC Mode
- `--stealth`: randomize UA per request, inject human-realistic delays,
  randomize request ordering, avoid parallel requests to same host
- `--tor`: route all HTTP through local Tor SOCKS5 proxy
- `--proxy socks5://...`: custom proxy support
- Never sends identifying headers (no `X-Forwarded-For` leakage)
- Option to rotate through a provided proxy list

### Graph Export
- ASCII tree (terminal)
- Mermaid diagram (paste into any markdown renderer)
- Gephi `.gexf` for visual analysis
- JSON nodes+edges for D3.js / Cytoscape / Neo4j import
- `osint graph --session last --format gephi --output graph.gexf`

### Bulk / File Input
- `--input targets.txt` — one target per line, any type (auto-detected)
- Produces combined report with per-target sections
- Respects rate limits across all targets collectively

### REST API Server Mode
- `osint server --port 8080` — exposes every module as a REST endpoint
- Useful for integrating into pipelines, SIEM tools, or a custom frontend
- Returns JSON; supports async job queuing for long-running scans
- Basic token auth

### Interactive TUI
- `osint tui` — full-screen terminal UI (Textual)
- Browse the entity graph interactively
- Drill into findings, queue follow-up queries, view confidence scores
- Export current session from within the TUI

### Plugin System
- Drop a `my_module.py` + `my_module.yaml` into `~/.osint/plugins/`
- Auto-discovered and registered as a new CLI subcommand
- Plugin API exposes: session cache, HTTP client, Rich output helpers, config

### Session Management
- Every run is a named session (auto-named or `--session my-investigation`)
- Sessions are persisted to SQLite: all findings, graph edges, raw API responses
- `osint sessions list` — browse past sessions
- `osint sessions resume <name>` — continue from where you left off
- `osint sessions diff <session1> <session2>` — compare two runs against the same target

### Reporting Engine
- `osint report --session <name> --format html` — generate a full investigation report
- Sections: executive summary, all module findings, entity graph, timeline, confidence scores
- HTML report is self-contained (no external assets)
- PDF via WeasyPrint
- Markdown for paste into wikis/Notion

### Passive-First Architecture
- Default mode: **zero direct contact** with the target
  - No HTTP requests to target domains/IPs
  - No DNS queries for target hostnames
  - Only third-party APIs, public databases, caches
- `--active` flag unlocks: HTTP header fetch, port scan, subdomain brute force, DNS queries
- `--level [passive|semi|active]` for granular control

---

## Module 8 — Geospatial Intelligence

- **IP/EXIF coordinate mapping** — collect every coordinate from EXIF data, IP geolocation,
  and location mentions; plot on an interactive Leaflet.js map embedded in the HTML report
- **Location history reconstruction** — stitch geopoints chronologically; infer home city,
  travel patterns, workplace location from post timestamps + geolocated IPs
- **Check-in / venue correlation** — parse public Foursquare, Swarm, and Google Maps review
  activity to build a physical location history
- **Cell tower / Wi-Fi SSID hints** — extract network names from photo metadata or device
  fingerprints; cross-reference with WiGLE.net for approximate location

---

## Module 9 — Automated Investigation Playbooks

- **YAML-defined playbooks** — define multi-step investigation workflows:
  ```yaml
  name: full-person-profile
  steps:
    - module: person.email
    - module: person.username
      with: "{{ findings.email.username_guess }}"
    - module: social.username
      with: "{{ findings.person.username }}"
    - module: domain.whois
      with: "{{ findings.email.domain }}"
  ```
- **Conditional branching** — steps execute only if prior findings meet a condition
- **Built-in playbook library** — ships with ready-made playbooks:
  `full-person`, `company-recon`, `domain-takeover-check`, `breach-exposure`, `infra-pivot`
- **Playbook output** — each step's findings feed the next; final output is a unified report

---

## Module 10 — AI-Augmented Analysis

- **LLM summary layer** — after any module run, pass structured findings to a local or
  API-connected LLM (Ollama / Claude API) to generate a natural-language summary,
  highlight anomalies, and suggest next pivot steps
- **Natural language query interface** — `osint ask "what is the attack surface of example.com?"`
  — the LLM decomposes the question, runs the relevant modules, and synthesizes the answer
- **Pattern recognition** — LLM flags non-obvious connections: "The breach password matches
  the format of the GitHub commit email's domain — possible password reuse pattern"
- **Hypothesis generation** — given a partial profile, suggest investigative hypotheses and
  the specific queries needed to confirm or rule them out
- **Configurable backends** — Ollama (local, private), Claude API, OpenAI — all optional;
  tool is fully functional without any LLM

---

## Module 11 — Threat Intelligence & Scoring

- **Attack surface score** — for a domain/org: aggregate exposed services, leaked creds,
  misconfigured DNS/email, publicly known CVEs on detected software → single 0–100 risk score
- **STIX 2.1 export** — export all findings as STIX bundles (Indicators, Threat Actors,
  Infrastructure, Relationships) for sharing with MISP or other threat intel platforms
- **MISP integration** — push findings directly to a MISP instance as events + attributes
- **MITRE ATT&CK mapping** — tag discovered infrastructure and techniques against ATT&CK
  framework TTPs; useful for red team / blue team context
- **IOC extraction** — automatically extract and tag IPs, domains, hashes, emails as
  indicators of compromise; export as flat IOC list (CSV, STIX, OpenIOC)

---

## Module 12 — Evidence Preservation

- **Screenshot capture** — headless Playwright screenshots of all discovered web properties,
  timestamped and stored locally for evidence
- **Page archival** — submit discovered URLs to Wayback Machine for archival; store local
  copies as MHTML/PDF
- **Chain of custody log** — every query, response, and finding is logged with:
  timestamp, source URL, HTTP response code, raw response hash (SHA-256)
- **Tamper-evident log** — append-only SQLite journal with per-entry hashes; detectable
  if any historical finding is modified after the fact
- **Export for legal** — produce a structured evidence package (ZIP): screenshots,
  raw responses, chain-of-custody log, signed manifest

---

## Cross-Cutting — Additional Power Features

### Infrastructure Pivot Chain Visualizer
- Starting from any seed (email, domain, IP, username), automatically follow all
  discoverable links: email → domain → IP → ASN → co-hosted domains → their IPs → ...
- Visualize the full pivot chain as an animated graph in the TUI or HTML report
- Set a **pivot depth limit** to control how far the engine recurses

### Cross-Investigation Memory
- The SQLite store spans all sessions; when a new finding matches something from a
  previous investigation, it's automatically flagged: "This IP appeared in session
  `acme-recon` on 2024-11-14"
- Useful for attribution: connecting separate investigations to a common infrastructure

### Behavioral Profiling
- Aggregate all timestamped findings into a behavioral profile:
  - Active hours heatmap (hour-of-day × day-of-week posting frequency)
  - Platform usage preferences and crossover
  - Topic/interest clustering from public post content
  - Writing consistency score across platforms (same person or impersonator?)

### Automated Diff & Change Alerting
- `osint diff --session yesterday --session today` — structured diff of any two sessions
- Highlight: new nodes, removed nodes, changed confidence scores, new edges
- `osint watch` daemon mode runs this diff on schedule and fires configured alerts

### Headless / CI Mode
- `--ci` flag: machine-readable output only (JSON to stdout, exit codes for findings),
  no Rich formatting, suitable for running in GitHub Actions / Jenkins pipelines
- Exit codes: `0` = clean, `1` = findings below threshold, `2` = high-risk findings

### Self-Updating Platform Definitions
- `osint update-platforms` — fetches latest `platforms.json` from a community-maintained
  registry (similar to how Sherlock maintains its sites list)
- Platforms are versioned; tool logs when a platform definition changes

---

## Technology Stack

| Layer | Choice |
|---|---|
| CLI | Click 8.x |
| Terminal UI | Rich 13.x + Textual |
| Async HTTP | aiohttp + asyncio |
| Sync HTTP | httpx |
| DNS | dnspython (async resolver) |
| Database/Cache | SQLite via aiosqlite |
| Graph | networkx (analysis) + custom exporters |
| Config | tomllib (stdlib) + env vars |
| Reports | Jinja2 (HTML) + WeasyPrint (PDF) |
| Plugins | importlib.metadata entry points |
| Packaging | pyproject.toml + pip |

---

## Planned Integrations (Optional API Keys)

| Service | What it adds | Free tier |
|---|---|---|
| HIBP | Email breach data | Yes (free key) |
| Shodan | Banner data, CVEs, favicon search | Yes (limited) |
| Censys | Certificate + host data | Yes (250 req/month) |
| ipinfo.io | Enhanced IP data | Yes (50k/month) |
| Hunter.io | Email enumeration | Yes (25 searches/month) |
| DeHashed | Breach credential search | Paid only |
| VirusTotal | URL/IP/domain reputation | Yes (4 req/min) |
| AbuseIPDB | IP reputation | Yes (1000 req/day) |
| SecurityTrails | DNS/WHOIS history | Yes (50 req/month) |
| Farsight DNSDB | Passive DNS | Free research access |
| AlienVault OTX | Threat intelligence | Yes |
| Numverify | Phone enrichment | Yes (100 req/month) |

All integrations degrade gracefully when no key is configured.

---

## What Makes This Different

1. **No false positives by design** — multi-signal, scored, corroborated
2. **Correlation-first** — findings connect and multiply automatically
3. **Passive by default** — legal and safe out of the box
4. **Session-based** — investigations persist, resume, diff
5. **Graph-native** — entity relationships are first-class, not an afterthought
6. **Operator-grade stealth** — Tor, proxy rotation, timing randomization built in
7. **Full-stack reports** — from raw JSON to polished PDF in one command
8. **Extensible** — drop a file to add a module, no fork required
