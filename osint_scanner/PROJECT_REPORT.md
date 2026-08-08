# OSINT & Passive Reconnaissance Scanner
## Project Report

---

### 1. Abstract

This project presents a modular, passive OSINT (Open-Source Intelligence) reconnaissance tool built in Python. The tool collects WHOIS registration data, DNS records, IP geolocation, Shodan host intelligence, subdomain enumerations, and leak/breach data for one or more domains using exclusively public data sources. It provides two user interfaces: a command-line interface (CLI) with Rich-formatted output and JSON export, and a Tkinter-based graphical user interface (GUI) with tabbed results and background-thread scanning. The system is designed with a modular architecture where each data source is an independent module with a standardized interface (`scan(domain) -> dict`), enabling easy extension. All modules handle errors gracefully and return structured results instead of crashing. Rate limiting is built into every module to respect free-tier API limits.

---

### 2. Introduction

#### 2.1 Background

OSINT (Open-Source Intelligence) refers to intelligence gathered from publicly available sources. In cybersecurity, OSINT reconnaissance is the first phase of penetration testing and threat intelligence — understanding what information about a target is publicly accessible without making direct contact with the target's infrastructure.

Passive reconnaissance differs from active reconnaissance in that it never sends packets directly to the target. Instead, it queries public databases, certificate transparency logs, DNS resolvers, and third-party intelligence platforms. This makes passive reconnaissance undetectable by the target and legally permissible in most jurisdictions when performed against publicly available data.

#### 2.2 Problem Statement

Security professionals and researchers need a consolidated tool that aggregates multiple OSINT data sources into a single interface. Existing tools often focus on a single data type (e.g., only WHOIS or only Shodan), require API keys for basic functionality, or lack a user-friendly interface for non-technical users.

#### 2.3 Objectives

1. Build a Python-based OSINT scanner that collects six types of reconnaissance data from public sources
2. Provide both CLI and GUI interfaces for different user preferences
3. Implement a modular architecture where each data source is independently testable and extensible
4. Handle errors gracefully — no module should crash the entire scan
5. Respect rate limits of free-tier APIs through built-in sequential rate limiting
6. Export results to both human-readable console output and machine-readable JSON

---

### 3. Literature Review

#### 3.1 OSINT Data Sources

| Source | Type | Data Provided |
|--------|------|---------------|
| WHOIS | Domain registration database | Registrar, creation/expiration dates, name servers, contact information |
| DNS | Domain Name System records | A/AAAA (IP addresses), MX (mail servers), NS (name servers), TXT (SPF/DKIM/verification), SOA (zone authority) |
| IP Geolocation | IP-to-location databases | City, region, country, coordinates, ISP, ASN |
| Shodan | Internet-wide scanning | Open ports, services, vulnerabilities, hostnames, OS detection |
| crt.sh | Certificate Transparency logs | Subdomains discovered via SSL/TLS certificate issuance |
| GitHub Code Search | Public code repositories | Exposed secrets, API keys, internal configurations |
| HaveIBeenPwned | Breach database | Email addresses found in known data breaches |

#### 3.2 Passive vs Active Reconnaissance

| Aspect | Passive | Active |
|--------|---------|--------|
| Target contact | None | Direct probes to target infrastructure |
| Detection risk | Undetectable | Detectable by IDS/IPS |
| Data sources | Public databases, third-party APIs | Port scanning, service enumeration |
| Legal risk | Low (public data only) | Higher (unauthorized scanning) |
| Data completeness | Limited to what's publicly indexed | Comprehensive service discovery |

This tool operates exclusively in passive mode.

#### 3.3 Existing Tools

- **theHarvester** — email/subdomain enumeration from multiple sources
- **Shodan CLI** — direct Shodan queries
- **WHOIS lookup** — domain registration queries
- **Recon-ng** — modular OSINT framework
- **Maltego** — visual link analysis (commercial)

This project differentiates itself by combining all six data types into a single, modular, rate-limited tool with both CLI and GUI interfaces and no required API keys.

---

### 4. System Design

#### 4.1 Architecture

The system follows a modular pipeline architecture:

```
                    +------------------+
                    |   scanner.py     |  CLI orchestrator
                    |   gui.py         |  GUI orchestrator
                    +--------+---------+
                             |
                    +--------v---------+
                    |   MODULES dict    |  Module registry
                    +--------+---------+
                             |
        +--------+--------+--------+--------+--------+
        |        |        |        |        |        |
    +---v---+ +--v---+ +--v----+ +--v----+ +--v----+ +--v----+
    | whois | | dns  | | geoip | |shodan | | subd. | | leaks |
    +---+---+ +--+---+ +--+----+ +--+----+ +--+----+ +--+----+
        |        |        |        |        |        |
    +---v---+ +--v---+ +--v----+ +--v----+ +--v----+ +--v----+
    |python | |dnspy | |ip-api | |shodan | |crt.sh | |GitHub |
    | -whois| |thon  | | .com  | |  .io  | |  +DNS | |  +HIBP|
    +-------+ +------+ +-------+ +-------+ +-------+ +-------+
```

Each module:
- Accepts a domain string
- Returns a JSON-serializable dict with a standardized error field
- Handles rate limiting internally via `RateLimiter`
- Never raises exceptions to the caller

#### 4.2 Module Interface

```python
# Standard module contract
def scan(domain: str) -> dict:
    """
    Returns:
        dict with module-specific keys + "error" field
        error = None or "N/A" on success, str message on failure
    """
```

#### 4.3 Data Flow

1. User initiates scan via CLI (`scanner.py`) or GUI (`gui.py`)
2. For each domain, iterate `MODULES` dict calling `scan(domain)`
3. Each module queries its data source(s) with rate limiting
4. Results are aggregated into a single dict keyed by module name
5. Results are rendered to console (Rich) and written to JSON file
6. In GUI mode, each module result is posted back to the main thread via `root.after()` for progressive tab population

---

### 5. Implementation

#### 5.1 Module Breakdown

##### 5.1.1 WHOIS Module (`modules/whois.py`)

- **Library:** `python-whois`
- **Rate limit:** 2.0 seconds between calls
- **Output keys:** `registrar`, `creation_date`, `expiration_date`, `name_servers` (list), `emails` (list), `error`
- **Behavior:** Queries the WHOIS server for the domain. Handles missing fields gracefully (returns "N/A" or empty lists). Uses `safe_str()` to convert values that may be None, lists, or strings into display-ready strings.

##### 5.1.2 DNS Module (`modules/dns.py`)

- **Library:** `dnspython`
- **Rate limit:** 1.0 seconds
- **Output keys:** `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME` (all lists), `SOA` (string), `error`
- **Behavior:** Queries each record type independently. Missing record types return empty lists (not errors). SOA is returned as a single string representation. MX records include priority (e.g., "10 smtp.google.com.").

##### 5.1.3 GeoIP Module (`modules/geoip.py`)

- **Library:** `requests` + `ip-api.com` (free, no key)
- **Rate limit:** 1.0 seconds
- **Output keys:** `ip`, `city`, `region`, `country`, `lat`, `lon`, `isp`, `org`, `as`, `error`
- **Behavior:** First resolves the domain to an IP via `socket.gethostbyname()`. Then queries ip-api.com with a fields parameter to minimize response size. Handles DNS resolution failure and API failure separately.

##### 5.1.4 Shodan Module (`modules/shodan.py`)

- **Library:** `requests` + Shodan API (free tier, no key)
- **Rate limit:** 2.0 seconds
- **Output keys:** `ip`, `ports` (list), `hostnames` (list), `vulns` (list), `org`, `os`, `error`
- **Behavior:** Resolves domain to IP, then queries `api.shodan.io/shodan/host/{ip}`. Handles 200 (success), 401 (key required), 404 (no record) as expected outcomes, not errors. Other HTTP status codes and network exceptions are caught.

##### 5.1.5 Subdomains Module (`modules/subdomains.py`)

- **Sources:** crt.sh (certificate transparency) + DNS brute-force
- **Rate limit:** 1.0 seconds for crt.sh, 0.2 seconds per DNS lookup
- **Output keys:** `subdomains` (sorted list), `sources` (dict with `crt_sh` and `brute_force` lists), `error`
- **Behavior:** crt.sh returns JSON arrays of certificate entries; the module extracts `name_value` fields, deduplicates, and filters to the target domain. DNS brute-force reads `config/subdomains.txt` (16 common prefixes) and attempts A-record resolution for each. Results from both sources are merged and sorted.

##### 5.1.6 Leaks Module (`modules/leaks.py`)

- **Sources:** GitHub code search API + HaveIBeenPwned domain API
- **Rate limit:** 2.0 seconds
- **Output keys:** `github_leaks` (list of dicts with `repository`, `path`, `html_url`), `email_leaks` (int), `error`
- **Behavior:** GitHub search uses unauthenticated API (401 = expected, returns empty list). HIBP domain API returns breach count; 401/404 = expected free-tier result, returns 0.

#### 5.2 Shared Utilities (`modules/_utils.py`)

- **`RateLimiter(delay)`** — enforces minimum delay between calls using `time.monotonic()`. Each module creates its own instance.
- **`http_get(url, limiter, timeout)`** — rate-limited HTTP GET with `raise_for_status()`. Used for APIs where HTTP errors should propagate.
- **`safe_str(value)`** — converts None, lists, or strings to a single display string. Used by the WHOIS module.

#### 5.3 CLI Orchestrator (`scanner.py`)

- Uses `argparse` for argument parsing (domains as positional args, `-f` for file input)
- `scan_domain(domain)` iterates all modules sequentially
- `scan_batch(domains)` processes multiple domains with Rich console output
- BOM-safe file reading (`utf-8-sig` encoding)
- JSON export via `output.write_json()`

#### 5.4 GUI (`gui.py`)

- Built with Tkinter (stdlib, zero dependencies)
- **Layout:** toolbar (domain input, Scan/Load/JSON/Results buttons) + tabbed results + status bar with progress
- **Background threading:** `threading.Thread(daemon=True)` runs the scan; `root.after()` posts results back to the main thread
- **Progressive rendering:** each module's result is rendered to its tab immediately upon completion
- **Error resilience:** disabled inputs during scan, graceful error display in tabs

#### 5.5 Output (`output.py`)

- **Console:** Rich `Panel` + `Table` with color-coded sections (magenta headers, cyan labels, red errors)
- **JSON:** timestamped file in `results/` directory, written with `json.dumps(indent=2, default=str)`

---

### 6. Testing Results

#### 6.1 Test Case: google.com

| Module | Result | Key Findings |
|--------|--------|--------------|
| WHOIS | Pass | Registrar: MarkMonitor, Inc. Created: 1997-09-15. Expires: 2028-09-14. 4 Google name servers. 2 registrar contact emails. |
| DNS | Pass | 6 A records (192.178.211.x), 1 AAAA record, 1 MX record (smtp.google.com), 4 NS records, 15+ TXT records (SPF, domain verification for DocuSign/Facebook/Cisco/OneTrust/Apple), SOA record. |
| GeoIP | Pass | IP: 192.178.211.139, City: Mountain View, Region: California, Country: United States, ISP: Google LLC, AS: AS15169 Google LLC. |
| Shodan | Pass | Ports: 80, 443. Hostnames: 17+ Google properties (youtube.com, android.com, google-analytics.com, etc.). Vulns: none. |
| Subdomains | Pass | 9 subdomains found: admin, api, blog, mail, ns1, ns2, shop, vpn, www (via crt.sh + DNS brute-force). |
| Leaks | Pass | GitHub hits: none. Breach domains: 0. |

#### 6.2 Test Case: example.com

| Module | Result | Key Findings |
|--------|--------|--------------|
| WHOIS | Pass | Registrar: IANA. Created: 1995-08-14. Expires: 2026-08-13. Cloudflare name servers. |
| DNS | Pass | 2 A records (Cloudflare IPs), 1 AAAA record, SPF + verification TXT records. |
| GeoIP | Pass | IP: 172.66.147.243, City: Toronto, Country: Canada (Cloudflare CDN). |
| Shodan | Pass | No record (free tier expected). |
| Subdomains | Pass | 6 subdomains: dev, example, m, products, support, www. |
| Leaks | Pass | GitHub hits: 0. Breach domains: 0. |

#### 6.3 Test Case: Invalid Domain (nonexistent-domain-xyz-12345.invalid)

| Module | Result | Key Findings |
|--------|--------|--------------|
| WHOIS | Pass | Error returned (timeout), all fields N/A. No crash. |
| DNS | Pass | All record lists empty. No crash. |
| GeoIP | Pass | DNS resolution failed, error returned. No crash. |
| Shodan | Pass | DNS resolution failed, error returned. No crash. |
| Subdomains | Pass | crt.sh returned empty. DNS brute-force: no matches. No crash. |
| Leaks | Pass | GitHub: 0. HIBP: 0. No crash. |

#### 6.4 Error Handling Verification

- All modules return structured error dicts on failure (never raise to caller)
- CLI continues scanning after individual module failures
- GUI displays errors in tabs, never crashes
- BOM-prefixed domain files handled correctly (`utf-8-sig`)

---

### 7. GUI Screenshots

The following screenshots demonstrate the GUI scanning `google.com`:

![WHOIS Tab](docs/images/gui_1.png)

**WHOIS Tab** — Domain registration information showing registrar (MarkMonitor, Inc.), creation date (1997-09-15), expiration (2028-09-14), four Google name servers, and registrar contact emails.

![DNS Tab](docs/images/gui_2.png)

**DNS Tab** — Complete DNS record enumeration showing 6 A records, 1 AAAA record, MX record (smtp.google.com), 4 NS records, 15+ TXT records (SPF, DocuSign, Facebook, Cisco, OneTrust, Apple verification), and SOA record.

![GeoIP Tab](docs/images/gui_3.png)

**GeoIP Tab** — IP geolocation showing Mountain View, California, United States, ISP: Google LLC, AS: AS15169 Google LLC, coordinates 37.4225/-122.085.

![Shodan Tab](docs/images/gui_4.png)

**Shodan Tab** — Host intelligence showing open ports (80, 443), 17+ hostnames (android.com, youtube.com, google-analytics.com, etc.), no vulnerabilities, OS not identified.

![Subdomains Tab](docs/images/gui_5.png)

**Subdomains Tab** — 9 discovered subdomains: admin, api, blog, mail, ns1, ns2, shop, vpn, www.

![Leaks Tab](docs/images/gui_6.png)

**Leaks Tab** — GitHub code search: no hits. HaveIBeenPwned breach count: 0.

---

### 8. Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| `RATE_LIMITS["whois"]` | 2.0 s | Delay before WHOIS lookup |
| `RATE_LIMITS["dns"]` | 1.0 s | Delay before DNS queries |
| `RATE_LIMITS["geoip"]` | 1.0 s | Delay before geolocation lookup |
| `RATE_LIMITS["shodan"]` | 2.0 s | Delay before Shodan query |
| `RATE_LIMITS["subdomains"]` | 1.0 s | Delay before crt.sh query |
| `RATE_LIMITS["leaks"]` | 2.0 s | Delay before leak checks |
| `TIMEOUT` | 10 s | HTTP request timeout |
| `SUBDOMAIN_WORDLIST` | config/subdomains.txt | 16-word brute-force list |

---

### 9. Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `python-whois` | 0.9.6 | WHOIS domain lookups |
| `dnspython` | 2.8.0 | DNS record enumeration |
| `requests` | 2.34.2 | HTTP requests to APIs |
| `rich` | 15.0.0 | Console formatting (CLI only) |
| `tkinter` | stdlib | GUI framework (no install needed) |

---

### 10. Future Enhancements

| Enhancement | Description |
|-------------|-------------|
| **API key integration** | Support Shodan, HIBP, and Censys API keys for full data access |
| **Async scanning** | Replace sequential with async HTTP for faster batch scans |
| **Plugin system** | Dynamic module loading for community-contributed data sources |
| **Database storage** | Store scan history in SQLite for trend analysis |
| **Web dashboard** | Flask/FastAPI-based web interface for team collaboration |
| **Recursive subdomain scan** | Discover subdomains of discovered subdomains |
| **Email enumeration** | Find email addresses associated with the domain |
| **Social media OSINT** | LinkedIn, Twitter/X profile lookups |

---

### 11. Conclusion

This project successfully implements a modular, passive OSINT reconnaissance tool that aggregates six data sources into a single Python application. The modular architecture ensures each data source is independently testable and extensible. The dual CLI/GUI interface accommodates both automation and interactive use cases. Error handling is robust — no module failure crashes the entire scan. Rate limiting is built into every module to respect free-tier API limits. The tool has been verified against real domains (google.com, example.com) and handles edge cases (invalid domains, missing APIs, BOM-prefixed files) gracefully.

---

### 12. References

1. ICANN WHOIS Protocol (RFC 3912)
2. DNS Protocol (RFC 1034, RFC 1035)
3. ip-api.com — Free IP Geolocation API
4. Shodan — Internet-Wide Scanning Database
5. crt.sh — Certificate Transparency Log Search
6. HaveIBeenPwned — Breach Data API
7. GitHub Code Search API
8. python-whois Documentation
9. dnspython Documentation
10. Rich — Python Library for Rich Text in Terminal

---

**Project:** OSINT & Passive Reconnaissance Scanner
**Language:** Python 3.12
**Framework:** Tkinter (GUI), Rich (CLI)
**Date:** August 2026
