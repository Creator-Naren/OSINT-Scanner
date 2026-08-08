# OSINT Scanner

A modular, passive OSINT (Open-Source Intelligence) reconnaissance tool written in Python. It collects WHOIS, DNS, IP geolocation, Shodan, subdomain, and leak data for one or more domains — entirely from public data sources, with no direct contact with the target.

## Features

- **WHOIS lookup** — registrar, creation/expiration dates, name servers, contact emails (`python-whois`)
- **DNS enumeration** — A, AAAA, MX, NS, TXT, CNAME, and SOA records (`dnspython`)
- **IP geolocation** — IP, city, region, country, coordinates, ISP, and ASN via `ip-api.com`
- **Shodan host lookup** — open ports, hostnames, CVEs, and OS from Shodan's index (free tier)
- **Subdomain enumeration** — certificate transparency logs (`crt.sh`) plus DNS brute-force from a wordlist
- **Leak checking** — GitHub code search and HaveIBeenPwned domain breach count
- **Two interfaces**
  - **CLI** — batch scan with Rich-formatted console tables and JSON export
  - **GUI** — Tkinter desktop app with per-source tabs, background-thread scanning, and progress feedback
- **Resilient** — every module fails gracefully (returns an `error` field instead of crashing); invalid domains and offline APIs are handled
- **Rate-limited** — sequential requests with configurable delays to respect free-tier API limits

---

## Project Structure

```
osint_scanner/
├── scanner.py          # CLI entry point + batch orchestrator
├── gui.py              # Tkinter desktop GUI (python -m osint_scanner.gui)
├── output.py           # Rich console rendering + JSON export
├── config.py           # Rate limits, timeouts, paths
├── modules/
│   ├── __init__.py     # Module registry (MODULES dict) + run_module()
│   ├── _utils.py       # RateLimiter, http_get, safe_str helpers
│   ├── whois.py        # WHOIS lookup
│   ├── dns.py          # DNS record enumeration
│   ├── geoip.py        # IP resolution + geolocation
│   ├── shodan.py       # Shodan host lookup (free tier)
│   ├── subdomains.py   # crt.sh + DNS brute-force enumeration
│   └── leaks.py        # GitHub code search + HIBP breach count
├── config/
│   └── subdomains.txt  # Wordlist for DNS brute-force
└── results/            # JSON scan reports (created automatically)
```

---

## Installation

Requires **Python 3.10+**.

```bash
pip install python-whois dnspython requests rich
```

The GUI uses **Tkinter**, which ships with the standard Python installer on Windows and macOS. On Linux it is often packaged separately:

```bash
# Debian / Ubuntu
sudo apt install python3-tk
```

---

## Usage

### CLI

```bash
# Scan one domain
python -m osint_scanner.scanner example.com

# Scan multiple domains
python -m osint_scanner.scanner example.com google.com github.com

# Scan a list of domains from a file (one per line)
python -m osint_scanner.scanner -f domains.txt
```

Sample output:

```
------------------------- Scanning example.com (1/1) --------------------------
+-------------------------------- example.com --------------------------------+
|  WHOIS                                                                      |
|  Registrar         RESERVED-Internet Assigned Numbers Authority             |
|  Created           1995-08-14 04:00:00+00:00                                |
|  Expires           2026-08-13 04:00:00+00:00                                |
|  DNS                                                                        |
|  A                 104.20.23.154, 172.66.147.243                            |
|  NS                elliott.ns.cloudflare.com., hera.ns.cloudflare.com.      |
|  ...
+-----------------------------------------------------------------------------+

Results written to: ...\osint_scanner\results\osint_20260808T075906.555920+0000.json
```

### GUI

```bash
python -m osint_scanner.gui
```

Enter a domain (or comma-separated list) and press **Scan**. **Load file** reads a `.txt` list of domains. Results appear in six tabs (WHOIS, DNS, GeoIP, Shodan, Subdomains, Leaks) and populate progressively while the scan runs in a background thread. **Open JSON** opens the exported report; **Results folder** opens `results/` in Explorer.

---

## GUI Tab Reference (google.com scan)

The following screenshots demonstrate a real scan of `google.com` across all six data-source tabs.

### Tab 1 — WHOIS

![WHOIS Tab](docs/images/gui_1.png)

The WHOIS tab displays domain registration information retrieved from the IANA WHOIS database:

| Field         | Meaning |
|---------------|---------|
| **Registrar** | The ICANN-accredited registrar managing the domain. For google.com this is **MarkMonitor, Inc.**, a registrar commonly used by large enterprises for brand protection. |
| **Created** | The domain's original registration date. google.com was first registered on **1997-09-15**, making it one of the older domains on the internet. |
| **Expires** | When the current registration period ends. google.com expires **2028-09-14** — large registrants typically pre-renew for many years. |
| **Name servers** | The authoritative DNS servers for the domain. google.com uses four Google-managed name servers: NS1 through NS4.GOOGLE.COM. |
| **Emails** | Contact emails visible in the WHOIS record. For large domains these are typically privacy-protected registrar contacts (e.g. `abusecomplaints@markmonitor.com`). |

**What this reveals:** Domain age, registration authority, and the fact that Google manages its own name servers rather than using a third-party DNS provider.

---

### Tab 2 — DNS

![DNS Tab](docs/images/gui_2.png)

The DNS tab enumerates all standard record types for the domain, providing a detailed map of the domain's infrastructure:

| Record | Sample Output | Meaning |
|--------|---------------|---------|
| **A** | `192.178.211.100`, `192.178.211.138`, ... | IPv4 addresses pointing to Google's load-balanced frontend servers. Multiple A records indicate a large, distributed infrastructure. |
| **AAAA** | `2404:6800:4009:806::200e` | IPv6 address for the domain, indicating IPv6 support. |
| **MX** | `10 smtp.google.com.` | Mail server handling inbound email. The `10` is the priority (lower = preferred). Google runs its own SMTP infrastructure. |
| **NS** | `ns1.google.com.`, `ns2.google.com.`, `ns3.google.com.`, `ns4.google.com.` | Authoritative name servers — matches the WHOIS result and confirms Google self-hosts DNS. |
| **TXT** | `v=spf1 include:_spf.google.com ~all`, `google-site-verification=...`, `docusign=...` | Text records used for SPF email authentication, domain verification for third-party services (DocuSign, Facebook, Cisco, OneTrust, Apple, GlobalSign), and Microsoft 365 integration (`MS=E4A6...`). |
| **CNAME** | `none` | No canonical name alias — google.com resolves directly via A records, which is expected for a root domain of this scale. |
| **SOA** | `ns1.google.com. dns-admin.google.com. 960819459 ...` | Start of Authority record containing the primary name server (`ns1`), admin contact (`dns-admin@google.com`), serial number, and refresh/expire timers for zone transfers. |

**What this reveals:** The TXT records expose third-party service integrations (DocuSign, Facebook domain verification, Cisco, OneTrust, Apple). The SPF record confirms Google handles its own email. The SOA serial number (`960819459`) can indicate zone update frequency.

---

### Tab 3 — GeoIP

![GeoIP Tab](docs/images/gui_3.png)

The GeoIP tab resolves the domain to an IP address and performs geographic and organizational lookup via ip-api.com:

| Field       | Value |
|-------------|-------|
| **IP**      | `192.178.211.139` — the resolved IPv4 address (one of the A records returned by DNS). |
| **City**    | `Mountain View` — the city where this particular server is located. |
| **Region**  | `California` — the US state. |
| **Country** | `United States` — the country. |
| **ISP**     | `Google LLC` — the Internet Service Provider, confirming the server is owned by Google. |
| **AS**      | `AS15169 Google LLC` — the Autonomous System number, which is the BGP routing identity for Google's network. AS15169 is one of the largest autonomous systems on the internet. |
| **Latitude**  | `37.4225` — approximate server location (Google's Mountain View campus). |
| **Longitude** | `-122.085` — approximate server location. |

**What this reveals:** The IP belongs to Google's own ASN (AS15169), confirming the domain resolves to Google's infrastructure rather than a CDN or third-party hosting provider. The geographic coordinates place the server at Google's headquarters campus.

---

### Tab 4 — Shodan

![Shodan Tab](docs/images/gui_4.png)

The Shodan tab queries the Shodan internet-wide scanning database for information about the resolved IP address:

| Field        | Sample Output | Meaning |
|--------------|---------------|---------|
| **Ports**    | `80`, `443` | Open ports detected by Shodan's scanners. Port 80 (HTTP) and 443 (HTTPS) are the standard web ports — expected for a major website. |
| **Hostnames**| `android.com`, `music.youtube.com`, `ai.android`, `youtube.com`, `google.com`, `youtu.be`, `youtubekids.com`, `urchin.com`, `google-analytics.com`, `googlecommerce.com`, `yt.be`, `www.goo.gl`, `g.co`, `goo.gl`, `youtubeeducation.com`, `alt55.adwords.l.google.com`, ... | Other domains that share this IP address. This reveals that Google hosts many services on shared infrastructure — YouTube, Android, Google Analytics, AdWords, and URL shorteners all resolve to overlapping IP ranges. |
| **Vulns**    | `none` | No known CVEs or vulnerabilities detected on this IP. |
| **OS**       | `N/A` | Operating system not identified — typical for large CDNs and load balancers that obscure the underlying OS. |

**What this reveals:** The IP hosts a large number of Google's properties (YouTube, Android, Google Analytics, AdWords, URL shorteners). The shared IP hosting indicates Google's infrastructure is heavily load-balanced. No vulnerabilities were found on this particular IP.

---

### Tab 5 — Subdomains

![Subdomains Tab](docs/images/gui_5.png)

The Subdomains tab discovers subdomains using two methods: **crt.sh** (certificate transparency logs) and **DNS brute-force** (resolving common subdomain prefixes):

```
Found subdomains:
admin.google.com
api.google.com
blog.google.com
mail.google.com
ns1.google.com
ns2.google.com
shop.google.com
vpn.google.com
www.google.com
```

| Method | How It Works |
|--------|--------------|
| **crt.sh** | Queries the certificate transparency log for SSL/TLS certificates issued for `*.google.com`. Every public certificate is logged, so this passively reveals subdomains that have HTTPS enabled. |
| **DNS brute-force** | Attempts to resolve a list of common prefixes (www, mail, admin, api, blog, shop, vpn, etc.) against the domain. If DNS returns an A record, the subdomain exists. |

**What this reveals:** The discovered subdomains map to Google's internal services — `admin` (Google Admin), `api` (API endpoints), `blog` (official blog), `mail` (Gmail), `ns1`/`ns2` (name servers), `shop` (Google Store), `vpn` (corporate VPN), `www` (main website). This is a small subset; the actual list of Google subdomains is vastly larger.

---

### Tab 6 — Leaks

![Leaks Tab](docs/images/gui_6.png)

The Leaks tab checks for publicly exposed credentials and breach data associated with the domain:

| Field              | Value | Meaning |
|--------------------|-------|---------|
| **GitHub hits**    | `none` | No results from GitHub code search for `domain:google.com`. This means no publicly visible GitHub repositories contain code or secrets referencing google.com (or the unauthenticated API returned no results due to rate limits). |
| **Breach domains** | `0` | Zero breach records from HaveIBeenPwned's domain API. This checks whether email addresses under `@google.com` have appeared in known data breaches. A result of 0 may indicate either no breaches or that the HIBP domain API requires an API key (the free tier returns limited data). |

**What this reveals:** No publicly exposed GitHub leaks or breach data were found. For security assessments, a paid HIBP API key would provide more comprehensive breach data.

---

## Module Interface

Every data-source module exposes the same contract:

```python
scan(domain: str) -> dict
```

Returns a JSON-serializable dict. On failure, each module returns its normal shape with an `error` field populated instead of raising.

| Module      | Keys                                                        |
|-------------|-------------------------------------------------------------|
| `whois`     | `registrar`, `creation_date`, `expiration_date`, `name_servers`, `emails`, `error` |
| `dns`       | `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME` (lists), `SOA` (str), `error` |
| `geoip`     | `ip`, `city`, `region`, `country`, `lat`, `lon`, `isp`, `org`, `as`, `error` |
| `shodan`    | `ip`, `ports`, `hostnames`, `vulns`, `org`, `os`, `error`  |
| `subdomains`| `subdomains`, `sources` (`crt_sh`, `brute_force`), `error`  |
| `leaks`     | `github_leaks` (list of `{repository, path, html_url}`), `email_leaks` (int), `error` |

### Using modules programmatically

```python
from osint_scanner.modules import MODULES, run_module

whois_result = run_module("whois", "example.com")        # single module
all_modules = {name: scan("example.com") for name, scan in MODULES.items()}
```

### Extending

Add a new source by creating `modules/yourmodule.py` with a `scan(domain) -> dict` function, then registering it in the `MODULES` dict in `modules/__init__.py`. It will automatically be picked up by the CLI, GUI, and JSON export.

---

## Configuration

All settings live in `config.py`:

| Setting                | Default | Purpose                                 |
|------------------------|---------|-----------------------------------------|
| `RATE_LIMITS`          | 1–2 s   | Min delay between requests per module   |
| `TIMEOUT`              | 10 s    | HTTP request timeout                    |
| `SUBDOMAIN_WORDLIST`   | `config/subdomains.txt` | Words used for brute-force |
| `OUTPUT_DIR`           | `results/` | Where JSON reports are written        |

---

## Output Format

JSON reports are written to `results/osint_<timestamp>.json`:

```json
{
  "scan_timestamp": "2026-08-08T12:00:00+00:00",
  "domains": [
    {
      "domain": "example.com",
      "whois": { "registrar": "...", "error": "N/A" },
      "dns": { "A": ["1.2.3.4"], "error": null },
      "geoip": { "ip": "1.2.3.4", "city": "...", "error": "N/A" },
      "shodan": { "ports": [], "error": "no Shodan record (free tier)" },
      "subdomains": { "subdomains": ["www.example.com"], "error": null },
      "leaks": { "github_leaks": [], "email_leaks": 0, "error": null }
    }
  ]
}
```

---

## Notes on Free-Tier Sources

- **Shodan** requires an API key for full data. On the free tier the module returns `error: "Shodan API key required"` or `"no Shodan record (free tier)"`.
- **GitHub code search** and **HIBP** APIs require authentication for full results. Without a key they return empty results (`[]` / `0`), which is expected, not an error.
- **ip-api.com** free tier is limited to 45 requests/minute over HTTP. The rate limiter stays well below this.

---

## Error Handling

- Each module wraps its operations in `try/except` and returns an `error` field.
- The CLI catches unexpected module failures and continues to the next module/domain.
- The GUI displays errors inside the relevant tab and never crashes.

---

## Troubleshooting

| Problem                            | Fix                                                        |
|------------------------------------|------------------------------------------------------------|
| `ModuleNotFoundError: No module named 'whois'` | Run `pip install python-whois dnspython requests rich` |
| WHOIS times out                    | WHOIS servers can be slow; increase `RATE_LIMITS["whois"]` and `TIMEOUT` |
| `TclError: no display name`        | GUI requires a display; use the CLI instead (or install `python3-tk`) |
| No subdomains found                | `crt.sh` can return empty results; add more words to `config/subdomains.txt` |
| Shodan/GitHub/HIBP return empty    | Expected without API keys — see "Notes on Free-Tier Sources" |

---

## Legal & Ethical Note

This tool performs **passive reconnaissance using public data only** and is intended for educational use, security research, and scanning domains you own or are authorized to test. Always check the terms of service of each data source and applicable laws before use. Do not use this tool against systems you do not have permission to investigate.
