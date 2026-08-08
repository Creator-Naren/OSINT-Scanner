<div align="center">

# 🕵️‍♂️ OSINT Scanner

**A modular, passive OSINT (Open-Source Intelligence) reconnaissance tool written in Python.**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)]()
[![Interface](https://img.shields.io/badge/Interface-CLI%20%2F%20GUI-ff69b4?style=for-the-badge)]()
[![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)]()

> *It collects WHOIS, DNS, IP geolocation, Shodan, subdomain, and leak data for one or more domains — entirely from public data sources, with no direct contact with the target.*

<br />

[**Features**](#-features) • [**Installation**](#-installation) • [**Usage**](#-usage) • [**GUI Gallery**](#-gui-tab-reference-googlecom-scan) • [**Modules**](#-module-interface)

</div>

---

## ✨ Features

- 🌐 **WHOIS lookup** — registrar, creation/expiration dates, name servers, contact emails (`python-whois`)
- 🖧 **DNS enumeration** — A, AAAA, MX, NS, TXT, CNAME, and SOA records (`dnspython`)
- 📍 **IP geolocation** — IP, city, region, country, coordinates, ISP, and ASN via `ip-api.com`
- 🔍 **Shodan host lookup** — open ports, hostnames, CVEs, and OS from Shodan's index (free tier)
- 🌳 **Subdomain enumeration** — certificate transparency logs (`crt.sh`) plus DNS brute-force from a wordlist
- 🚨 **Leak checking** — GitHub code search and HaveIBeenPwned domain breach count
- 💻 **Two interfaces**
  - **CLI** — batch scan with Rich-formatted console tables and JSON export
  - **GUI** — Tkinter desktop app with per-source tabs, background-thread scanning, and progress feedback
- 🛡️ **Resilient** — every module fails gracefully (returns an `error` field instead of crashing); invalid domains and offline APIs are handled
- ⏱️ **Rate-limited** — sequential requests with configurable delays to respect free-tier API limits

---

## 📂 Project Structure

```text
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
