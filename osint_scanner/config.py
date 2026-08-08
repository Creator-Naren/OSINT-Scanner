"""Central configuration for the OSINT scanner."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

RATE_LIMITS = {
    "whois": 2.0,
    "dns": 1.0,
    "geoip": 1.0,
    "shodan": 2.0,
    "subdomains": 1.0,
    "leaks": 2.0,
}

TIMEOUT = 10
SUBDOMAIN_WORDLIST = BASE_DIR / "config" / "subdomains.txt"
OUTPUT_DIR = BASE_DIR / "results"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
