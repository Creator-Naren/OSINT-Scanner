"""OSINT scanner package."""

from . import whois, dns, geoip, shodan, subdomains, leaks

MODULES = {
    "whois": whois.scan,
    "dns": dns.scan,
    "geoip": geoip.scan,
    "shodan": shodan.scan,
    "subdomains": subdomains.scan,
    "leaks": leaks.scan,
}


def run_module(name: str, domain: str) -> dict:
    """Run a single module's scan for a domain, returning its result dict."""
    return MODULES[name](domain)
