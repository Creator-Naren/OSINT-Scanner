"""Subdomain enumeration via crt.sh and DNS brute-force wordlist."""

import requests

from osint_scanner.config import RATE_LIMITS, SUBDOMAIN_WORDLIST, TIMEOUT
from osint_scanner.modules._utils import RateLimiter


def _crt_sh(domain: str, limiter: RateLimiter) -> list:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    limiter.wait()
    try:
        response = requests.get(url, timeout=TIMEOUT)
        entries = response.json()
    except Exception:
        return []
    if not isinstance(entries, list):
        return []
    found = set()
    result = []
    for entry in entries:
        names = (entry.get("name_value") or "").split("\n")
        for name in names:
            name = name.strip()
            if name.startswith("*"):
                continue
            if not (name == domain or name.endswith("." + domain)):
                continue
            if name not in found:
                found.add(name)
                result.append(name)
    return result


def _brute_force(domain: str) -> list:
    try:
        import dns.resolver
    except ImportError:
        return []
    try:
        words = [w.strip() for w in SUBDOMAIN_WORDLIST.read_text().splitlines() if w.strip()]
    except OSError:
        return []
    found = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2
    resolver.timeout = 2
    limiter = RateLimiter(0.2)
    for word in words:
        host = f"{word}.{domain}"
        try:
            limiter.wait()
            resolver.resolve(host, "A")
            found.append(host)
        except Exception:
            continue
    return found


def scan(domain: str) -> dict:
    limiter = RateLimiter(RATE_LIMITS["subdomains"])
    try:
        crt = _crt_sh(domain, limiter)
        brute = _brute_force(domain)
        seen = set()
        merged = []
        for name in crt + brute:
            if name not in seen:
                seen.add(name)
                merged.append(name)
        return {
            "subdomains": sorted(merged),
            "sources": {"crt_sh": crt, "brute_force": brute},
            "error": None,
        }
    except Exception as exc:
        return {"subdomains": [], "sources": {"crt_sh": [], "brute_force": []}, "error": str(exc)}
