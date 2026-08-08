import whois

from osint_scanner.config import RATE_LIMITS
from osint_scanner.modules._utils import RateLimiter, safe_str


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def scan(domain: str) -> dict:
    limiter = RateLimiter(RATE_LIMITS["whois"])
    try:
        limiter.wait()
        w = whois.whois(domain)
        return {
            "registrar": safe_str(w.registrar),
            "creation_date": safe_str(w.creation_date),
            "expiration_date": safe_str(w.expiration_date),
            "name_servers": _as_list(w.name_servers),
            "emails": _as_list(w.emails),
            "error": "N/A",
        }
    except Exception as exc:
        return {
            "registrar": "N/A",
            "creation_date": "N/A",
            "expiration_date": "N/A",
            "name_servers": [],
            "emails": [],
            "error": str(exc),
        }
