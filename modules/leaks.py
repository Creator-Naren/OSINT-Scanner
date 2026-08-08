"""Leak checking via GitHub code search and HIBP domain API (free tier)."""

import requests

from osint_scanner.config import RATE_LIMITS, TIMEOUT
from osint_scanner.modules._utils import RateLimiter

_HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "osint-scanner"}


def _result(github_leaks, email_leaks: int, error) -> dict:
    return {"github_leaks": github_leaks, "email_leaks": email_leaks, "error": error}


def _github_search(domain: str, limiter: RateLimiter) -> list:
    url = f"https://api.github.com/search/code?q=domain:{domain}&per_page=5"
    limiter.wait()
    response = requests.get(url, timeout=TIMEOUT, headers=_HEADERS)
    if response.status_code != 200:
        return []
    data = response.json()
    return [
        {
            "repository": item["repository"]["full_name"],
            "path": item["path"],
            "html_url": item["html_url"],
        }
        for item in data.get("items", [])
    ]


def _hibp_breach_count(domain: str, limiter: RateLimiter) -> int:
    url = f"https://haveibeenpwned.com/api/v3/domain/{domain}"
    limiter.wait()
    response = requests.get(url, timeout=TIMEOUT, headers=_HEADERS)
    if response.status_code != 200:
        return 0
    data = response.json()
    return len(data) if isinstance(data, list) else 0


def scan(domain: str) -> dict:
    limiter = RateLimiter(RATE_LIMITS["leaks"])
    try:
        github_leaks = _github_search(domain, limiter)
        email_leaks = _hibp_breach_count(domain, limiter)
        return _result(github_leaks, email_leaks, None)
    except Exception as exc:
        return _result([], 0, str(exc))
