"""Shared helpers for OSINT modules: rate limiting, HTTP requests, and domain sanitization."""

import logging
import re
import time
from urllib.parse import urlparse

import requests

try:
    from config import TIMEOUT
except ImportError:
    from osint_scanner.config import TIMEOUT

logger = logging.getLogger("osint")


class RateLimiter:
    """Simple sequential rate limiter enforcing a minimum delay between calls."""

    def __init__(self, delay: float = 1.0):
        self.delay = delay
        self._last_call = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last_call
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_call = time.monotonic()


def http_get(url: str, limiter: RateLimiter, timeout: int = TIMEOUT, **kwargs) -> requests.Response:
    """Rate-limited GET request that raises on HTTP errors."""
    limiter.wait()
    response = requests.get(url, timeout=timeout, **kwargs)
    response.raise_for_status()
    return response


def sanitize_domain(domain: str) -> str:
    """Sanitize and validate a domain string.

    Removes protocols (http://, https://), paths, ports, whitespace, and leading/trailing dots/slashes.
    """
    if not domain:
        return ""
    d = domain.strip().lower()
    if d.startswith(("http://", "https://", "ftp://")):
        parsed = urlparse(d)
        d = parsed.netloc or parsed.path
    # Remove path/query/fragment if leftover
    d = d.split("/")[0].split("?")[0].split("#")[0]
    # Remove port if present
    d = re.sub(r":\d+$", "", d)
    # Strip invalid surrounding characters
    d = d.strip("./")
    return d


def safe_str(value) -> str:
    """Convert a value to a string, handling None and list-of-str from whois libs."""
    if value is None:
        return "N/A"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v is not None)
    return str(value)
