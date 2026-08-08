"""Shodan host lookup for a domain (free tier, no API key)."""

import socket

import requests

from osint_scanner.config import RATE_LIMITS, TIMEOUT
from osint_scanner.modules._utils import RateLimiter


def _result(ip: str, error: str, data: dict = None) -> dict:
    data = data or {}
    return {
        "ip": ip,
        "ports": data.get("ports", []) or [],
        "hostnames": data.get("hostnames", []) or [],
        "vulns": data.get("vulns", []) or [],
        "org": data.get("org") or "N/A",
        "os": data.get("os") or "N/A",
        "error": error,
    }


def scan(domain: str) -> dict:
    limiter = RateLimiter(RATE_LIMITS["shodan"])
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as exc:
        return _result("", str(exc))
    try:
        limiter.wait()
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}", timeout=TIMEOUT)
        if response.status_code == 200:
            return _result(ip, "N/A", response.json())
        if response.status_code == 401:
            return _result(ip, "Shodan API key required")
        if response.status_code == 404:
            return _result(ip, "no Shodan record (free tier)")
        return _result(ip, f"HTTP {response.status_code}")
    except Exception as exc:
        return _result(ip, str(exc))
