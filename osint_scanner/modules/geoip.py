import socket

from osint_scanner.config import RATE_LIMITS
from osint_scanner.modules._utils import RateLimiter, http_get


def scan(domain: str) -> dict:
    limiter = RateLimiter(RATE_LIMITS["geoip"])
    try:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror as exc:
            return {"ip": "N/A", "city": "N/A", "region": "N/A", "country": "N/A", "lat": 0.0, "lon": 0.0, "isp": "N/A", "org": "N/A", "as": "N/A", "error": str(exc)}
        resp = http_get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as", limiter)
        data = resp.json()
        if data.get("status") != "success":
            return {"ip": "N/A", "city": "N/A", "region": "N/A", "country": "N/A", "lat": 0.0, "lon": 0.0, "isp": "N/A", "org": "N/A", "as": "N/A", "error": data.get("message", "geo lookup failed")}
        return {
            "ip": ip,
            "city": data.get("city", "N/A") or "N/A",
            "region": data.get("regionName", "N/A") or "N/A",
            "country": data.get("country", "N/A") or "N/A",
            "lat": data.get("lat", 0.0) or 0.0,
            "lon": data.get("lon", 0.0) or 0.0,
            "isp": data.get("isp", "N/A") or "N/A",
            "org": data.get("org", "N/A") or "N/A",
            "as": data.get("as", "N/A") or "N/A",
            "error": "N/A",
        }
    except Exception as exc:
        return {"ip": "N/A", "city": "N/A", "region": "N/A", "country": "N/A", "lat": 0.0, "lon": 0.0, "isp": "N/A", "org": "N/A", "as": "N/A", "error": str(exc)}
