"""Console (Rich) and JSON output for OSINT scan results."""

import json
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from osint_scanner.config import OUTPUT_DIR

console = Console()


def render_console(domain: str, result: dict) -> None:
    """Render a single domain's scan result as a Rich panel."""
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="bold cyan", width=16)
    table.add_column("Value", overflow="fold")

    def add_section(title: str) -> None:
        table.add_row(f"[bold magenta]{title}[/]", "")

    add_section("WHOIS")
    w = result.get("whois", {})
    table.add_row("Registrar", str(w.get("registrar", "N/A")))
    table.add_row("Created", str(w.get("creation_date", "N/A")))
    table.add_row("Expires", str(w.get("expiration_date", "N/A")))
    if w.get("error") and w["error"] != "N/A":
        table.add_row("Whois error", f"[red]{w['error']}[/]")

    add_section("DNS")
    d = result.get("dns", {})
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        table.add_row(rtype, ", ".join(d.get(rtype, [])) or "none")
    if d.get("SOA"):
        table.add_row("SOA", str(d["SOA"]))
    if d.get("error"):
        table.add_row("DNS error", f"[red]{d['error']}[/]")

    add_section("Geolocation")
    g = result.get("geoip", {})
    table.add_row("IP", str(g.get("ip", "N/A")))
    table.add_row("City", str(g.get("city", "N/A")))
    table.add_row("Country", str(g.get("country", "N/A")))
    table.add_row("ISP", str(g.get("isp", "N/A")))
    table.add_row("AS", str(g.get("as", "N/A")))

    add_section("Shodan")
    s = result.get("shodan", {})
    ports = ", ".join(str(p) for p in s.get("ports", [])) or "none"
    table.add_row("Ports", ports)
    table.add_row("Hostnames", ", ".join(s.get("hostnames", [])) or "none")
    table.add_row("Vulns", ", ".join(s.get("vulns", [])) or "none")
    table.add_row("OS", str(s.get("os", "N/A")))

    add_section("Subdomains")
    sd = result.get("subdomains", {})
    table.add_row("Found", ", ".join(sd.get("subdomains", [])) or "none")

    add_section("Leaks")
    lk = result.get("leaks", {})
    table.add_row("GitHub hits", str(len(lk.get("github_leaks", []))))
    table.add_row("Breach domains", str(lk.get("email_leaks", 0)))

    console.print(Panel(table, title=f"[bold]{domain}[/]", border_style="cyan"))


def write_json(scan_timestamp: str, results: dict) -> str:
    """Write aggregated results to a timestamped JSON file. Returns the path."""
    payload = {
        "scan_timestamp": scan_timestamp,
        "domains": results,
    }
    path = OUTPUT_DIR / f"osint_{scan_timestamp.replace(':', '').replace('-', '')}.json"
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return str(path)


def timestamp_now() -> str:
    return datetime.now(timezone.utc).isoformat()
