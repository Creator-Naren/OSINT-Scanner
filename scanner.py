"""OSINT scanner orchestrator and CLI entry point."""

import argparse
import logging
import sys

try:
    from modules import MODULES
    from modules._utils import sanitize_domain
    from output import console, render_console, timestamp_now, write_json
except ImportError:
    from osint_scanner.modules import MODULES
    from osint_scanner.modules._utils import sanitize_domain
    from osint_scanner.output import console, render_console, timestamp_now, write_json

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("osint")


def scan_domain(domain: str) -> dict:
    """Run all modules against a single domain, returning aggregated results."""
    clean = sanitize_domain(domain)
    if not clean:
        logger.error("Invalid domain name: %r", domain)
        return {name: {"error": "Invalid domain name"} for name in MODULES}

    result = {}
    for name, scan_fn in MODULES.items():
        try:
            result[name] = scan_fn(clean)
        except Exception as exc:
            logger.error("module %s failed for %s: %s", name, clean, exc)
            result[name] = {"error": str(exc)}
    return result


def scan_batch(domains: list) -> list:
    results = []
    clean_domains = []
    for raw in domains:
        c = sanitize_domain(raw)
        if c and c not in clean_domains:
            clean_domains.append(c)

    if not clean_domains:
        logger.error("No valid domains provided.")
        return []

    for i, domain in enumerate(clean_domains, start=1):
        console.rule(f"[bold cyan]Scanning {domain} ({i}/{len(clean_domains)})[/]")
        result = scan_domain(domain)
        results.append({"domain": domain, **result})
        render_console(domain, result)
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Passive OSINT scanner for domains.")
    parser.add_argument("domains", nargs="*", help="One or more domains to scan")
    parser.add_argument("-f", "--file", help="File with domains, one per line")
    args = parser.parse_args(argv)

    raw_domains = list(args.domains)
    if args.file:
        try:
            with open(args.file, encoding="utf-8-sig") as fh:
                raw_domains.extend(line.strip() for line in fh if line.strip())
        except OSError as exc:
            logger.error("cannot read domain file: %s", exc)
            return 1

    if not raw_domains:
        parser.print_usage()
        print("error: provide at least one domain or a --file")
        return 1

    scan_timestamp = timestamp_now()
    results = scan_batch(raw_domains)
    if not results:
        print("error: no valid domains to scan")
        return 1

    path = write_json(scan_timestamp, results)
    console.print(f"\n[bold green]Results written to:[/] {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
