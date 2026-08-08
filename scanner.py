"""OSINT scanner orchestrator and CLI entry point."""

import argparse
import logging
import sys

from osint_scanner.modules import MODULES
from osint_scanner.output import console, render_console, timestamp_now, write_json

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("osint")


def scan_domain(domain: str) -> dict:
    """Run all modules against a single domain, returning aggregated results."""
    result = {}
    for name, scan in MODULES.items():
        try:
            result[name] = scan(domain)
        except Exception as exc:
            logger.error("module %s failed for %s: %s", name, domain, exc)
            result[name] = {"error": str(exc)}
    return result


def scan_batch(domains: list) -> list:
    results = []
    for i, domain in enumerate(domains, start=1):
        console.rule(f"[bold]Scanning {domain} ({i}/{len(domains)})[/]")
        result = scan_domain(domain)
        results.append({"domain": domain, **result})
        render_console(domain, result)
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Passive OSINT scanner for domains.")
    parser.add_argument("domains", nargs="*", help="One or more domains to scan")
    parser.add_argument("-f", "--file", help="File with domains, one per line")
    args = parser.parse_args(argv)

    domains = list(args.domains)
    if args.file:
        try:
            with open(args.file, encoding="utf-8-sig") as fh:
                domains.extend(line.strip() for line in fh if line.strip())
        except OSError as exc:
            logger.error("cannot read domain file: %s", exc)
            return 1

    if not domains:
        parser.print_usage()
        print("error: provide at least one domain or a --file")
        return 1

    scan_timestamp = timestamp_now()
    results = scan_batch(domains)
    path = write_json(scan_timestamp, results)
    console.print(f"\n[bold green]Results written to:[/] {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
