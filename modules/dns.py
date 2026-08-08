"""DNS record enumeration for a domain."""

import dns.rdataclass
import dns.rdatatype
import dns.resolver

from osint_scanner.config import RATE_LIMITS
from osint_scanner.modules._utils import RateLimiter

_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def scan(domain: str) -> dict:
    result = {t: [] for t in _TYPES}
    result["SOA"] = ""
    result["error"] = None
    limiter = RateLimiter(RATE_LIMITS["dns"])
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 5
    try:
        for t in _TYPES + ["SOA"]:
            limiter.wait()
            rtype = dns.rdatatype.from_text(t)
            try:
                answers = resolver.resolve(domain, rtype)
                if t == "SOA":
                    result["SOA"] = str(answers[0])
                elif t == "MX":
                    for answer in answers:
                        result[t].append(f"{answer.preference} {answer.exchange}")
                elif t == "TXT":
                    for answer in answers:
                        result[t].append("".join(s.decode() for s in answer.strings))
                else:
                    for answer in answers:
                        result[t].append(answer.to_text())
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
    except Exception as exc:
        return {t: [] for t in _TYPES} | {"SOA": "", "error": str(exc)}
    return result
