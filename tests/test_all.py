"""Automated unit test suite for OSINT Scanner."""

import json
import unittest
from unittest.mock import MagicMock, patch

from modules import MODULES, run_module
from modules._utils import sanitize_domain, safe_str, RateLimiter
import scanner
import output


class TestSanitizer(unittest.TestCase):
    def test_sanitize_domain(self):
        self.assertEqual(sanitize_domain("http://example.com/path"), "example.com")
        self.assertEqual(sanitize_domain("HTTPS://SUB.DOMAIN.ORG:8080/"), "sub.domain.org")
        self.assertEqual(sanitize_domain("  example.com.  "), "example.com")
        self.assertEqual(sanitize_domain("http://target.com?query=1#hash"), "target.com")
        self.assertEqual(sanitize_domain(""), "")

    def test_safe_str(self):
        self.assertEqual(safe_str(None), "N/A")
        self.assertEqual(safe_str(["a", "b"]), "a, b")
        self.assertEqual(safe_str("test"), "test")


class TestModulesRegistry(unittest.TestCase):
    def test_modules_dict(self):
        expected = {"whois", "dns", "geoip", "shodan", "subdomains", "leaks"}
        self.assertEqual(set(MODULES.keys()), expected)

    def test_invalid_domain_graceful_response(self):
        for name, scan_fn in MODULES.items():
            res = scan_fn("")
            self.assertIsInstance(res, dict)
            self.assertIn("error", res)


class TestOutput(unittest.TestCase):
    def test_timestamp_now(self):
        ts = output.timestamp_now()
        self.assertIsInstance(ts, str)
        self.assertIn("T", ts)

    def test_write_json(self):
        ts = output.timestamp_now()
        data = [{"domain": "test.com", "whois": {"registrar": "test"}}]
        path = output.write_json(ts, data)
        self.assertTrue(path.endswith(".json"))
        with open(path, encoding="utf-8") as fh:
            content = json.load(fh)
        self.assertIn("scan_timestamp", content)
        self.assertEqual(content["domains"], data)


class TestScannerOrchestrator(unittest.TestCase):
    def test_scan_domain_invalid(self):
        res = scanner.scan_domain("")
        self.assertIn("whois", res)
        self.assertEqual(res["whois"]["error"], "Invalid domain name")

    @patch("scanner.render_console")
    def test_scan_batch(self, mock_render):
        with patch.object(scanner, "scan_domain", return_value={"whois": {"error": None}}):
            results = scanner.scan_batch(["example.com", "http://google.com"])
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]["domain"], "example.com")
            self.assertEqual(results[1]["domain"], "google.com")


if __name__ == "__main__":
    unittest.main()
