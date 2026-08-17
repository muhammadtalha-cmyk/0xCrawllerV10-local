from __future__ import annotations

import unittest

from smart_recon.browser import extract_browser_observations
from smart_recon.classification import classify_endpoint_url
from smart_recon.keywords import filter_keywords, generate_candidates
from smart_recon.runtime import sanitize_domain


class OfflineTests(unittest.TestCase):
    def test_domain_sanitization(self) -> None:
        self.assertEqual(sanitize_domain("https://Example.COM/path"), "example.com")
        with self.assertRaises(ValueError):
            sanitize_domain("not-a-domain")

    def test_keyword_filter(self) -> None:
        self.assertIn("payroll", filter_keywords(["Payroll", "css", "123"]))
        self.assertNotIn("css", filter_keywords(["Payroll", "css", "123"]))

    def test_candidate_generation(self) -> None:
        candidates = generate_candidates("example.com", ["payroll"], max_mode=False)
        self.assertIn("payroll.example.com", candidates)
        self.assertIn("payroll-api.example.com", candidates)

    def test_browser_extraction(self) -> None:
        records = [{"link_request": ["https://api.example.com/v1/time", "https://external.test/x"]}]
        urls, hosts = extract_browser_observations(records, "example.com")
        self.assertIn("https://api.example.com/v1/time", urls)
        self.assertEqual(hosts, {"api.example.com"})

    def test_endpoint_classification(self) -> None:
        result = classify_endpoint_url("https://admin.example.com/login", "example.com")
        self.assertEqual(result["priority"], "High")


if __name__ == "__main__":
    unittest.main()
