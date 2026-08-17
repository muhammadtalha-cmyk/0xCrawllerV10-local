from __future__ import annotations

import unittest

from smart_recon.classification import canonicalize_endpoint_url, classify_endpoint_url
from smart_recon.keywords import assess_keyword, generate_candidate_records
from smart_recon.runtime import detect_diagnostics
from smart_recon.validation import is_valid_hostname, parent_zone_for_host


class KeywordTests(unittest.TestCase):
    def test_rejects_report_noise(self) -> None:
        for value in ["0050ziihckmdy", "1024x584", "1qx2997voqaun", "600x400"]:
            self.assertFalse(assess_keyword(value)["accepted"], value)

    def test_accepts_meaningful_words(self) -> None:
        for value in ["api", "dashboard", "booking", "integration", "public-api"]:
            self.assertTrue(assess_keyword(value)["accepted"], value)

    def test_candidate_cap_keeps_exact(self) -> None:
        evidence = {f"meaningful{i}": {"score": 70, "source": "test"} for i in range(100)}
        records, stats = generate_candidate_records(
            "example.com",
            evidence,
            exact_hosts=["exact.example.com"],
            max_mode=True,
            exhaustive=False,
            candidate_limit=50,
        )
        self.assertIn("exact.example.com", records)
        self.assertTrue(stats["truncated"])


class ValidationTests(unittest.TestCase):
    def test_invalid_labels(self) -> None:
        self.assertFalse(is_valid_hostname("-wildcard.example.com"))
        self.assertFalse(is_valid_hostname("_wildcard.example.com"))
        self.assertTrue(is_valid_hostname("wildcard-test.example.com"))

    def test_parent_zone(self) -> None:
        self.assertEqual(parent_zone_for_host("id.staging.example.com", "example.com"), "staging.example.com")
        self.assertEqual(parent_zone_for_host("api.example.com", "example.com"), "example.com")


class ClassificationTests(unittest.TestCase):
    def test_url_normalization(self) -> None:
        value = canonicalize_endpoint_url("https://api.example.com/openapi.json%5C")
        self.assertEqual(value, "https://api.example.com/openapi.json/")

    def test_static_admin_json_not_admin_endpoint(self) -> None:
        record = classify_endpoint_url(
            "https://hub.example.com/_next/static/chunks/locales/en/admin.json",
            "example.com",
        )
        self.assertEqual(record["category"], "JavaScript/Static Bundle")

    def test_real_admin_path(self) -> None:
        record = classify_endpoint_url("https://hub.example.com/admin/users", "example.com")
        self.assertEqual(record["category"], "Admin/Management Endpoint")


class RuntimeTests(unittest.TestCase):
    def test_urls_with_error_words_are_not_warnings(self) -> None:
        stdout = "https://hub.example.com/api/error\nhttps://nextjs.org/docs/messages/invalid-images-config\n"
        warnings, errors = detect_diagnostics("katana", stdout, "")
        self.assertEqual(warnings, [])
        self.assertEqual(errors, [])

    def test_explicit_warning_is_detected(self) -> None:
        warnings, _ = detect_diagnostics("bbot", "", "[WARNING] No API key set")
        self.assertTrue(warnings)


if __name__ == "__main__":
    unittest.main()
