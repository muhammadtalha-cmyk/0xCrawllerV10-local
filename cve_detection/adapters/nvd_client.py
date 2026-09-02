"""NVD (National Vulnerability Database) REST API 2.0 Client with Offline Curated Fallback."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple
import requests

logger = logging.getLogger("cve_detection.nvd_client")

# Curated fallback vulnerabilities for offline execution, testing, or rate-limited environments
CURATED_OFFLINE_CVES: Dict[Tuple[str, str], List[Dict[str, Any]]] = {
    ("drupal", "7"): [
        {
            "cve_id": "CVE-2018-7600",
            "cvss_score": 9.8,
            "cvss_version": "CVSS v3.1",
            "severity": "CRITICAL",
            "description": "Drupal 7.x and 8.x remote code execution vulnerability (Drupalgeddon 2). Unauthenticated attackers can execute arbitrary code on the underlying server via AJAX requests.",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-7600",
        },
        {
            "cve_id": "CVE-2018-7602",
            "cvss_score": 8.1,
            "cvss_version": "CVSS v3.1",
            "severity": "HIGH",
            "description": "Drupal 7.x and 8.x remote code execution vulnerability (Drupalgeddon 3) in URL request handling for destination redirect parameters.",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-7602",
        },
        {
            "cve_id": "CVE-2019-6340",
            "cvss_score": 9.8,
            "cvss_version": "CVSS v3.1",
            "severity": "CRITICAL",
            "description": "Drupal REST web services arbitrary PHP code execution via crafted web requests.",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-6340",
        },
    ],
    ("apache", "2.4.49"): [
        {
            "cve_id": "CVE-2021-41773",
            "cvss_score": 9.8,
            "cvss_version": "CVSS v3.1",
            "severity": "CRITICAL",
            "description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives.",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        },
        {
            "cve_id": "CVE-2021-42013",
            "cvss_score": 9.8,
            "cvss_version": "CVSS v3.1",
            "severity": "CRITICAL",
            "description": "Incomplete fix for CVE-2021-41773 in Apache HTTP Server 2.4.49 and 2.4.50 allowing path traversal and remote code execution.",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        },
    ],
    ("apache", "2.4.50"): [
        {
            "cve_id": "CVE-2021-42013",
            "cvss_score": 9.8,
            "cvss_version": "CVSS v3.1",
            "severity": "CRITICAL",
            "description": "Incomplete fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 allowing path traversal and remote code execution.",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        },
    ],
    ("php", "8.1.0"): [
        {
            "cve_id": "CVE-2021-21703",
            "cvss_score": 7.5,
            "cvss_version": "CVSS v3.1",
            "severity": "HIGH",
            "description": "Local privilege escalation in PHP-FPM socket handling.",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-21703",
        }
    ],
    ("openssh", "7.2p2"): [
        {
            "cve_id": "CVE-2016-0777",
            "cvss_score": 5.9,
            "cvss_version": "CVSS v3.0",
            "severity": "MEDIUM",
            "description": "OpenSSH roaming information disclosure vulnerability (client memory leak).",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2016-0777",
        },
        {
            "cve_id": "CVE-2018-15473",
            "cvss_score": 5.3,
            "cvss_version": "CVSS v3.0",
            "severity": "MEDIUM",
            "description": "OpenSSH user enumeration vulnerability via malformed authentication requests.",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
        }
    ],
    ("nginx", "1.18.0"): [
        {
            "cve_id": "CVE-2021-23017",
            "cvss_score": 7.7,
            "cvss_version": "CVSS v3.1",
            "severity": "HIGH",
            "description": "1-byte memory overwrite in resolver component leading to worker crash or arbitrary code execution.",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
        }
    ],
}


def score_to_severity(score: Optional[float], explicit_severity: Optional[str] = None) -> str:
    if explicit_severity:
        sev = explicit_severity.strip().upper()
        if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "INFO"}:
            return "INFO" if sev == "INFORMATIONAL" else sev

    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


class NvdClient:
    def __init__(
        self,
        base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
        api_key: Optional[str] = None,
        timeout: float = 20.0,
        rate_limit_delay: float = 6.0,
        results_limit: int = 10,
        offline: bool = False,
    ) -> None:
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.results_limit = results_limit
        self.offline = offline
        self._cache: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        self._last_call_time: float = 0.0

    def _extract_cvss(self, cve_item: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
        metrics = cve_item.get("metrics", {})
        for key, label in [
            ("cvssMetricV31", "CVSS v3.1"),
            ("cvssMetricV30", "CVSS v3.0"),
            ("cvssMetricV2", "CVSS v2"),
        ]:
            if key in metrics and metrics[key]:
                first = metrics[key][0]
                cvss_data = first.get("cvssData", {})
                base_score = cvss_data.get("baseScore")
                base_severity = cvss_data.get("baseSeverity") or first.get("baseSeverity")
                if base_score is not None:
                    try:
                        return float(base_score), label, base_severity
                    except (ValueError, TypeError):
                        pass
        return None, None, None

    def search(self, product: str, version: str) -> List[Dict[str, Any]]:
        clean_product = product.strip()
        clean_version = version.strip()
        cache_key = (clean_product.lower(), clean_version.lower())

        if cache_key in self._cache:
            return self._cache[cache_key]

        # Check offline curated fallback
        if self.offline:
            results = CURATED_OFFLINE_CVES.get(cache_key, [])
            self._cache[cache_key] = results
            return results

        query = f"{clean_product} {clean_version}"
        params = {
            "keywordSearch": query,
            "resultsPerPage": self.results_limit,
        }
        headers = {
            "User-Agent": "0xCrawller-CVE-Scanner/1.0"
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        results: List[Dict[str, Any]] = []
        try:
            # Enforce polite rate limit before making request
            elapsed = time.time() - self._last_call_time
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)

            self._last_call_time = time.time()
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=self.timeout,
            )
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "UNKNOWN")
                    if not cve_id.startswith("CVE-"):
                        continue

                    descriptions = cve.get("descriptions", [])
                    description = next(
                        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                        "No description available.",
                    )

                    cvss_score, cvss_version, explicit_sev = self._extract_cvss(cve)
                    severity = score_to_severity(cvss_score, explicit_sev)

                    results.append({
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "cvss_version": cvss_version or "N/A",
                        "severity": severity,
                        "description": description,
                        "source": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "published": cve.get("published"),
                    })
            else:
                logger.warning(
                    f"NVD API returned HTTP {response.status_code} for '{query}'. Falling back to curated catalog if available."
                )
                results = CURATED_OFFLINE_CVES.get(cache_key, [])
        except Exception as exc:
            logger.warning(f"NVD query error for '{query}': {exc}. Using fallback catalog.")
            results = CURATED_OFFLINE_CVES.get(cache_key, [])

        self._cache[cache_key] = results
        return results
