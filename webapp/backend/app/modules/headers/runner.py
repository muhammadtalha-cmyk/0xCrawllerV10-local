from __future__ import annotations

import asyncio
import json
import ssl
import urllib.request
from pathlib import Path
from typing import Any, Callable, Awaitable, Dict, List
from ..base import BaseModule

SECURITY_HEADERS_SPEC = [
    {
        "header": "Strict-Transport-Security",
        "name": "HSTS",
        "description": "Enforces secure (HTTPS) connections and prevents SSL-stripping attacks.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "weight": 20,
    },
    {
        "header": "Content-Security-Policy",
        "name": "CSP",
        "description": "Restricts resources (scripts, images, stylesheets) that the browser is allowed to load to mitigate XSS.",
        "recommended": "default-src 'self'; script-src 'self' ...",
        "weight": 25,
    },
    {
        "header": "X-Frame-Options",
        "name": "Clickjacking Defense",
        "description": "Instructs browser whether the page can be rendered inside a <frame>, <iframe>, or <embed> to prevent Clickjacking.",
        "recommended": "DENY or SAMEORIGIN",
        "weight": 15,
    },
    {
        "header": "X-Content-Type-Options",
        "name": "MIME-Sniffing Prevention",
        "description": "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
        "recommended": "nosniff",
        "weight": 15,
    },
    {
        "header": "Referrer-Policy",
        "name": "Referrer Privacy Policy",
        "description": "Governs which referrer information sent in the Referer header should be included with requests.",
        "recommended": "strict-origin-when-cross-origin",
        "weight": 10,
    },
    {
        "header": "Permissions-Policy",
        "name": "Permissions Policy",
        "description": "Allows site to control which browser features (camera, microphone, geolocation) can be used in the page.",
        "recommended": "camera=(), microphone=(), geolocation=()",
        "weight": 15,
    },
]


class SecurityHeadersModule(BaseModule):
    id = "headers"
    name = "HTTP Security Headers Audit"
    description = "Audit HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Cookie security flags with A+ to F grading."
    category = "HTTP Security Hygiene"
    icon = "🛡️"

    async def run(
        self,
        job_id: str,
        target: str,
        output_dir: Path,
        update_progress: Callable[[int, str], Awaitable[None]],
    ) -> dict[str, Any]:
        await update_progress(10, "Preparing HTTP header audit request...")

        clean_target = target.strip()
        if not clean_target.startswith("http://") and not clean_target.startswith("https://"):
            url = f"https://{clean_target}"
        else:
            url = clean_target

        log_file = output_dir / "execution.log"
        with open(log_file, "a") as f:
            f.write(f"=== HTTP Security Headers Audit Job: {job_id} ===\nTarget URL: {url}\n\n")

        await update_progress(30, f"Probing {url} for HTTP response headers...")

        response_headers: Dict[str, str] = {}
        status_code = None
        final_url = url
        error_msg = None

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) 0xCrawller/10.0 Security Auditor",
                "Accept": "*/*",
            },
        )

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=12) as resp:
                status_code = resp.status
                final_url = resp.geturl()
                for k, v in resp.headers.items():
                    response_headers[k.lower()] = v
        except urllib.error.HTTPError as ex:
            status_code = ex.code
            final_url = ex.geturl()
            for k, v in ex.headers.items():
                response_headers[k.lower()] = v
        except Exception as ex:
            error_msg = str(ex)
            if url.startswith("https://"):
                try:
                    http_url = f"http://{clean_target}"
                    with urllib.request.urlopen(http_url, timeout=10) as hresp:
                        status_code = hresp.status
                        final_url = hresp.geturl()
                        for k, v in hresp.headers.items():
                            response_headers[k.lower()] = v
                        error_msg = None
                except Exception:
                    pass

        with open(log_file, "a") as f:
            f.write(f"Response Status: {status_code}\nFinal URL: {final_url}\nHeaders:\n{json.dumps(response_headers, indent=2)}\n\n")

        await update_progress(65, "Evaluating security policies and compliance...")

        audited_headers: List[Dict[str, Any]] = []
        earned_score = 0
        total_possible = sum(s["weight"] for s in SECURITY_HEADERS_SPEC)

        for spec in SECURITY_HEADERS_SPEC:
            h_key = spec["header"].lower()
            present = h_key in response_headers
            val = response_headers.get(h_key, "")

            if present:
                earned_score += spec["weight"]
                status = "PASS"
            else:
                status = "FAIL"

            audited_headers.append({
                "header": spec["header"],
                "name": spec["name"],
                "status": status,
                "value": val or "Not Set / Missing",
                "description": spec["description"],
                "recommended": spec["recommended"],
            })

        info_disclosures = []
        for leak_header in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
            if leak_header in response_headers:
                info_disclosures.append({
                    "header": leak_header,
                    "value": response_headers[leak_header],
                    "risk": "Server information disclosure gives attackers software stack details.",
                })

        percentage = round((earned_score / total_possible) * 100) if total_possible else 0
        if percentage >= 90:
            grade = "A+"
        elif percentage >= 80:
            grade = "A"
        elif percentage >= 65:
            grade = "B"
        elif percentage >= 50:
            grade = "C"
        elif percentage >= 35:
            grade = "D"
        else:
            grade = "F"

        await update_progress(100, "Security headers audit completed.")

        results = {
            "module": self.id,
            "target": target,
            "job_id": job_id,
            "url": final_url,
            "status_code": status_code,
            "score": percentage,
            "grade": grade,
            "passed_count": len([h for h in audited_headers if h["status"] == "PASS"]),
            "failed_count": len([h for h in audited_headers if h["status"] == "FAIL"]),
            "headers": audited_headers,
            "information_disclosures": info_disclosures,
            "raw_headers": response_headers,
            "error": error_msg,
        }

        return results
