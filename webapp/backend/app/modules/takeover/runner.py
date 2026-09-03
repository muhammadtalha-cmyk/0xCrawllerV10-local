from __future__ import annotations

import asyncio
import json
import urllib.request
from pathlib import Path
from typing import Any, Callable, Awaitable, Dict, List
from ..base import BaseModule

TAKEOVER_SIGNATURES = [
    {
        "provider": "GitHub Pages",
        "cname_keywords": ["github.io"],
        "body_fingerprints": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
    },
    {
        "provider": "AWS S3 Bucket",
        "cname_keywords": ["s3.amazonaws.com", "s3-website"],
        "body_fingerprints": ["The specified bucket does not exist", "NoSuchBucket"],
    },
    {
        "provider": "Heroku",
        "cname_keywords": ["herokudns.com", "herokuapp.com"],
        "body_fingerprints": ["no-such-app", "No such app", "herokucdn.com/error-pages/no-such-app.html"],
    },
    {
        "provider": "Zendesk",
        "cname_keywords": ["zendesk.com"],
        "body_fingerprints": ["Help Center Closed", "this help center no longer exists"],
    },
    {
        "provider": "Fastly CDN",
        "cname_keywords": ["fastly.net"],
        "body_fingerprints": ["Fastly error: unknown domain"],
    },
    {
        "provider": "Shopify",
        "cname_keywords": ["myshopify.com"],
        "body_fingerprints": ["Sorry, this shop is currently unavailable"],
    },
    {
        "provider": "Ghost",
        "cname_keywords": ["ghost.io"],
        "body_fingerprints": ["The thing you were looking for is no longer here"],
    },
    {
        "provider": "Bitbucket",
        "cname_keywords": ["bitbucket.io"],
        "body_fingerprints": ["Repository not found"],
    },
    {
        "provider": "Surge.sh",
        "cname_keywords": ["surge.sh"],
        "body_fingerprints": ["project not found"],
    },
    {
        "provider": "Microsoft Azure",
        "cname_keywords": ["azurewebsites.net", "cloudapp.net"],
        "body_fingerprints": ["404 Web Site not found"],
    },
]


class SubdomainTakeoverModule(BaseModule):
    id = "takeover"
    name = "Subdomain Takeover Analysis"
    description = "Audit CNAME records against dangling cloud services (AWS S3, GitHub Pages, Heroku, Zendesk, etc.) with active takeover verification."
    category = "Infrastructure Hygiene"
    icon = "🎯"

    async def run(
        self,
        job_id: str,
        target: str,
        output_dir: Path,
        update_progress: Callable[[int, str], Awaitable[None]],
    ) -> dict[str, Any]:
        await update_progress(10, "Generating candidate hostnames...")

        host = target.strip().lower()
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0].split(":", 1)[0]

        log_file = output_dir / "execution.log"
        with open(log_file, "a") as f:
            f.write(f"=== Subdomain Takeover Analysis Job: {job_id} ===\nTarget Host: {host}\n\n")

        candidates = [
            host,
            f"www.{host}",
            f"blog.{host}",
            f"dev.{host}",
            f"app.{host}",
            f"api.{host}",
            f"status.{host}",
            f"help.{host}",
            f"support.{host}",
            f"docs.{host}",
            f"shop.{host}",
            f"staging.{host}",
        ]

        await update_progress(25, f"Resolving CNAME records for {len(candidates)} hostnames...")

        dnsx_cmd = ["docker", "run", "--rm", "-i", "projectdiscovery/dnsx:latest", "-cname", "-json"]
        proc = await asyncio.create_subprocess_exec(
            *dnsx_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdin_text = "\n".join(candidates) + "\n"
        stdout_data, _ = await proc.communicate(input=stdin_text.encode())
        raw_output = stdout_data.decode(errors="ignore") if stdout_data else ""

        with open(log_file, "a") as f:
            f.write(raw_output)

        await update_progress(60, "Cross-referencing CNAME pointers against cloud signatures...")

        cname_records: List[Dict[str, Any]] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
                h = rec.get("host")
                cnames = rec.get("cname", [])
                if h and cnames:
                    for cn in cnames:
                        cname_records.append({"host": h, "cname": cn})
            except Exception:
                continue

        if not cname_records:
            cname_records.append({"host": host, "cname": "No CNAME (Direct A Record)"})

        await update_progress(75, "Performing active verification on matched pointers...")

        analyzed_items: List[Dict[str, Any]] = []
        vulnerable_count = 0

        for item in cname_records:
            h = item["host"]
            cn = item["cname"]
            matched_provider = None
            is_vulnerable = False
            evidence = "Valid / Active CNAME"

            if cn != "No CNAME (Direct A Record)":
                for sig in TAKEOVER_SIGNATURES:
                    if any(kw in cn.lower() for kw in sig["cname_keywords"]):
                        matched_provider = sig["provider"]
                        try:
                            req = urllib.request.Request(
                                f"http://{h}",
                                headers={"User-Agent": "Mozilla/5.0 (0xCrawller Security Engine)"},
                            )
                            with urllib.request.urlopen(req, timeout=5) as resp:
                                body = resp.read().decode(errors="ignore")
                                if any(fp.lower() in body.lower() for fp in sig["body_fingerprints"]):
                                    is_vulnerable = True
                                    evidence = f"Dangling {matched_provider} signature confirmed in HTTP response!"
                                else:
                                    evidence = f"CNAME matches {matched_provider}, but target responded without dangling error."
                        except urllib.error.HTTPError as e:
                            err_body = e.read().decode(errors="ignore")
                            if any(fp.lower() in err_body.lower() for fp in sig["body_fingerprints"]):
                                is_vulnerable = True
                                evidence = f"Dangling {matched_provider} signature found in HTTP {e.code} error body!"
                            else:
                                evidence = f"HTTP {e.code} from {matched_provider} (no confirmed dangling string)"
                        except Exception as ex:
                            evidence = f"Connection to {matched_provider} pointer timed out or failed ({ex})"
                        break

            if is_vulnerable:
                vulnerable_count += 1
                status = "VULNERABLE"
            elif matched_provider:
                status = "INFORMATIONAL"
            else:
                status = "SECURE"

            analyzed_items.append({
                "subdomain": h,
                "cname": cn,
                "provider": matched_provider or "Direct / Private Infrastructure",
                "status": status,
                "evidence": evidence,
            })

        await update_progress(100, "Takeover audit completed.")

        results = {
            "module": self.id,
            "target": target,
            "job_id": job_id,
            "total_checked": len(candidates),
            "cnames_found": len([x for x in analyzed_items if x["cname"] != "No CNAME (Direct A Record)"]),
            "vulnerable_count": vulnerable_count,
            "overall_status": "CRITICAL RISK" if vulnerable_count > 0 else "SECURE",
            "items": analyzed_items,
        }

        return results
