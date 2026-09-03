from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable, Awaitable, Dict, List
from ..base import BaseModule


class DNSHygieneModule(BaseModule):
    id = "dns_hygiene"
    name = "DNS & Email Security Hygiene"
    description = "Audit SPF, DMARC, MX mail exchanges, and CAA records to evaluate email spoofing and DNS security posture."
    category = "DNS & Email Hygiene"
    icon = "📑"

    async def run(
        self,
        job_id: str,
        target: str,
        output_dir: Path,
        update_progress: Callable[[int, str], Awaitable[None]],
    ) -> dict[str, Any]:
        await update_progress(10, "Initializing DNS intelligence queries...")

        host = target.strip().lower()
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0].split(":", 1)[0]

        log_file = output_dir / "execution.log"
        with open(log_file, "a") as f:
            f.write(f"=== DNS & Email Security Hygiene Job: {job_id} ===\nTarget Host: {host}\n\n")

        await update_progress(25, f"Querying TXT, MX, CAA, and NS records for {host}...")

        dnsx_cmd = ["docker", "run", "--rm", "-i", "projectdiscovery/dnsx:latest", "-recon", "-json"]
        proc = await asyncio.create_subprocess_exec(
            *dnsx_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        domain_input = f"{host}\n_dmarc.{host}\n"
        stdout_data, _ = await proc.communicate(input=domain_input.encode())
        raw_output = stdout_data.decode(errors="ignore") if stdout_data else ""

        with open(log_file, "a") as f:
            f.write(raw_output)

        await update_progress(60, "Parsing SPF and DMARC policies...")

        txt_records: List[str] = []
        dmarc_records: List[str] = []
        mx_records: List[str] = []
        caa_records: List[str] = []
        ns_records: List[str] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
                rec_host = record.get("host", "").lower()
                if rec_host == host:
                    txt_records.extend(record.get("txt", []))
                    mx_records.extend(record.get("mx", []))
                    caa_records.extend(record.get("caa", []))
                    ns_records.extend(record.get("ns", []))
                elif rec_host == f"_dmarc.{host}":
                    dmarc_records.extend(record.get("txt", []))
            except Exception:
                continue

        spf_record = None
        for txt in txt_records:
            if txt.strip().startswith("v=spf1"):
                spf_record = txt.strip()
                break

        dmarc_record = None
        for txt in dmarc_records:
            if "v=dmarc1" in txt.lower():
                dmarc_record = txt.strip()
                break

        if not dmarc_record:
            for txt in txt_records:
                if "v=dmarc1" in txt.lower():
                    dmarc_record = txt.strip()
                    break

        await update_progress(85, "Evaluating email spoofing resilience...")

        spf_status = "Missing"
        spf_mechanism = "None"
        if spf_record:
            spf_status = "Present"
            if "-all" in spf_record:
                spf_mechanism = "Hard Fail (-all) [Enforced]"
            elif "~all" in spf_record:
                spf_mechanism = "Soft Fail (~all) [Standard]"
            elif "?all" in spf_record:
                spf_mechanism = "Neutral (?all) [Weak]"
            elif "+all" in spf_record:
                spf_mechanism = "Allow All (+all) [Critical Vulnerability]"
            else:
                spf_mechanism = "Custom / Unspecified"

        dmarc_status = "Missing"
        dmarc_policy = "None"
        dmarc_rua = "None"
        if dmarc_record:
            dmarc_status = "Present"
            for part in dmarc_record.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    dmarc_policy = part.split("=")[1].strip().lower()
                elif part.lower().startswith("rua="):
                    dmarc_rua = part.split("=")[1].strip()

        if spf_status == "Present" and dmarc_policy in ("reject", "quarantine"):
            overall_grade = "A+" if dmarc_policy == "reject" else "A"
            security_posture = "Robust Email Protection (Spoofing Prevented)"
        elif spf_status == "Present" and dmarc_policy == "none":
            overall_grade = "B"
            security_posture = "Monitoring Only (Spoofing Possible)"
        elif spf_status == "Present" and dmarc_status == "Missing":
            overall_grade = "C"
            security_posture = "Weak Protection (SPF Only, No DMARC)"
        else:
            overall_grade = "F"
            security_posture = "Vulnerable to Direct Email Spoofing & Phishing"

        await update_progress(100, "DNS hygiene audit completed.")

        results = {
            "module": self.id,
            "target": target,
            "job_id": job_id,
            "host": host,
            "overall_grade": overall_grade,
            "security_posture": security_posture,
            "spf": {
                "status": spf_status,
                "record": spf_record,
                "mechanism": spf_mechanism,
            },
            "dmarc": {
                "status": dmarc_status,
                "record": dmarc_record,
                "policy": dmarc_policy,
                "reporting_rua": dmarc_rua,
            },
            "mx_records": [{"server": m, "priority": idx + 1} for idx, m in enumerate(mx_records)],
            "caa_records": caa_records,
            "name_servers": ns_records,
        }

        return results
