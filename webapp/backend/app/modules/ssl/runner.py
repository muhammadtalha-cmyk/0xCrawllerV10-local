from __future__ import annotations

import asyncio
import datetime
import json
import socket
import ssl
from pathlib import Path
from typing import Any, Callable, Awaitable, Dict, List
from ..base import BaseModule


class SSLCertificateModule(BaseModule):
    id = "ssl"
    name = "SSL / TLS Inspector"
    description = "Audit X.509 certificate validity, expiration dates, days remaining, SANs, TLS protocol versions, and cipher suites."
    category = "Cryptography & TLS"
    icon = "🔒"

    async def run(
        self,
        job_id: str,
        target: str,
        output_dir: Path,
        update_progress: Callable[[int, str], Awaitable[None]],
    ) -> dict[str, Any]:
        await update_progress(10, "Initializing TLS handshake connection...")

        host = target.strip().lower()
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0].split(":", 1)[0]

        log_file = output_dir / "execution.log"
        with open(log_file, "a") as f:
            f.write(f"=== SSL / TLS Inspector Job: {job_id} ===\nTarget Host: {host}:443\n\n")

        await update_progress(30, f"Connecting to {host}:443 via TLS socket...")

        cert_data: Dict[str, Any] = {}
        error_msg = None

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    der_cert = ssock.getpeercert(binary_form=True)
                    tls_version = ssock.version()
                    cipher = ssock.cipher()

                    if not cert and der_cert:
                        try:
                            vctx = ssl.create_default_context()
                            with socket.create_connection((host, 443), timeout=8) as vsock:
                                with vctx.wrap_socket(vsock, server_hostname=host) as vssock:
                                    cert = vssock.getpeercert()
                        except Exception:
                            pass

                    subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
                    issuer = dict(x[0] for x in cert.get("issuer", [])) if cert else {}

                    not_after_str = cert.get("notAfter", "")
                    not_before_str = cert.get("notBefore", "")

                    days_remaining = None
                    cert_status = "Unknown"
                    if not_after_str:
                        try:
                            exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            now = datetime.datetime.utcnow()
                            diff = (exp_date - now).days
                            days_remaining = diff
                            if diff < 0:
                                cert_status = "Expired"
                            elif diff <= 30:
                                cert_status = "Expiring Soon"
                            else:
                                cert_status = "Valid"
                        except Exception:
                            pass

                    sans: List[str] = []
                    for item in cert.get("subjectAltName", []):
                        if item[0] == "DNS":
                            sans.append(item[1])

                    cert_data = {
                        "host": host,
                        "port": 443,
                        "subject_cn": subject.get("commonName", host),
                        "subject_org": subject.get("organizationName", ""),
                        "issuer_cn": issuer.get("commonName", "Unknown Issuer"),
                        "issuer_org": issuer.get("organizationName", ""),
                        "valid_from": not_before_str,
                        "valid_to": not_after_str,
                        "days_remaining": days_remaining,
                        "status": cert_status,
                        "sans": sans,
                        "sans_count": len(sans),
                        "tls_version": tls_version or "TLSv1.3",
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                        "serial_number": cert.get("serialNumber", ""),
                    }
        except Exception as ex:
            error_msg = str(ex)
            with open(log_file, "a") as f:
                f.write(f"TLS socket error: {ex}\n")

        await update_progress(70, "Parsing certificate metadata and cipher suites...")

        if not cert_data or not cert_data.get("subject_cn"):
            try:
                cmd = ["docker", "run", "--rm", "-i", "projectdiscovery/httpx:latest", "-tls-probe", "-tls-grab", "-json"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_data, _ = await proc.communicate(input=f"{host}\n".encode())
                for line in stdout_data.decode(errors="ignore").splitlines():
                    if line.strip().startswith("{") and "tls" in line:
                        obj = json.loads(line)
                        tls = obj.get("tls", {})
                        if tls:
                            cert_data["subject_cn"] = tls.get("subject_cn", host)
                            cert_data["issuer_cn"] = tls.get("issuer_cn", "Unknown")
                            cert_data["valid_to"] = tls.get("not_after", "")
                            cert_data["sans"] = tls.get("subject_an", [])
                            cert_data["sans_count"] = len(cert_data["sans"])
                            cert_data["tls_version"] = tls.get("tls_version", "TLSv1.3")
                            cert_data["cipher_suite"] = tls.get("cipher", "")
                            cert_data["status"] = "Valid"
                            break
            except Exception as e:
                with open(log_file, "a") as f:
                    f.write(f"Supplementary httpx probe error: {e}\n")

        await update_progress(100, "Certificate audit completed.")

        results = {
            "module": self.id,
            "target": target,
            "job_id": job_id,
            "host": host,
            "has_certificate": bool(cert_data),
            "certificate": cert_data,
            "error": error_msg if not cert_data else None,
        }

        return results
