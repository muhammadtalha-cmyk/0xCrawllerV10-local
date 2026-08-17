from __future__ import annotations

import json
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .docker_runner import run_command


def _extract_version_product(value: Any, path: str = "") -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            next_path = f"{path}.{key}" if path else str(key)
            lower = str(key).lower()
            if isinstance(nested, (str, int, float)) and any(token in lower for token in ("version", "product", "server", "implementation", "software", "release")):
                text = str(nested).strip()
                if text and len(text) <= 500:
                    found.append({"field": next_path, "value": text})
            found.extend(_extract_version_product(nested, next_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            found.extend(_extract_version_product(nested, f"{path}[{index}]"))
    return found


def _normalise_record(module: str, target_rows: list[dict[str, Any]], row: dict[str, Any]) -> dict[str, Any]:
    domain = str(row.get("domain") or "").lower()
    ip = str(row.get("ip") or "")
    match = next((target for target in target_rows if target["host"] == domain and (not ip or not target.get("ip") or target.get("ip") == ip)), None)
    if match is None and len(target_rows) == 1:
        match = target_rows[0]
    data = row.get("data") or {}
    module_data = data.get(module) if isinstance(data, dict) else None
    if module_data is None and isinstance(data, dict) and len(data) == 1:
        module_data = next(iter(data.values()))
    module_data = module_data if isinstance(module_data, dict) else {}
    result = module_data.get("result") if isinstance(module_data.get("result"), dict) else module_data
    status = module_data.get("status") or row.get("status")
    extracted = _extract_version_product(result)
    return {
        "service_id": (match or {}).get("service_id"),
        "asset_id": (match or {}).get("asset_id"),
        "host": (match or {}).get("host") or domain,
        "ip": ip or (match or {}).get("ip"),
        "port": (match or {}).get("port"),
        "protocol": (match or {}).get("protocol") or "tcp",
        "module": module,
        "status": status,
        "success": str(status).lower() in {"success", "application_error"},
        "version_product_fields": extracted,
        "result": result,
        "source": "zgrab2",
    }


def _run_module(image: str, module: str, targets: list[dict[str, Any]], timeout: int) -> dict[str, Any]:
    lines: list[str] = []
    for target in targets:
        ip = target.get("ip") or ""
        host = target.get("host") or ""
        port = target.get("port") or ""
        lines.append(f"{ip},{host},{module},{port}")
    execution = run_command(["docker", "run", "--rm", "-i", image, module], stdin_text="\n".join(lines) + "\n", timeout=timeout)
    records: list[dict[str, Any]] = []
    for line in str(execution.get("stdout") or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            records.append(_normalise_record(module, targets, row))
    return {
        "module": module,
        "targets": len(targets),
        "records": records,
        "execution": {key: value for key, value in execution.items() if key not in {"stdout"}},
        "stderr_tail": str(execution.get("stderr") or "")[-4000:],
    }


def run_zgrab2(targets: list[dict[str, Any]], *, image: str, workers: int, timeout: int) -> dict[str, Any]:
    if not targets:
        return {"status": "SKIPPED", "reason": "no_network_service_targets", "records": [], "modules": [], "tool": "zgrab2"}
    by_module: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for target in targets:
        by_module[str(target.get("zgrab2_module") or "banner")].append(target)
    modules: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(by_module)))) as pool:
        futures = [pool.submit(_run_module, image, module, rows, timeout) for module, rows in by_module.items()]
        for future in as_completed(futures):
            modules.append(future.result())
    modules.sort(key=lambda item: item["module"])
    records = [record for module in modules for record in module["records"]]
    any_ok = any(module["execution"].get("ok") for module in modules)
    all_ok = all(module["execution"].get("ok") for module in modules)
    return {
        "status": "COMPLETE" if all_ok else ("PARTIAL" if any_ok or records else "FAILED"),
        "tool": "zgrab2",
        "image": image,
        "targets": len(targets),
        "modules": modules,
        "records": records,
    }
