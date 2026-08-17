"""Docker execution, process logging, worker selection, and target validation."""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import json
import os
import re
import shutil
import signal
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional, Sequence

from .models import ToolResult

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
EXPLICIT_WARNING_RE = re.compile(
    r"^(?:\[[^\]]*\]\s*)?(?:warn(?:ing)?|soft[- ]?fail|i/o timeout|timeout)\b",
    re.IGNORECASE,
)
EXPLICIT_ERROR_RE = re.compile(
    r"^(?:\[[^\]]*\]\s*)?(?:error|fatal|panic|failed|failure|refused|invalid(?:\s+value)?)\b",
    re.IGNORECASE,
)
SECRET_FLAGS = {
    "-H", "--header", "-header", "--token", "-token", "--api-key", "-api-key",
    "--password", "-password", "--secret", "-secret",
}
VERSION_ARGS = {
    "subfinder": ["-version"],
    "amass": ["-version"],
    "bbot": ["--version"],
    "gobuster": ["--version"],
    "katana": ["-version"],
    "dnsx": ["-version"],
    "httpx": ["-version"],
    "wafw00f": ["--version"],
    "naabu": ["-version"],
    "nmap": ["--version"],
}


def _clean_log_line(line: str) -> str:
    return ANSI_RE.sub("", str(line)).strip()


def detect_diagnostics(tool_name: str, stdout: str, stderr: str, limit: int = 20) -> tuple[list[str], list[str]]:
    """Extract explicit diagnostics without treating findings/URLs as warnings."""
    warnings: list[str] = []
    errors: list[str] = []

    # Most tools emit findings to stdout. Only explicit severity lines are parsed there.
    candidates = [("stdout", line) for line in stdout.splitlines()] + [("stderr", line) for line in stderr.splitlines()]
    for stream, raw_line in candidates:
        clean = _clean_log_line(raw_line)
        if not clean:
            continue

        # Structured records are findings unless they explicitly report failure.
        if clean.startswith("{") and clean.endswith("}"):
            try:
                obj = json.loads(clean)
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict):
                if obj.get("failed") is True or str(obj.get("error") or "").strip():
                    message = str(obj.get("error") or clean)[:500]
                    warnings.append(message)
                continue

        lower = clean.lower()
        if "setup soft-failed" in lower or "no api key set" in lower:
            warnings.append(clean[:500])
        elif "[timeout]" in lower or EXPLICIT_WARNING_RE.search(clean):
            warnings.append(clean[:500])
        elif EXPLICIT_ERROR_RE.search(clean):
            errors.append(clean[:500])
        elif stream == "stderr" and any(token in lower for token in ("i/o timeout", "connection refused")):
            warnings.append(clean[:500])

        if len(warnings) >= limit and len(errors) >= limit:
            break

    # Preserve order while deduplicating.
    warnings = list(dict.fromkeys(warnings))[:limit]
    errors = list(dict.fromkeys(errors))[:limit]
    return warnings, errors


def _actionable_failure_lines(stdout: str, stderr: str, limit: int = 10) -> list[str]:
    """Recover useful CLI errors even when a tool writes them to the wrong stream."""
    lines: list[str] = []
    for text in (stderr, stdout):
        for raw_line in text.splitlines():
            clean = _clean_log_line(raw_line)
            if not clean or clean.startswith(("http://", "https://", "{")):
                continue
            lines.append(clean[:500])
            if len(lines) >= limit:
                return list(dict.fromkeys(lines))
    return list(dict.fromkeys(lines))


def redact_command(command: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False
    for value in command:
        if hide_next:
            redacted.append("<redacted>")
            hide_next = False
            continue
        text = str(value)
        redacted.append(text)
        if text in SECRET_FLAGS:
            hide_next = True
    return redacted


def detect_warnings(stdout: str, stderr: str, limit: int = 20) -> list[str]:
    """Backward-compatible wrapper."""
    warnings, errors = detect_diagnostics("unknown", stdout, stderr, limit)
    return (warnings + errors)[:limit]


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def sanitize_domain(domain: str) -> str:
    value = domain.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0].split(":")[0].rstrip(".")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}", value):
        raise ValueError(f"Invalid target domain: {domain!r}")
    if any(not label or label.startswith("-") or label.endswith("-") for label in value.split(".")):
        raise ValueError(f"Invalid target domain: {domain!r}")
    return value


def docker_available() -> bool:
    return shutil.which("docker") is not None


def resolve_auto_workers(value: str, max_requested: bool = False) -> int:
    cpu = os.cpu_count() or 2
    raw = "auto" if value is None else str(value).strip().lower()
    if raw in {"all", "max"}:
        return max(2, int(cpu))
    if raw == "auto":
        return max(2, min(int(cpu), 6 if max_requested else 4))
    try:
        return max(1, int(raw))
    except ValueError as exc:
        raise ValueError("--workers must be an integer, 'auto', 'max', or 'all'") from exc


def volume_arg(host_dir: Path, container_dir: str = "/output") -> str:
    return f"{str(host_dir.resolve())}:{container_dir}"


def _inject_container_name(cmd: Sequence[str], name: str) -> tuple[list[str], str | None]:
    command = list(cmd)
    if len(command) < 2 or command[0:2] != ["docker", "run"]:
        return command, None
    if "--name" in command:
        index = command.index("--name")
        return command, command[index + 1] if index + 1 < len(command) else None
    safe = re.sub(r"[^a-z0-9_.-]+", "-", name.lower()).strip("-")[:40] or "tool"
    container_name = f"smartrecon-{safe}-{uuid.uuid4().hex[:8]}"
    command[2:2] = ["--name", container_name]
    return command, container_name


def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _remove_container(container_name: str | None) -> None:
    if not container_name:
        return
    try:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except Exception:
        pass


def run_cmd(
    name: str,
    cmd: Sequence[str],
    logs_dir: Path,
    timeout: int,
    stdin_text: Optional[str] = None,
    metadata: Optional[dict[str, object]] = None,
) -> ToolResult:
    stdout_path = logs_dir / f"{name}.stdout.txt"
    stderr_path = logs_dir / f"{name}.stderr.txt"
    logs_dir.mkdir(parents=True, exist_ok=True)
    command, container_name = _inject_container_name(cmd, name)
    started = time.monotonic()
    proc: subprocess.Popen[str] | None = None
    try:
        popen_kwargs: dict[str, object] = {
            "stdin": subprocess.PIPE if stdin_text is not None else None,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "errors": "replace",
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(command, **popen_kwargs)  # type: ignore[arg-type]
        stdout, stderr = proc.communicate(input=stdin_text, timeout=timeout)
        stdout = stdout or ""
        stderr = stderr or ""
        stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
        stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
        warnings, errors = detect_diagnostics(name, stdout, stderr)
        if proc.returncode != 0 and not errors:
            errors = _actionable_failure_lines(stdout, stderr)
        result_metadata = dict(metadata or {})
        safe_command = redact_command(command)
        result_metadata.update({
            "timeout_seconds": timeout,
            "container_name": container_name,
            "command_argv": safe_command,
            "command_copyable": subprocess.list2cmdline(safe_command),
        })
        return ToolResult(
            name=name,
            ok=proc.returncode == 0,
            returncode=int(proc.returncode or 0),
            seconds=time.monotonic() - started,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            warnings=warnings,
            errors=errors,
            timed_out=False,
            metadata=result_metadata,
        )
    except subprocess.TimeoutExpired as exc:
        _remove_container(container_name)
        if proc is not None:
            _terminate_process_tree(proc)
            try:
                stdout_tail, stderr_tail = proc.communicate(timeout=5)
            except Exception:
                stdout_tail, stderr_tail = "", ""
        else:
            stdout_tail, stderr_tail = "", ""
        stdout = str(exc.stdout or "") + str(stdout_tail or "")
        stderr = str(exc.stderr or "") + str(stderr_tail or "") + f"\n[TIMEOUT] {name} exceeded {timeout}s\n"
        stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
        stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
        warnings, errors = detect_diagnostics(name, stdout, stderr)
        result_metadata = dict(metadata or {})
        safe_command = redact_command(command)
        result_metadata.update({
            "timeout_seconds": timeout,
            "container_name": container_name,
            "command_argv": safe_command,
            "command_copyable": subprocess.list2cmdline(safe_command),
        })
        return ToolResult(
            name=name,
            ok=False,
            returncode=124,
            seconds=time.monotonic() - started,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            warnings=warnings,
            errors=errors,
            timed_out=True,
            metadata=result_metadata,
        )
    except Exception as exc:  # pragma: no cover - defensive process boundary
        _remove_container(container_name)
        if proc is not None:
            _terminate_process_tree(proc)
        stdout_path.write_text("", encoding="utf-8")
        stderr = f"[ERROR] {type(exc).__name__}: {exc}\n"
        stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
        warnings, errors = detect_diagnostics(name, "", stderr)
        result_metadata = dict(metadata or {})
        safe_command = redact_command(command)
        result_metadata.update({
            "timeout_seconds": timeout,
            "container_name": container_name,
            "command_argv": safe_command,
            "command_copyable": subprocess.list2cmdline(safe_command),
        })
        return ToolResult(
            name=name,
            ok=False,
            returncode=1,
            seconds=time.monotonic() - started,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            warnings=warnings,
            errors=errors,
            timed_out=False,
            metadata=result_metadata,
        )


def run_parallel(
    tasks: list[tuple[str, list[str], Optional[str]] | tuple[str, list[str], Optional[str], dict[str, object]]],
    logs_dir: Path,
    timeout: int,
    workers: int,
) -> list[ToolResult]:
    if not tasks:
        return []
    results: list[ToolResult] = []
    max_workers = max(1, min(workers, len(tasks)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for task in tasks:
            if len(task) == 3:
                name, cmd, stdin = task
                metadata = None
            else:
                name, cmd, stdin, metadata = task
            futures[executor.submit(run_cmd, name, cmd, logs_dir, timeout, stdin, metadata)] = name
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            print(
                f"    [{result.name}] status={result.status} "
                f"seconds={result.seconds:.1f} returncode={result.returncode}"
            )
    return results


def docker_image_exists(image: str) -> bool:
    proc = subprocess.run(
        ["docker", "image", "inspect", image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def _image_status_one(name: str, image: str, logs_dir: Path, pull_missing: bool) -> tuple[str, bool]:
    if docker_image_exists(image):
        return name, True
    if not pull_missing:
        return name, False
    print(f"[+] Pulling missing Docker image: {image}")
    result = run_cmd(f"docker_pull_{name}", ["docker", "pull", image], logs_dir, timeout=1800)
    return name, result.ok and docker_image_exists(image)


def ensure_images(
    images: dict[str, str],
    logs_dir: Path,
    pull_missing: bool = True,
    workers: int = 4,
) -> dict[str, bool]:
    status: dict[str, bool] = {}
    max_workers = max(1, min(workers, len(images)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_image_status_one, name, image, logs_dir, pull_missing)
            for name, image in images.items()
        ]
        for future in concurrent.futures.as_completed(futures):
            name, ok = future.result()
            status[name] = ok
    return status



def ensure_local_image(
    *,
    image: str,
    context_dir: Path,
    logs_dir: Path,
    timeout: int = 1800,
    build_name: str = "docker_build_local_image",
) -> ToolResult | None:
    """Build a pinned local Docker image once, returning the build result.

    ``None`` means the image already existed. The caller can inspect
    :func:`docker_image_exists` afterward to decide whether an optional stage is
    available.
    """
    if docker_image_exists(image):
        return None
    dockerfile = context_dir / "Dockerfile"
    if not dockerfile.exists():
        raise FileNotFoundError(f"Dockerfile not found: {dockerfile}")
    print(f"[+] Building local Docker image: {image}")
    return run_cmd(
        build_name,
        ["docker", "build", "--pull", "-t", image, str(context_dir.resolve())],
        logs_dir,
        timeout=timeout,
        metadata={"image": image, "context_dir": str(context_dir.resolve())},
    )

def inspect_tool_images(images: dict[str, str]) -> dict[str, dict[str, object]]:
    """Capture immutable image identity, entrypoint, and the installed tool version."""
    manifest: dict[str, dict[str, object]] = {}
    for name, image in images.items():
        record: dict[str, object] = {"image": image, "exists": docker_image_exists(image)}
        if not record["exists"]:
            manifest[name] = record
            continue
        try:
            inspected = subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=30,
            )
            values = json.loads(inspected.stdout)[0]
            record.update({
                "image_id": values.get("Id"),
                "created": values.get("Created"),
                "entrypoint": (values.get("Config") or {}).get("Entrypoint"),
            })
        except Exception as exc:
            record["inspect_error"] = f"{type(exc).__name__}: {exc}"
        version_args = VERSION_ARGS.get(name, ["--version"])
        version_command = ["docker", "run", "--rm", image, *version_args]
        try:
            version = subprocess.run(
                version_command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=120,
            )
            output = "\n".join(
                line for line in (version.stdout + "\n" + version.stderr).splitlines()
                if _clean_log_line(line)
            )
            record.update({
                "version_command": version_command,
                "version_returncode": version.returncode,
                "version_output": _clean_log_line(output)[:4000],
            })
        except Exception as exc:
            record["version_error"] = f"{type(exc).__name__}: {exc}"
        manifest[name] = record
    return manifest
