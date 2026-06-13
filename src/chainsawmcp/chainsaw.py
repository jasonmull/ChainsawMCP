"""Subprocess wrapper for Chainsaw hunt."""

import asyncio
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import (
    get_chainsaw_binary,
    get_hunt_timeout,
    get_mapping_path,
    get_output_dir,
    get_rules_path,
    get_sigma_path,
    get_webhook_url,
)


class ChainsawError(Exception):
    pass


@dataclass
class HuntResult:
    hits: list[dict[str, Any]] = field(default_factory=list)
    output_file: Path | None = None


async def run_hunt_async(
    evtx_dir: Path,
    rules_path: Path | None = None,
    sigma_path: Path | None = None,
    mapping_path: Path | None = None,
    extra_args: list[str] | None = None,
) -> HuntResult:
    """Run `chainsaw hunt` without blocking the asyncio event loop."""
    return await asyncio.to_thread(
        run_hunt, evtx_dir, rules_path, sigma_path, mapping_path, extra_args
    )


def run_hunt(
    evtx_dir: Path,
    rules_path: Path | None = None,
    sigma_path: Path | None = None,
    mapping_path: Path | None = None,
    extra_args: list[str] | None = None,
) -> HuntResult:
    """Run `chainsaw hunt`, stream output to a file, and return parsed hits (blocking)."""
    rules = rules_path or get_rules_path()
    sigma = sigma_path or get_sigma_path()
    mapping = mapping_path or get_mapping_path()

    if sigma and not mapping:
        raise ChainsawError(
            "A mapping file is required when using Sigma rules. "
            "Provide mapping_path or set the CHAINSAW_MAPPING env var. "
            "Chainsaw ships mappings in mappings/sigma-event-logs-all.yml."
        )

    cmd = _build_command(evtx_dir, rules, sigma, mapping, extra_args or [])
    timeout = get_hunt_timeout()

    output_dir = get_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "hunt_results.json"

    # Stream stdout directly to a file — avoids pipe buffer exhaustion on large hunts.
    try:
        with output_file.open("w", encoding="utf-8") as fh:
            result = subprocess.run(
                cmd,
                stdout=fh,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
    except FileNotFoundError:
        binary = get_chainsaw_binary()
        raise ChainsawError(
            f"Chainsaw binary '{binary}' not found. "
            "Ensure it is on PATH or set CHAINSAW_BIN env var."
        )
    except subprocess.TimeoutExpired:
        raise ChainsawError(f"Chainsaw timed out after {timeout} seconds.")

    if result.returncode != 0:
        # Chainsaw often writes errors to stdout rather than stderr.
        # Read the output file for the actual message when stderr is empty.
        detail = (result.stderr or "").strip()
        if not detail:
            try:
                detail = output_file.read_text(encoding="utf-8", errors="replace").strip()[:500]
            except OSError:
                pass
        raise ChainsawError(
            f"Chainsaw exited with code {result.returncode}."
            + (f"\n{detail}" if detail else "")
        )

    hits = _parse_output_file(output_file)
    return HuntResult(hits=hits, output_file=output_file)


def _build_command(
    evtx_dir: "Path | list[Path]",
    rules_path: Path | None,
    sigma_path: Path | None,
    mapping_path: Path | None,
    extra_args: list[str],
) -> list[str]:
    binary = get_chainsaw_binary()
    if isinstance(evtx_dir, list):
        paths = [str(p) for p in evtx_dir]
    else:
        paths = [str(evtx_dir)]
    cmd = [str(binary), "hunt"] + paths + ["--json", "--skip-errors"]

    if rules_path:
        cmd += ["--rule", str(rules_path)]
    if sigma_path:
        cmd += ["--sigma", str(sigma_path)]
    if mapping_path:
        cmd += ["--mapping", str(mapping_path)]

    cmd += extra_args
    return cmd


def parse_output_file(path: Path) -> list[dict[str, Any]]:
    """Public alias for reading and parsing a Chainsaw JSON output file."""
    return _parse_output_file(path)


def _write_runner_payload(job_id: str, payload: "list | dict") -> None:
    """Persist the runner payload to <job_dir>/runner_payload.json with owner-only
    permissions, so evidence paths and arguments are not exposed in the process
    list (as they would be if passed on the monitor's command line)."""
    from .config import get_jobs_dir

    jdir = get_jobs_dir() / job_id
    jdir.mkdir(parents=True, exist_ok=True)
    pfile = jdir / "runner_payload.json"
    fd = os.open(str(pfile), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)


def spawn_hunt_detached(
    evtx_dir: Path,
    job_id: str,
    job_dir: Path,
    rules_path: Path | None = None,
    sigma_path: Path | None = None,
    mapping_path: Path | None = None,
    extra_args: list[str] | None = None,
) -> int:
    """Spawn the hunt runner as a detached process. Returns the runner PID.

    The runner (monitor.py) opens its own file handles and runs Chainsaw
    internally, avoiding Windows cross-process handle inheritance issues.
    """
    rules = rules_path or get_rules_path()
    sigma = sigma_path or get_sigma_path()
    mapping = mapping_path or get_mapping_path()

    if sigma and not mapping:
        raise ChainsawError(
            "A mapping file is required when using Sigma rules. "
            "Provide mapping_path or set the CHAINSAW_MAPPING env var. "
            "Chainsaw ships mappings in mappings/sigma-event-logs-all.yml."
        )

    cmd = _build_command(evtx_dir, rules, sigma, mapping, extra_args or [])

    detach: dict = (
        {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
        if sys.platform == "win32"
        else {"start_new_session": True}
    )

    _write_runner_payload(job_id, cmd)
    runner_cmd = [sys.executable, "-m", "chainsawmcp.monitor", job_id]

    runner = subprocess.Popen(
        runner_cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **detach,
    )
    return runner.pid


def spawn_detached_config(job_id: str, config: dict) -> int:
    """Spawn a detached monitor with an arbitrary config dict. Returns runner PID."""
    detach: dict = (
        {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
        if sys.platform == "win32"
        else {"start_new_session": True}
    )
    _write_runner_payload(job_id, config)
    runner = subprocess.Popen(
        [sys.executable, "-m", "chainsawmcp.monitor", job_id],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **detach,
    )
    return runner.pid


def spawn_detached_from_evidence(
    evidence_path: "str | Path",
    job_id: str,
    job_dir: Path,
    rules_path: Path | None = None,
    sigma_path: Path | None = None,
    mapping_path: Path | None = None,
    extra_args: list[str] | None = None,
) -> int:
    """Spawn a detached job that prepares evidence AND runs Chainsaw. Returns runner PID."""
    config: dict = {"evidence_path": str(evidence_path)}
    if rules_path:
        config["rules"] = str(rules_path)
    if sigma_path:
        config["sigma"] = str(sigma_path)
    if mapping_path:
        config["mapping"] = str(mapping_path)
    if extra_args:
        config["extra_args"] = extra_args

    detach: dict = (
        {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
        if sys.platform == "win32"
        else {"start_new_session": True}
    )

    _write_runner_payload(job_id, config)
    runner = subprocess.Popen(
        [sys.executable, "-m", "chainsawmcp.monitor", job_id],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **detach,
    )
    return runner.pid


def _parse_output_file(path: Path) -> list[dict[str, Any]]:
    """Read and parse Chainsaw's JSON output file."""
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return []
    return _parse_output(raw)


def _parse_output(raw: str) -> list[dict[str, Any]]:
    """Parse Chainsaw's JSON output, which may be a JSON array or newline-delimited objects."""
    if not raw:
        return []

    if raw.startswith("["):
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            pass

    hits: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, list):
                hits.extend(obj)
            elif isinstance(obj, dict):
                hits.append(obj)
        except json.JSONDecodeError:
            continue

    return hits
