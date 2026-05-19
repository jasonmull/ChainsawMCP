"""Subprocess wrapper for Chainsaw hunt."""

import asyncio
import json
import subprocess
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
                text=True,
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
        raise ChainsawError(
            f"Chainsaw exited with code {result.returncode}.\nstderr: {result.stderr}"
        )

    hits = _parse_output_file(output_file)
    return HuntResult(hits=hits, output_file=output_file)


def _build_command(
    evtx_dir: Path,
    rules_path: Path | None,
    sigma_path: Path | None,
    mapping_path: Path | None,
    extra_args: list[str],
) -> list[str]:
    binary = get_chainsaw_binary()
    cmd = [str(binary), "hunt", str(evtx_dir), "--json"]

    if rules_path:
        cmd += ["--rule", str(rules_path)]
    if sigma_path:
        cmd += ["--sigma", str(sigma_path)]
    if mapping_path:
        cmd += ["--mapping", str(mapping_path)]

    cmd += extra_args
    return cmd


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
