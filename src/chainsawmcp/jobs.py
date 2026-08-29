"""Disk-persisted job state for detached Chainsaw hunts."""

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import get_jobs_dir
from .chainsaw import _parse_output_file


def _new_job_dir(job_id: str) -> Path:
    """Directory for a job id this process just generated. Never client input."""
    return get_jobs_dir() / job_id


def _job_dir(job_id: str) -> Path:
    """Resolve an existing job's directory by matching the on-disk listing.

    job_id reaches here from load_hunt_results, which takes it straight from the MCP
    client, so it is untrusted — and the server feeds adversary-authored event log text
    to an LLM that can call these tools, so it is reachable by prompt injection, not
    just by the analyst.

    The caller's string is therefore only ever *compared*; the returned path is built
    from the directory entry itself, so an untrusted value never reaches a path join.
    That is a stronger guarantee than a containment check, and it also rejects ids for
    jobs that do not exist. Guarding this one function covers read_job, results_path,
    log_path, provenance_path and load_job_results at once.
    """
    if not job_id or not isinstance(job_id, str):
        raise ValueError("A job_id is required.")
    jobs_dir = get_jobs_dir()
    if jobs_dir.is_dir():
        for entry in jobs_dir.iterdir():
            if entry.is_dir() and entry.name == job_id:
                return entry
    raise ValueError(f"No such job {job_id!r} in {jobs_dir}.")


def _job_file(job_id: str) -> Path:
    return _job_dir(job_id) / "job.json"


def create_job(evidence_path: "str | Path") -> str:
    job_id = uuid.uuid4().hex[:8]
    # _new_job_dir, not _job_dir: this id was generated here and its directory does
    # not exist yet, so there is nothing to match against the listing.
    jdir = _new_job_dir(job_id)
    jdir.mkdir(parents=True, exist_ok=True)
    _write_job(job_id, {
        "job_id": job_id,
        "evidence_path": str(evidence_path),
        "evtx_path": None,
        "started_at": _now(),
        "status": "running",
        "pid": None,
        "monitor_pid": None,
        "hit_count": None,
        "rules_triggered": None,
        "completed_at": None,
        "error": None,
        "exit_code": None,
        "suggested_fix": None,
        "attempt": _count_prior_failures(str(evidence_path)) + 1,
    })
    return job_id


def _count_prior_failures(evidence_path: str) -> int:
    """Count prior failed jobs for the same evidence path — used to set attempt counter."""
    jobs_dir = get_jobs_dir()
    if not jobs_dir.exists():
        return 0
    count = 0
    for jfile in jobs_dir.glob("*/job.json"):
        try:
            data = json.loads(jfile.read_text(encoding="utf-8"))
            if data.get("evidence_path") == evidence_path and data.get("status") == "error":
                count += 1
        except Exception:
            pass
    return count


def update_job(job_id: str, **fields: Any) -> None:
    data = read_job(job_id) or {}
    data.update(fields)
    _write_job(job_id, data)


def read_job(job_id: str) -> dict | None:
    jfile = _job_file(job_id)
    try:
        return json.loads(jfile.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def results_path(job_id: str) -> Path:
    return _job_dir(job_id) / "hunt_results.json"


def log_path(job_id: str) -> Path:
    return _job_dir(job_id) / "chainsaw_stderr.log"


def provenance_path(job_id: str) -> Path:
    return _job_dir(job_id) / "chainsaw_provenance.json"


def read_provenance(job_id: str) -> dict | None:
    """Return the chain-of-custody record for *job_id*, or None if unreadable.

    Written by monitor.py alongside hunt_results.json: the exact command, Chainsaw
    version, binary and output SHA-256, and UTC completion time.
    """
    if not job_id:
        return None
    try:
        pfile = provenance_path(job_id)
    except ValueError:
        return None  # unknown or malformed job id — no provenance to report
    if not pfile.exists():
        return None
    try:
        return json.loads(pfile.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def get_latest_completed_job() -> str | None:
    jobs_dir = get_jobs_dir()
    if not jobs_dir.exists():
        return None
    best_time: str | None = None
    best_id: str | None = None
    for jfile in jobs_dir.glob("*/job.json"):
        try:
            data = json.loads(jfile.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("status") == "complete" and data.get("completed_at"):
            t = data["completed_at"]
            if best_time is None or t > best_time:
                best_time = t
                best_id = data.get("job_id")
    return best_id


def load_job_results(job_id: str) -> list[dict]:
    return _parse_output_file(results_path(job_id))


def is_pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        import ctypes
        SYNCHRONIZE = 0x00100000
        handle = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, pid)
        if handle == 0:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    else:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # process exists but we can't signal it


def _write_job(job_id: str, data: dict) -> None:
    _job_file(job_id).write_text(json.dumps(data, indent=2), encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
