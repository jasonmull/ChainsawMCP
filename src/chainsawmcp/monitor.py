"""Completion monitor for detached Chainsaw hunts.

Invoked as: python -m chainsawmcp.monitor <job_id> <chainsaw_pid>

Blocks until the Chainsaw process exits, then updates job.json and
POSTs a webhook notification if CHAINSAWMCP_WEBHOOK_URL is set.
Uses only stdlib — no extra dependencies.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


def _job_dir(job_id: str) -> Path:
    # Inline the path logic to avoid importing config (which imports Path) in a detached process
    jobs_dir = os.environ.get("CHAINSAWMCP_JOBS_DIR")
    if jobs_dir:
        return Path(jobs_dir) / job_id
    import tempfile
    return Path(tempfile.gettempdir()) / "chainsawmcp_jobs" / job_id


def _job_file(job_id: str) -> Path:
    return _job_dir(job_id) / "job.json"


def _results_path(job_id: str) -> Path:
    return _job_dir(job_id) / "hunt_results.json"


def _read_job(job_id: str) -> dict:
    try:
        return json.loads(_job_file(job_id).read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_job(job_id: str, data: dict) -> None:
    try:
        _job_file(job_id).write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def _count_hits(job_id: str) -> tuple[int, int]:
    """Return (hit_count, rules_triggered) from the results file."""
    rpath = _results_path(job_id)
    try:
        raw = rpath.read_text(encoding="utf-8").strip()
    except OSError:
        return 0, 0
    if not raw:
        return 0, 0
    hits: list[dict] = []
    if raw.startswith("["):
        try:
            hits = json.loads(raw)
        except json.JSONDecodeError:
            pass
    else:
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
    rules: set[str] = set()
    for h in hits:
        name = h.get("name") or h.get("rule_name") or (h.get("document") or {}).get("name", "")
        if name:
            rules.add(str(name))
    return len(hits), len(rules)


def _wait_for_pid(pid: int) -> int:
    """Wait for a PID to exit. Returns exit code if available, else -1."""
    if sys.platform == "win32":
        import ctypes
        WAIT_INFINITE = 0xFFFFFFFF
        SYNCHRONIZE = 0x00100000
        handle = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, pid)
        if handle:
            ctypes.windll.kernel32.WaitForSingleObject(handle, WAIT_INFINITE)
            ctypes.windll.kernel32.CloseHandle(handle)
        return -1
    else:
        # We can't waitpid on a non-child process; poll instead.
        while True:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return -1
            except PermissionError:
                pass  # still alive, no permission to signal
            time.sleep(5)


def _post_webhook(url: str, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=10) as resp:
            resp.read()
    except URLError:
        pass


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python -m chainsawmcp.monitor <job_id> <chainsaw_pid>", file=sys.stderr)
        sys.exit(1)

    job_id = sys.argv[1]
    try:
        chainsaw_pid = int(sys.argv[2])
    except ValueError:
        print(f"Invalid PID: {sys.argv[2]}", file=sys.stderr)
        sys.exit(1)

    _wait_for_pid(chainsaw_pid)

    # Chainsaw has exited — determine success or failure
    rpath = _results_path(job_id)
    completed_at = datetime.now(timezone.utc).isoformat()

    if rpath.exists() and rpath.stat().st_size > 0:
        hit_count, rules_triggered = _count_hits(job_id)
        status = "complete"
        error = None
    else:
        # Check stderr log for an error message
        log = _job_dir(job_id) / "chainsaw_stderr.log"
        error = ""
        try:
            error = log.read_text(encoding="utf-8", errors="replace").strip()[-500:]
        except OSError:
            pass
        hit_count, rules_triggered = 0, 0
        status = "error"

    data = _read_job(job_id)
    data.update({
        "status": status,
        "hit_count": hit_count,
        "rules_triggered": rules_triggered,
        "completed_at": completed_at,
        "error": error,
    })
    _write_job(job_id, data)

    webhook_url = os.environ.get("CHAINSAWMCP_WEBHOOK_URL")
    if webhook_url:
        payload = {
            "job_id": job_id,
            "status": status,
            "hit_count": hit_count,
            "rules_triggered": rules_triggered,
            "completed_at": completed_at,
        }
        if error:
            payload["error"] = error
        _post_webhook(webhook_url, payload)


if __name__ == "__main__":
    main()
