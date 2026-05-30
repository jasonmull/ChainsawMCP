"""Detached hunt runner for ChainsawMCP.

Invoked as: python -m chainsawmcp.monitor <job_id> <chainsaw_cmd_json>

Runs as a fully detached process. Opens output files itself (avoiding
Windows cross-process handle inheritance issues), executes Chainsaw
blocking, updates job.json, and POSTs a webhook on completion.
Uses only stdlib — no extra dependencies.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


def _job_dir(job_id: str) -> Path:
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
    if not hits:
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


def _post_webhook(url: str, payload: dict) -> None:
    """POST hunt completion to a webhook.

    Sends a human-readable message in both 'content' (Discord) and 'text'
    (Slack) fields, plus raw data fields for generic webhook receivers.
    """
    status = payload.get("status", "unknown")
    job_id = payload.get("job_id", "?")
    hit_count = payload.get("hit_count", 0)
    rules = payload.get("rules_triggered", 0)
    completed_at = payload.get("completed_at", "")
    error = payload.get("error")

    if status == "complete":
        msg = (
            f"✅ ChainsawMCP hunt complete (job {job_id})\n"
            f"Hits: {hit_count} across {rules} rules\n"
            f"Completed: {completed_at}\n"
            f"Call load_hunt_results() in your MCP session to begin analysis."
        )
    else:
        msg = (
            f"❌ ChainsawMCP hunt failed (job {job_id})\n"
            f"Error: {error or 'unknown'}"
        )

    body = json.dumps({
        "content": msg,   # Discord
        "text": msg,      # Slack
        **payload,        # raw fields for generic receivers
    }).encode("utf-8")

    req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=15) as resp:
            resp.read()
    except Exception as e:
        # Write failure to job log so it's visible
        job_id_str = payload.get("job_id", "unknown")
        jobs_dir = os.environ.get("CHAINSAWMCP_JOBS_DIR")
        if jobs_dir:
            log = Path(jobs_dir) / job_id_str / "webhook_error.log"
        else:
            import tempfile
            log = Path(tempfile.gettempdir()) / "chainsawmcp_jobs" / job_id_str / "webhook_error.log"
        try:
            log.write_text(f"Webhook POST failed: {type(e).__name__}: {e}\nURL: {url}\n", encoding="utf-8")
        except OSError:
            pass


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python -m chainsawmcp.monitor <job_id> <chainsaw_cmd_json>", file=sys.stderr)
        sys.exit(1)

    job_id = sys.argv[1]
    try:
        cmd: list[str] = json.loads(sys.argv[2])
    except (json.JSONDecodeError, IndexError) as e:
        print(f"Invalid command JSON: {e}", file=sys.stderr)
        sys.exit(1)

    jdir = _job_dir(job_id)
    results_file = _results_path(job_id)
    log_file = jdir / "chainsaw_stderr.log"

    # Record our own PID so the MCP server can find us
    data = _read_job(job_id)
    data["runner_pid"] = os.getpid()
    _write_job(job_id, data)

    # Run Chainsaw — file handles opened here, in this process, so no inheritance issues
    returncode = -1
    error_detail = ""
    try:
        with results_file.open("w", encoding="utf-8") as out_fh, \
             log_file.open("w", encoding="utf-8") as err_fh:
            proc = subprocess.run(
                cmd,
                stdout=out_fh,
                stderr=err_fh,
                stdin=subprocess.DEVNULL,
            )
            returncode = proc.returncode
    except FileNotFoundError:
        error_detail = f"Chainsaw binary not found: {cmd[0]}"
    except Exception as e:
        error_detail = f"{type(e).__name__}: {e}"

    completed_at = datetime.now(timezone.utc).isoformat()

    if not error_detail and returncode != 0:
        try:
            error_detail = log_file.read_text(encoding="utf-8", errors="replace").strip()[-500:]
        except OSError:
            error_detail = f"Chainsaw exited with code {returncode}"

    if not error_detail and results_file.exists() and results_file.stat().st_size > 0:
        hit_count, rules_triggered = _count_hits(job_id)
        status = "complete"
        error = None
    else:
        hit_count, rules_triggered = 0, 0
        status = "error"
        error = error_detail or "No results produced"

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
