"""Detached hunt runner for ChainsawMCP.

Invoked as: python -m chainsawmcp.monitor <job_id> <payload_json>

Two modes detected by payload type:
  list  → direct chainsaw command (legacy mode, used for EVTX dirs)
  dict  → evidence-prep mode: {"evidence_path": "...", "rules": "...", ...}
           The monitor prepares evidence (including slow E01 extraction) and
           then runs Chainsaw, so the MCP tool call returns immediately.

Runs as a fully detached process. Updates job.json and POSTs a webhook on completion.
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    """POST hunt completion to a webhook."""
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
        **payload,
    }).encode("utf-8")

    req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=15) as resp:
            resp.read()
    except Exception as e:
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


def _prepare_evidence_and_build_cmd(job_id: str, config: dict) -> "tuple[list[str] | None, object]":
    """Prepare evidence (possibly slow E01 extraction) and return (chainsaw_cmd, ev).

    Returns (None, None) on failure — job.json is updated with the error before returning.
    """
    from chainsawmcp.evidence import EvidenceError, prepare_evidence
    from chainsawmcp.chainsaw import _build_command
    from chainsawmcp.config import get_mapping_path, get_rules_path, get_sigma_path

    evidence_path = config["evidence_path"]

    data = _read_job(job_id)
    data["status"] = "preparing"
    _write_job(job_id, data)

    try:
        ev = prepare_evidence(evidence_path)
    except Exception as e:
        completed_at = _now()
        data = _read_job(job_id)
        data.update({"status": "error", "error": str(e), "completed_at": completed_at})
        _write_job(job_id, data)
        webhook_url = os.environ.get("CHAINSAWMCP_WEBHOOK_URL")
        if webhook_url:
            _post_webhook(webhook_url, {
                "job_id": job_id, "status": "error", "hit_count": 0,
                "rules_triggered": 0, "completed_at": completed_at, "error": str(e),
            })
        return None, None

    evtx_dir = ev.evtx_dir
    data = _read_job(job_id)
    data["evtx_path"] = str(evtx_dir)
    data["status"] = "running"
    _write_job(job_id, data)

    rules_str = config.get("rules")
    sigma_str = config.get("sigma")
    mapping_str = config.get("mapping")
    extra_args = config.get("extra_args") or []

    rules = Path(rules_str) if rules_str else get_rules_path()
    sigma = Path(sigma_str) if sigma_str else get_sigma_path()
    mapping = Path(mapping_str) if mapping_str else get_mapping_path()

    if sigma and not mapping:
        error = (
            "Sigma rules require a mapping file. "
            "Set CHAINSAW_MAPPING env var or pass mapping_path."
        )
        ev.cleanup()
        completed_at = _now()
        data = _read_job(job_id)
        data.update({"status": "error", "error": error, "completed_at": completed_at})
        _write_job(job_id, data)
        webhook_url = os.environ.get("CHAINSAWMCP_WEBHOOK_URL")
        if webhook_url:
            _post_webhook(webhook_url, {
                "job_id": job_id, "status": "error", "hit_count": 0,
                "rules_triggered": 0, "completed_at": completed_at, "error": error,
            })
        return None, None

    cmd = _build_command(evtx_dir, rules, sigma, mapping, extra_args)
    return cmd, ev


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python -m chainsawmcp.monitor <job_id> <payload_json>", file=sys.stderr)
        sys.exit(1)

    job_id = sys.argv[1]
    try:
        payload = json.loads(sys.argv[2])
    except (json.JSONDecodeError, IndexError) as e:
        print(f"Invalid payload JSON: {e}", file=sys.stderr)
        sys.exit(1)

    ev = None  # PreparedEvidence object to clean up after hunt

    if isinstance(payload, list):
        # Direct command mode (EVTX dir, already prepared)
        cmd: list[str] | None = payload
    else:
        # Evidence-prep mode (E01 or raw path — preparation happens here)
        cmd, ev = _prepare_evidence_and_build_cmd(job_id, payload)
        if cmd is None:
            return  # job already updated with error status

    jdir = _job_dir(job_id)
    results_file = _results_path(job_id)
    log_file = jdir / "chainsaw_stderr.log"

    # Record our own PID
    data = _read_job(job_id)
    data["runner_pid"] = os.getpid()
    _write_job(job_id, data)

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
    finally:
        if ev is not None:
            try:
                ev.cleanup()
            except Exception:
                pass

    completed_at = _now()

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
        webhook_payload = {
            "job_id": job_id,
            "status": status,
            "hit_count": hit_count,
            "rules_triggered": rules_triggered,
            "completed_at": completed_at,
        }
        if error:
            webhook_payload["error"] = error
        _post_webhook(webhook_url, webhook_payload)


if __name__ == "__main__":
    main()
