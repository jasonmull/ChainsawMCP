"""Detached hunt runner for ChainsawMCP.

Invoked as: python -m chainsawmcp.monitor <job_id> <payload_json>

Three modes detected by payload type / keys:
  list                → direct chainsaw command (legacy; EVTX dir already prepared)
  dict, "evidence_path"  → single E01 / path; monitor prepares then runs
  dict, "evidence_paths" → bulk; monitor prepares all sources, runs chainsaw once

Runs as a fully detached process. Updates job.json and POSTs a webhook on completion.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
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
        "content": msg,
        "text": msg,
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


def _fail_job(job_id: str, error: str) -> None:
    completed_at = _now()
    data = _read_job(job_id)
    data.update({"status": "error", "error": error, "completed_at": completed_at,
                 "hit_count": 0, "rules_triggered": 0})
    _write_job(job_id, data)
    webhook_url = os.environ.get("CHAINSAWMCP_WEBHOOK_URL")
    if webhook_url:
        _post_webhook(webhook_url, {
            "job_id": job_id, "status": "error", "hit_count": 0,
            "rules_triggered": 0, "completed_at": completed_at, "error": error,
        })


def _prepare_one(evidence_path: str, job_id: str) -> "tuple[object | None, Path | None]":
    """Prepare a single evidence source. Returns (PreparedEvidence, evtx_dir) or (None, None) on failure."""
    from chainsawmcp.evidence import EvidenceError, prepare_evidence

    try:
        ev = prepare_evidence(evidence_path)
    except Exception as e:
        _fail_job(job_id, f"Evidence preparation failed for {evidence_path}: {e}")
        return None, None

    evtx_dir = ev.evtx_dir

    # Verify the staging directory actually exists and has files before proceeding.
    if not evtx_dir.exists():
        _fail_job(job_id, f"Staging directory missing after extraction: {evtx_dir}")
        ev.cleanup()
        return None, None

    evtx_files = list(evtx_dir.rglob("*.evtx"))
    if not evtx_files:
        _fail_job(job_id, f"No .evtx files in staging directory: {evtx_dir}")
        ev.cleanup()
        return None, None

    return ev, evtx_dir


def _build_chainsaw_cmd(evtx_dirs: "list[Path]", config: dict) -> "list[str] | None":
    """Build the chainsaw hunt command. Returns None (and fails the job) on config error."""
    from chainsawmcp.chainsaw import _build_command
    from chainsawmcp.config import get_mapping_path, get_rules_path, get_sigma_path

    rules_str = config.get("rules")
    sigma_str = config.get("sigma")
    mapping_str = config.get("mapping")
    extra_args = config.get("extra_args") or []

    rules = Path(rules_str) if rules_str else get_rules_path()
    sigma = Path(sigma_str) if sigma_str else get_sigma_path()
    mapping = Path(mapping_str) if mapping_str else get_mapping_path()

    if sigma and not mapping:
        return None  # caller handles error

    return _build_command(evtx_dirs, rules, sigma, mapping, extra_args)


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

    ev_objects: list = []   # PreparedEvidence objects to clean up after hunt
    cmd: list[str] | None = None

    if isinstance(payload, list):
        # Legacy direct-command mode (EVTX dir, already prepared)
        cmd = payload

    elif "evidence_paths" in payload:
        # Bulk mode: prepare multiple sources, run chainsaw once with all dirs
        evidence_paths: list[str] = payload["evidence_paths"]
        evtx_dirs: list[Path] = []

        data = _read_job(job_id)
        data["status"] = "preparing"
        _write_job(job_id, data)

        for ep in evidence_paths:
            ev, evtx_dir = _prepare_one(ep, job_id)
            if ev is None:
                # _prepare_one already failed the job; clean up what we have so far
                for done_ev in ev_objects:
                    try:
                        done_ev.cleanup()
                    except Exception:
                        pass
                return
            ev_objects.append(ev)
            evtx_dirs.append(evtx_dir)

        data = _read_job(job_id)
        data["status"] = "running"
        data["evtx_paths"] = [str(d) for d in evtx_dirs]
        _write_job(job_id, data)

        cmd = _build_chainsaw_cmd(evtx_dirs, payload)
        if cmd is None:
            error = "Sigma rules require a mapping file. Set CHAINSAW_MAPPING or pass mapping_path."
            for done_ev in ev_objects:
                try:
                    done_ev.cleanup()
                except Exception:
                    pass
            _fail_job(job_id, error)
            return

    else:
        # Single evidence-prep mode
        evidence_path: str = payload["evidence_path"]

        data = _read_job(job_id)
        data["status"] = "preparing"
        _write_job(job_id, data)

        ev, evtx_dir = _prepare_one(evidence_path, job_id)
        if ev is None:
            return  # _prepare_one already failed the job

        ev_objects.append(ev)

        data = _read_job(job_id)
        data["status"] = "running"
        data["evtx_path"] = str(evtx_dir)
        _write_job(job_id, data)

        cmd = _build_chainsaw_cmd([evtx_dir], payload)
        if cmd is None:
            error = "Sigma rules require a mapping file. Set CHAINSAW_MAPPING or pass mapping_path."
            ev.cleanup()
            _fail_job(job_id, error)
            return

    # Record our own PID
    data = _read_job(job_id)
    data["runner_pid"] = os.getpid()
    _write_job(job_id, data)

    jdir = _job_dir(job_id)
    results_file = _results_path(job_id)
    log_file = jdir / "chainsaw_stderr.log"

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
        for done_ev in ev_objects:
            try:
                done_ev.cleanup()
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
