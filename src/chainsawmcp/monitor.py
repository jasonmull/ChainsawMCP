"""Detached hunt runner for ChainsawMCP.

Invoked as: python -m chainsawmcp.monitor <job_id> <payload_json>

Three modes detected by payload type / keys:
  list                   → direct chainsaw command (legacy; EVTX dir already prepared)
  dict, "evidence_path"  → single source; monitor stages then runs
  dict, "evidence_paths" → bulk; monitor stages all sources, runs chainsaw once

EVTXs are staged under <job_dir>/evtx/<source_stem>/ so they persist alongside
hunt results. Chainsaw is pointed at <job_dir>/evtx/ and finds all sources
recursively. No temp dirs or cleanup needed.
"""

import hashlib
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
    case_dir = os.environ.get("CHAINSAWMCP_CASE_DIR")
    base = Path(case_dir) if case_dir else Path.cwd()
    return base / "analysis" / job_id


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

    body = json.dumps({"content": msg, "text": msg, **payload}).encode("utf-8")
    req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=15) as resp:
            resp.read()
    except Exception as e:
        jdir = _job_dir(payload.get("job_id", "unknown"))
        try:
            (jdir / "webhook_error.log").write_text(
                f"Webhook POST failed: {type(e).__name__}: {e}\nURL: {url}\n", encoding="utf-8"
            )
        except OSError:
            pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _chainsaw_version(binary: str) -> str:
    try:
        result = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=10
        )
        return (result.stdout or result.stderr).strip().splitlines()[0]
    except Exception:
        return "unknown"


def _write_provenance(job_id: str, cmd: list[str], results_file: Path, completed_at: str) -> None:
    """Write chainsaw_provenance.json to the job directory for chain-of-custody."""
    provenance = {
        "command": cmd,
        "output_file": str(results_file),
        "output_sha256": _sha256(results_file),
        "completed_at": completed_at,
        "chainsaw_version": _chainsaw_version(cmd[0]),
    }
    prov_file = results_file.parent / "chainsaw_provenance.json"
    try:
        prov_file.write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    except OSError:
        pass


def _classify_error(stderr: str, returncode: int) -> str:
    """Map common Chainsaw failure patterns to actionable suggested fixes."""
    s = stderr.lower()
    if "mapping" in s and any(p in s for p in ("not found", "missing", "no such file", "required")):
        return "Mapping file missing — run setup_environment or set CHAINSAW_MAPPING"
    if "sigma" in s and any(p in s for p in ("not found", "no such file", "failed to read", "no sigma", "0 sigma")):
        return "Sigma rules not found — run setup_environment or set CHAINSAW_SIGMA"
    if any(p in s for p in ("command not found", "no such file or directory")) and any(b in s for b in ("chainsaw", cmd_name)):
        return "Chainsaw binary not found — run setup_environment"
    if any(p in s for p in ("no evtx", "no .evtx", "0 evtx", "found 0")):
        return "No EVTX files found at the specified path — verify evidence path"
    if "rules" in s and any(p in s for p in ("not found", "no such file", "0 rules")):
        return "Chainsaw rules not found — run setup_environment or set CHAINSAW_RULES"
    if returncode != 0:
        return "Chainsaw exited with an error — inspect stderr field for details"
    return "Hunt failed unexpectedly — check chainsaw_stderr.log in the job directory"


cmd_name = "chainsaw"  # module-level fallback for _classify_error


def _fail_job(job_id: str, error: str, exit_code: int | None = None, stderr: str = "") -> None:
    completed_at = _now()
    suggested_fix = _classify_error(stderr, exit_code or -1) if stderr or exit_code else error
    data = _read_job(job_id)
    data.update({
        "status": "error",
        "error": error,
        "exit_code": exit_code,
        "suggested_fix": suggested_fix,
        "completed_at": completed_at,
        "hit_count": 0,
        "rules_triggered": 0,
    })
    _write_job(job_id, data)
    webhook_url = os.environ.get("CHAINSAWMCP_WEBHOOK_URL")
    if webhook_url:
        _post_webhook(webhook_url, {
            "job_id": job_id, "status": "error", "hit_count": 0,
            "rules_triggered": 0, "completed_at": completed_at, "error": error,
        })


def _stage_source(source_path: str, dest: Path, job_id: str) -> "tuple[bool, str]":
    """Stage one evidence source into dest. Returns (success, error_message)."""
    from chainsawmcp.evidence import stage_evtx

    try:
        stage_evtx(Path(source_path), dest)
    except Exception as e:
        return False, f"Staging failed for {source_path}: {e}"

    evtx_count = len(list(dest.rglob("*.evtx")))
    if evtx_count == 0:
        return False, f"No .evtx files found after staging {source_path} → {dest}"

    return True, ""


def _build_chainsaw_cmd(evtx_root: Path, config: dict) -> "list[str] | None":
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
        return None

    return _build_command(evtx_root, rules, sigma, mapping, extra_args)


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

    jdir = _job_dir(job_id)
    results_file = _results_path(job_id)
    log_file = jdir / "chainsaw_stderr.log"

    if isinstance(payload, list):
        # Legacy direct-command mode (EVTX dir, already prepared externally)
        cmd: list[str] | None = payload
    else:
        # Evidence-prep mode: stage to job_dir/evtx/<source_stem>/
        evtx_root = jdir / "evtx"
        evtx_root.mkdir(parents=True, exist_ok=True)

        evidence_paths: list[str] = (
            payload.get("evidence_paths")
            or [payload["evidence_path"]]
        )

        data = _read_job(job_id)
        data["status"] = "preparing"
        data["evtx_path"] = str(evtx_root)
        _write_job(job_id, data)

        staging_errors: list[str] = []
        staging_log = jdir / "staging_errors.log"

        for ep in evidence_paths:
            stem = Path(ep).stem
            dest = evtx_root / stem
            dest.mkdir(parents=True, exist_ok=True)
            ok, err = _stage_source(ep, dest, job_id)
            if not ok:
                staging_errors.append(err)
                print(f"[ChainsawMCP] STAGING ERROR (continuing): {err}", file=sys.stderr, flush=True)
                try:
                    with staging_log.open("a", encoding="utf-8") as slh:
                        slh.write(f"[{_now()}] {err}\n")
                except OSError:
                    pass

        if staging_errors:
            # Persist errors into job.json so load_hunt_results can surface them
            data = _read_job(job_id)
            data["staging_errors"] = staging_errors
            _write_job(job_id, data)

        total_evtx = len(list(evtx_root.rglob("*.evtx")))
        if total_evtx == 0:
            all_errs = "\n".join(staging_errors) or "No .evtx files staged from any source"
            _fail_job(job_id, f"All sources failed to stage — no EVTXs available:\n{all_errs}")
            return

        data = _read_job(job_id)
        data["status"] = "running"
        data["evtx_count"] = total_evtx
        _write_job(job_id, data)

        cmd = _build_chainsaw_cmd(evtx_root, payload)
        if cmd is None:
            _fail_job(job_id, "Sigma rules require a mapping file. Set CHAINSAW_MAPPING or pass mapping_path.")
            return

    # Record PID
    data = _read_job(job_id)
    data["runner_pid"] = os.getpid()
    _write_job(job_id, data)

    returncode = -1
    error_detail = ""
    try:
        with results_file.open("w", encoding="utf-8") as out_fh, \
             log_file.open("w", encoding="utf-8") as err_fh:
            proc = subprocess.run(cmd, stdout=out_fh, stderr=err_fh, stdin=subprocess.DEVNULL)
            returncode = proc.returncode
    except FileNotFoundError:
        error_detail = f"Chainsaw binary not found: {cmd[0]}"
    except Exception as e:
        error_detail = f"{type(e).__name__}: {e}"

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
        exit_code_final = returncode
        suggested_fix = None
        _write_provenance(job_id, cmd, results_file, completed_at)
    else:
        hit_count, rules_triggered = 0, 0
        status = "error"
        error = error_detail or "No results produced"
        exit_code_final = returncode
        stderr_text = ""
        try:
            stderr_text = log_file.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            pass
        suggested_fix = _classify_error(stderr_text, returncode)

    data = _read_job(job_id)
    data.update({
        "status": status,
        "hit_count": hit_count,
        "rules_triggered": rules_triggered,
        "completed_at": completed_at,
        "error": error,
        "exit_code": exit_code_final,
        "suggested_fix": suggested_fix,
    })
    _write_job(job_id, data)

    webhook_url = os.environ.get("CHAINSAWMCP_WEBHOOK_URL")
    if webhook_url:
        webhook_payload = {
            "job_id": job_id, "status": status,
            "hit_count": hit_count, "rules_triggered": rules_triggered,
            "completed_at": completed_at,
        }
        if error:
            webhook_payload["error"] = error
        _post_webhook(webhook_url, webhook_payload)


if __name__ == "__main__":
    main()
