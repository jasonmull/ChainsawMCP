"""MCP server entry point — exposes Chainsaw tools over the Model Context Protocol."""

import asyncio
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .chainsaw import ChainsawError, HuntResult, run_hunt_async, spawn_detached_config, spawn_detached_from_evidence, spawn_hunt_detached
from .config import get_http_host, get_http_port, get_jobs_dir, get_output_dir, is_windows
from .evidence import EvidenceError, PreparedEvidence
from .evidence import prepare_evidence as _stage_evidence
from .jobs import (
    create_job,
    get_latest_completed_job,
    is_pid_alive,
    load_job_results,
    read_job,
    results_path,
    update_job,
)
from .report import format_summary, format_summary_json, get_detections_json, write_full_report
from .report import get_detections as _filter_detections

mcp = FastMCP("ChainsawMCP")


class _SessionState:
    """Module-level session state for a single analysis session."""
    evidence: PreparedEvidence | None = None
    hits: list[dict] = []
    output_file: str = ""
    report_file: str = ""
    evidence_path: str = ""
    hunt_status: str = "idle"   # idle | running | done | error
    hunt_started_at: float | None = None
    hunt_finished_at: float | None = None
    hunt_error: str = ""
    _hunt_task: asyncio.Task | None = None


state = _SessionState()


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def prepare_evidence(path: str) -> str:
    """Mounts an E01 image and stages EVTXs synchronously.

    WARNING: large E01 images take 3-5 minutes and may hit MCP timeouts —
    prefer start_hunt or start_bulk_hunt which handle preparation in the background.
    Use prepare_evidence only if you need to inspect the staging directory before hunting.
    """
    path = path.strip()
    if not path:
        raise ValueError("'path' argument is required.")

    if state.hunt_status == "running":
        raise ValueError("A hunt is currently running. Wait for it to finish before re-staging evidence.")

    if state.evidence:
        state.evidence.cleanup()

    try:
        ev = _stage_evidence(path)
    except EvidenceError as e:
        raise ValueError(str(e)) from e
    except Exception as e:
        raise ValueError(f"Unexpected error preparing evidence: {type(e).__name__}: {e}") from e

    state.evidence = ev
    state.hits = []
    state.output_file = ""
    state.report_file = ""
    state.evidence_path = path
    state.hunt_status = "idle"
    state.hunt_started_at = None
    state.hunt_finished_at = None
    state.hunt_error = ""

    evtx_count = len(list(ev.evtx_dir.rglob("*.evtx")))
    return (
        f"Evidence prepared.\n"
        f"  Source : {path}\n"
        f"  EVTX files staged: {evtx_count}\n"
        f"  Staging dir: {ev.evtx_dir}\n\n"
        f"Next step: call start_hunt('{ev.evtx_dir}') to begin the hunt."
    )


@mcp.tool()
async def start_hunt(
    path: str,
    rules_path: str = "",
    sigma_path: str = "",
    mapping_path: str = "",
    extra_args: list[str] | None = None,
) -> str:
    """Start a Chainsaw hunt against an EVTX directory or E01 image.

    Returns immediately — Chainsaw runs as a fully detached process and cannot time out.
    A webhook POST is sent to CHAINSAWMCP_WEBHOOK_URL when the hunt finishes.
    Once notified, call load_hunt_results() then chainsaw_report to begin analysis.
    """
    path = path.strip()
    if not path:
        raise ValueError("'path' argument is required.")

    rules = Path(rules_path) if rules_path else None
    sigma = Path(sigma_path) if sigma_path else None
    mapping = Path(mapping_path) if mapping_path else None
    extra = extra_args or []

    p = Path(path)

    if p.is_dir():
        evtx_files = list(p.rglob("*.evtx"))
        if not evtx_files:
            raise ValueError(f"No .evtx files found under {path}")
        job_id = create_job(path)
        jdir = get_jobs_dir() / job_id
        try:
            runner_pid = spawn_hunt_detached(
                p, job_id, jdir,
                rules_path=rules, sigma_path=sigma,
                mapping_path=mapping, extra_args=extra,
            )
        except ChainsawError as e:
            update_job(job_id, status="error", error=str(e))
            raise ValueError(str(e)) from e
        update_job(job_id, pid=runner_pid, evtx_path=str(p))
        evtx_count: int | None = len(evtx_files)
    else:
        if not p.exists():
            raise ValueError(f"Path does not exist: {path}")
        job_id = create_job(path)
        jdir = get_jobs_dir() / job_id
        config: dict = {"evidence_path": path}
        if rules:
            config["rules"] = str(rules)
        if sigma:
            config["sigma"] = str(sigma)
        if mapping:
            config["mapping"] = str(mapping)
        if extra:
            config["extra_args"] = extra
        runner_pid = spawn_detached_config(job_id, config)
        update_job(job_id, pid=runner_pid)
        evtx_count = None

    from .config import get_webhook_url
    webhook_note = (
        "A webhook POST will be sent to your configured URL when the hunt finishes."
        if get_webhook_url()
        else "No webhook configured — set CHAINSAWMCP_WEBHOOK_URL to receive a notification."
    )

    evtx_line = f"  EVTX files: {evtx_count}\n" if evtx_count is not None else ""
    staging_line = f"  EVTXs staging to: {jdir / 'evtx'}\n" if evtx_count is None else ""
    return (
        f"Hunt started (job ID: {job_id}).\n"
        f"  Evidence : {path}\n"
        f"{evtx_line}"
        f"{staging_line}"
        f"  Runner PID: {runner_pid}\n"
        f"  Results will be written to: {jdir / 'hunt_results.json'}\n"
        f"  {webhook_note}\n\n"
        "IMPORTANT: Chainsaw is now running as a fully independent background process.\n"
        "Do NOT call hunt_status or load_hunt_results yet — the hunt is not done.\n"
        "Tell the user the hunt is running and that they will be notified when it finishes.\n"
        "When the webhook fires or the user returns to ask for results, call load_hunt_results()."
    )


@mcp.tool()
async def start_bulk_hunt(
    paths: list[str],
    rules_path: str = "",
    sigma_path: str = "",
    mapping_path: str = "",
    extra_args: list[str] | None = None,
) -> str:
    """Start Chainsaw hunts against multiple E01 images or EVTX directories in one call.

    Spawns one independent background job per path and returns all job IDs immediately —
    no MCP timeout possible. Each hunt fires a webhook when done.
    Call load_hunt_results(job_id=...) for each job to load results for analysis.
    """
    if not paths:
        raise ValueError("'paths' must be a non-empty list of evidence paths.")

    errors = []
    valid_paths = []
    for path in paths:
        p = Path(path)
        if not p.exists():
            errors.append(f"  SKIP {path} — path does not exist")
        else:
            valid_paths.append(path)

    if not valid_paths:
        lines = ["No valid evidence paths provided."] + errors
        raise ValueError("\n".join(lines))

    rules = Path(rules_path) if rules_path else None
    sigma = Path(sigma_path) if sigma_path else None
    mapping = Path(mapping_path) if mapping_path else None
    extra = extra_args or []

    job_id = create_job(f"bulk:{','.join(valid_paths)}")
    jdir = get_jobs_dir() / job_id
    update_job(job_id, evidence_paths=valid_paths)

    config: dict = {"evidence_paths": valid_paths}
    if rules:
        config["rules"] = str(rules)
    if sigma:
        config["sigma"] = str(sigma)
    if mapping:
        config["mapping"] = str(mapping)
    if extra:
        config["extra_args"] = extra

    runner_pid = spawn_detached_config(job_id, config)
    update_job(job_id, pid=runner_pid)

    from .config import get_webhook_url
    webhook_note = (
        "A webhook POST will be sent to your configured URL when the hunt finishes."
        if get_webhook_url()
        else "No webhook configured — set CHAINSAWMCP_WEBHOOK_URL to receive a notification."
    )

    source_lines = "\n".join(f"    {p}" for p in valid_paths)
    lines = [
        f"Bulk hunt started (job ID: {job_id}).",
        f"  Sources ({len(valid_paths)}): \n{source_lines}",
        f"  Runner PID: {runner_pid}",
        f"  Results will be written to: {jdir / 'hunt_results.json'}",
        f"  {webhook_note}",
        "",
        "All sources will be prepared and analyzed in a single Chainsaw run.",
        "IMPORTANT: This is a fully independent background process — do NOT poll.",
        "When the webhook fires, call load_hunt_results() to load the combined results.",
    ]
    if errors:
        lines += ["", "Skipped (not found):"] + errors

    return "\n".join(lines)


@mcp.tool()
async def load_hunt_results(job_id: str = "") -> str:
    """Load results from a completed detached hunt into the session for analysis.

    If job_id is omitted, loads the most recently completed hunt automatically.
    Call chainsaw_report and get_detections after this.
    """
    job_id = job_id.strip() or None  # type: ignore[assignment]

    if job_id is None:
        job_id = get_latest_completed_job()
        if job_id is None:
            jobs_dir = get_jobs_dir()
            running = []
            if jobs_dir.exists():
                import json as _json
                for jf in jobs_dir.glob("*/job.json"):
                    try:
                        d = _json.loads(jf.read_text(encoding="utf-8"))
                        if d.get("status") == "running":
                            running.append(d.get("job_id", "?"))
                    except Exception:
                        pass
            if running:
                raise ValueError(
                    f"No completed hunts found. Hunt(s) still running: {', '.join(running)}.\n"
                    "Wait for the webhook notification, then call load_hunt_results() again."
                )
            raise ValueError("No completed hunt results found. Run start_hunt to begin a hunt.")

    job = read_job(job_id)
    if job is None:
        raise ValueError(f"Job '{job_id}' not found in {get_jobs_dir()}.")

    status = job.get("status")
    if status == "running":
        pid = job.get("pid")
        if pid and is_pid_alive(pid):
            raise ValueError(
                f"Job {job_id} is still running (PID {pid}). "
                "Wait for the webhook notification, then call load_hunt_results() again."
            )
    elif status == "error":
        raise ValueError(f"Job {job_id} failed: {job.get('error', 'unknown error')}")

    rpath = results_path(job_id)
    if not rpath.exists() or rpath.stat().st_size == 0:
        raise ValueError(f"Results file for job {job_id} is empty or missing: {rpath}")

    hits = load_job_results(job_id)
    state.hits = hits
    state.output_file = str(rpath)
    state.hunt_status = "done"
    state.hunt_started_at = None
    state.hunt_finished_at = None
    state.hunt_error = ""
    state.evidence_path = job.get("evidence_path") or job.get("evtx_path") or ""

    completed_at = job.get("completed_at", "unknown time")
    hit_count = len(hits)
    rules_triggered = job.get("rules_triggered") or len({
        str(h.get("name") or h.get("rule_name") or (h.get("document") or {}).get("name", ""))
        for h in hits if h
    })

    # Include provenance record so it travels with findings into Claude's context.
    # This is the chain-of-custody anchor: proof that hits came from Chainsaw,
    # not from AI inference.
    provenance_lines = ""
    prov_path = rpath.parent / "chainsaw_provenance.json"
    if prov_path.exists():
        try:
            import json as _json
            prov = _json.loads(prov_path.read_text(encoding="utf-8"))
            provenance_lines = (
                "\nProvenance (chain of custody):\n"
                f"  Command  : {' '.join(prov.get('command', []))}\n"
                f"  Output   : {prov.get('output_file')}\n"
                f"  SHA-256  : {prov.get('output_sha256')}\n"
                f"  Chainsaw : {prov.get('chainsaw_version')}\n"
            )
        except Exception:
            pass

    return (
        f"Loaded {hit_count} hit(s) from job {job_id}.\n"
        f"  Rules triggered: {rules_triggered}\n"
        f"  Completed: {completed_at}\n"
        f"{provenance_lines}\n"
        "Call chainsaw_report for a structured summary, or get_detections to drill into specific rules."
    )


@mcp.tool()
async def chainsaw_report(output_format: str = "text") -> str:
    """Write the full hunt report to disk and return a summary with severity breakdown
    and top detections. Call after load_hunt_results.
    Use get_detections to drill into specific rules.

    output_format: 'text' (default, human-readable) or 'json' (structured, for orchestration).
    JSON output includes severity breakdown and top rules as a machine-readable object.
    """
    if state.hunt_status == "running":
        raise ValueError("Hunt is still running. Call hunt_status to check progress.")

    if state.hunt_status != "done":
        raise ValueError("No completed hunt results. Call load_hunt_results first.")

    report_file = write_full_report(
        state.hits,
        evtx_path=state.evidence_path,
        output_dir=get_output_dir(),
    )
    state.report_file = str(report_file)

    if output_format == "json":
        import json
        result = format_summary_json(
            state.hits, evtx_path=state.evidence_path, report_file=report_file
        )
        return json.dumps(result, indent=2)

    return format_summary(state.hits, evtx_path=state.evidence_path, report_file=report_file)


@mcp.tool()
async def get_detections(
    rule: str = "",
    severity: str = "",
    limit: int = 25,
    output_format: str = "text",
    page: int = 1,
    page_size: int = 25,
) -> str:
    """Return individual events from the completed hunt, optionally filtered by rule name
    (substring match) or severity level. Use this to investigate specific detections
    after chainsaw_report shows the summary.

    output_format: 'text' (default, human-readable) or 'json' (structured, paginated).
    When output_format='json', use page/page_size for pagination instead of limit.
    JSON output is suitable for automated orchestration — each page is a manageable
    token-bounded batch of hits.
    """
    if state.hunt_status != "done":
        raise ValueError("No completed hunt results. Call load_hunt_results first.")

    if output_format == "json":
        import json
        result = get_detections_json(
            state.hits,
            rule=rule or None,
            severity=severity or None,
            page=page,
            page_size=page_size,
        )
        return json.dumps(result, indent=2)

    return _filter_detections(
        state.hits,
        rule=rule or None,
        severity=severity or None,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# Legacy inline-hunt helpers (not registered as MCP tools)
# ---------------------------------------------------------------------------

async def _chainsaw_hunt(args: dict) -> str:
    if not state.evidence:
        raise ValueError("No evidence staged. Call prepare_evidence first.")

    if state.hunt_status == "running":
        elapsed = time.time() - (state.hunt_started_at or time.time())
        raise ValueError(
            f"A hunt is already running ({_fmt_elapsed(elapsed)}). "
            "Call hunt_status to check progress."
        )

    rules = Path(args["rules_path"]) if args.get("rules_path") else None
    sigma = Path(args["sigma_path"]) if args.get("sigma_path") else None
    mapping = Path(args["mapping_path"]) if args.get("mapping_path") else None
    extra = args.get("extra_args") or []

    evtx_dir = state.evidence.evtx_dir
    evtx_count = len(list(evtx_dir.rglob("*.evtx")))

    state.hits = []
    state.output_file = ""
    state.report_file = ""
    state.hunt_status = "running"
    state.hunt_started_at = time.time()
    state.hunt_finished_at = None
    state.hunt_error = ""

    state._hunt_task = asyncio.create_task(
        _run_hunt_background(evtx_dir, rules, sigma, mapping, extra)
    )

    return (
        f"Hunt started against {evtx_count} EVTX file(s).\n"
        "Wait 60 seconds, then call hunt_status once to check progress.\n"
        "Do NOT poll hunt_status more than once per 60 seconds — Chainsaw is "
        "CPU-bound and the status will not change faster than that."
    )


async def _run_hunt_background(
    evtx_dir: Path,
    rules: "Path | None",
    sigma: "Path | None",
    mapping: "Path | None",
    extra: list,
) -> None:
    try:
        result: HuntResult = await run_hunt_async(
            evtx_dir, rules_path=rules, sigma_path=sigma,
            mapping_path=mapping, extra_args=extra,
        )
        state.hits = result.hits
        state.output_file = str(result.output_file) if result.output_file else ""
        state.hunt_status = "done"
    except ChainsawError as exc:
        state.hunt_error = str(exc)
        state.hunt_status = "error"
    finally:
        state.hunt_finished_at = time.time()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_elapsed(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    return f"{m}m {s}s"


def _hits_summary(hits: list[dict]) -> str:
    counts: dict[str, int] = {}
    for hit in hits:
        key = str(
            hit.get("name")
            or hit.get("rule_name")
            or hit.get("document", {}).get("name", "Unknown")
        )
        counts[key] = counts.get(key, 0) + 1

    lines = ["Top detections:"]
    for rule, count in sorted(counts.items(), key=lambda x: -x[1])[:10]:
        lines.append(f"  {count:>4}x  {rule}")
    if len(counts) > 10:
        lines.append(f"  ... and {len(counts) - 10} more rule(s)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(prog="chainsawmcp")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="Transport to use. 'streamable-http' exposes an HTTP endpoint for OpenWebUI. (default: stdio)",
    )
    args = parser.parse_args()

    if args.transport == "streamable-http":
        _run_http()
    else:
        _run_stdio()


def _run_stdio() -> None:
    mcp.run()


def _run_http() -> None:
    import contextlib
    from collections.abc import AsyncIterator

    import uvicorn
    from starlette.applications import Starlette
    from starlette.middleware.cors import CORSMiddleware
    from starlette.routing import Mount
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    host = get_http_host()
    port = get_http_port()

    session_manager = StreamableHTTPSessionManager(
        app=mcp._mcp_server,
        event_store=None,
        json_response=False,
    )

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    starlette_app = Starlette(
        lifespan=lifespan,
        routes=[Mount("/mcp", app=session_manager.handle_request)],
    )
    starlette_app = CORSMiddleware(
        starlette_app,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "DELETE"],
        expose_headers=["Mcp-Session-Id"],
    )

    print(f"ChainsawMCP listening on http://{host}:{port}/mcp")
    print("Add this URL to OpenWebUI: Admin → External Tools → Add Server (MCP Streamable HTTP)")
    if is_windows():
        print("  To change host/port (PowerShell): $env:CHAINSAWMCP_HOST='0.0.0.0'; $env:CHAINSAWMCP_PORT='8000'")
    else:
        print("  To change host/port: CHAINSAWMCP_HOST=0.0.0.0 CHAINSAWMCP_PORT=8000 chainsawmcp --transport streamable-http")

    if is_windows():
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    uvicorn.run(starlette_app, host=host, port=port)


if __name__ == "__main__":
    main()
