"""MCP server entry point — exposes Chainsaw tools over the Model Context Protocol."""

import asyncio
import time
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

from .chainsaw import ChainsawError, HuntResult, run_hunt_async, spawn_hunt_detached
from .config import get_http_host, get_http_port, get_jobs_dir, get_output_dir, is_windows
from .evidence import EvidenceError, PreparedEvidence, prepare_evidence
from .jobs import (
    create_job,
    get_latest_completed_job,
    is_pid_alive,
    load_job_results,
    read_job,
    results_path,
    update_job,
)
from .report import format_summary, get_detections, write_full_report

app = Server("ChainsawMCP")


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
# Tool catalogue
# ---------------------------------------------------------------------------

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="prepare_evidence",
            description=(
                "Mount an E01 forensic image or validate an EVTX directory and stage "
                "files for Chainsaw. Must be called before any other tool."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to an EVTX directory or .E01 image file.",
                    }
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="chainsaw_hunt",
            description=(
                "Start a Chainsaw hunt against staged EVTXs. Returns immediately — the hunt "
                "runs in the background. Call hunt_status to wait for results; it blocks up to "
                "60 seconds per call and returns as soon as the hunt finishes. "
                "Call chainsaw_report once hunt_status reports 'done'."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "rules_path": {
                        "type": "string",
                        "description": "Path to Chainsaw rules directory (overrides CHAINSAW_RULES env var).",
                    },
                    "sigma_path": {
                        "type": "string",
                        "description": "Path to Sigma rules directory (overrides CHAINSAW_SIGMA env var).",
                    },
                    "mapping_path": {
                        "type": "string",
                        "description": "Path to mapping file for Sigma rules, e.g. mappings/sigma-event-logs-all.yml (overrides CHAINSAW_MAPPING env var). Required when using sigma_path.",
                    },
                    "extra_args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Extra arguments passed verbatim to chainsaw hunt.",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="hunt_status",
            description=(
                "Wait for the background Chainsaw hunt to finish. Blocks up to 60 seconds "
                "per call and returns as soon as the hunt completes or the window expires. "
                "Call repeatedly until status is 'done', then call chainsaw_report."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="chainsaw_report",
            description=(
                "Write the full hunt report to disk and return a concise summary with severity "
                "breakdown and top detections. Call after hunt_status reports 'done'. "
                "Use get_detections to drill into specific rules."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="start_hunt",
            description=(
                "Start a Chainsaw hunt as a fully detached background process. "
                "Returns immediately — Chainsaw keeps running even if this MCP session closes. "
                "A webhook POST is sent to CHAINSAWMCP_WEBHOOK_URL when the hunt finishes. "
                "Call load_hunt_results (with no arguments) once notified, then chainsaw_report. "
                "Use this instead of chainsaw_hunt for large evidence sets (> 1 GB)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to an EVTX directory or .E01 image file.",
                    },
                    "rules_path": {
                        "type": "string",
                        "description": "Path to Chainsaw rules directory (overrides CHAINSAW_RULES).",
                    },
                    "sigma_path": {
                        "type": "string",
                        "description": "Path to Sigma rules directory (overrides CHAINSAW_SIGMA).",
                    },
                    "mapping_path": {
                        "type": "string",
                        "description": "Path to Sigma mapping file (overrides CHAINSAW_MAPPING). Required when using sigma_path.",
                    },
                    "extra_args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Extra arguments passed verbatim to chainsaw hunt.",
                    },
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="load_hunt_results",
            description=(
                "Load results from a completed detached hunt into the session for analysis. "
                "If job_id is omitted, loads the most recently completed hunt automatically. "
                "Call chainsaw_report and get_detections after this."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "job_id": {
                        "type": "string",
                        "description": "Job ID returned by start_hunt. Omit to load the latest completed hunt.",
                    }
                },
                "required": [],
            },
        ),
        Tool(
            name="get_detections",
            description=(
                "Return individual events from the completed hunt, optionally filtered by rule name "
                "(substring match) or severity level. Use this to investigate specific detections "
                "after chainsaw_report shows the summary."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "rule": {
                        "type": "string",
                        "description": "Filter events whose rule name contains this string (case-insensitive).",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by exact severity level, e.g. 'critical', 'high', 'medium', 'low'.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of events to return (default 25).",
                    },
                },
                "required": [],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
    handlers = {
        "prepare_evidence": _prepare_evidence,
        "start_hunt": _start_hunt,
        "load_hunt_results": _load_hunt_results,
        "chainsaw_hunt": _chainsaw_hunt,
        "hunt_status": _hunt_status,
        "chainsaw_report": _chainsaw_report,
        "get_detections": _get_detections,
    }
    handler = handlers.get(name)
    if handler is None:
        return _error(f"Unknown tool: {name}")
    return await handler(arguments)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def _prepare_evidence(args: dict) -> CallToolResult:
    path = args.get("path", "").strip()
    if not path:
        return _error("'path' argument is required.")

    if state.hunt_status == "running":
        return _error("A hunt is currently running. Wait for it to finish before re-staging evidence.")

    if state.evidence:
        state.evidence.cleanup()

    try:
        ev = prepare_evidence(path)
    except EvidenceError as e:
        return _error(str(e))
    except Exception as e:
        return _error(f"Unexpected error preparing evidence: {type(e).__name__}: {e}")

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
    return _ok(
        f"Evidence prepared.\n"
        f"  Source : {path}\n"
        f"  EVTX files staged: {evtx_count}\n"
        f"  Staging dir: {ev.evtx_dir}\n\n"
        "Next step: call chainsaw_hunt."
    )


async def _start_hunt(args: dict) -> CallToolResult:
    path = args.get("path", "").strip()
    if not path:
        return _error("'path' argument is required.")

    if state.hunt_status == "running":
        return _error("A hunt is currently running in this session. Wait for it to finish first.")

    # Prepare evidence (handles both EVTX dirs and E01 images)
    if state.evidence:
        state.evidence.cleanup()
    try:
        ev = prepare_evidence(path)
    except EvidenceError as e:
        return _error(str(e))
    except Exception as e:
        return _error(f"Unexpected error preparing evidence: {type(e).__name__}: {e}")

    state.evidence = ev
    state.evidence_path = path

    rules = Path(args["rules_path"]) if args.get("rules_path") else None
    sigma = Path(args["sigma_path"]) if args.get("sigma_path") else None
    mapping = Path(args["mapping_path"]) if args.get("mapping_path") else None
    extra = args.get("extra_args") or []

    evtx_dir = ev.evtx_dir
    evtx_count = len(list(evtx_dir.rglob("*.evtx")))

    # Create job record on disk before spawning
    job_id = create_job(evtx_dir)
    jdir = get_jobs_dir() / job_id

    try:
        chainsaw_pid, monitor_pid = spawn_hunt_detached(
            evtx_dir, job_id, jdir,
            rules_path=rules, sigma_path=sigma,
            mapping_path=mapping, extra_args=extra,
        )
    except ChainsawError as e:
        update_job(job_id, status="error", error=str(e))
        return _error(str(e))

    update_job(job_id, pid=chainsaw_pid, monitor_pid=monitor_pid)

    from .config import get_webhook_url
    webhook_note = (
        f"\nA webhook POST will be sent to your configured URL when the hunt finishes."
        if get_webhook_url()
        else "\nNo webhook configured — set CHAINSAWMCP_WEBHOOK_URL to receive a notification."
    )

    return _ok(
        f"Hunt started (job ID: {job_id}).\n"
        f"  Evidence : {path}\n"
        f"  EVTX files: {evtx_count}\n"
        f"  Chainsaw PID: {chainsaw_pid}\n"
        f"  Results will be written to: {jdir / 'hunt_results.json'}\n"
        f"{webhook_note}\n\n"
        "Chainsaw is running as a detached process — this MCP session can be closed.\n"
        "When the hunt completes, call load_hunt_results() (no arguments needed) to begin analysis."
    )


async def _load_hunt_results(args: dict) -> CallToolResult:
    job_id = args.get("job_id", "").strip() or None

    if job_id is None:
        job_id = get_latest_completed_job()
        if job_id is None:
            # Check if any job is still running
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
                return _error(
                    f"No completed hunts found. Hunt(s) still running: {', '.join(running)}.\n"
                    "Wait for the webhook notification, then call load_hunt_results() again."
                )
            return _error(
                "No completed hunt results found. Run start_hunt to begin a hunt."
            )

    job = read_job(job_id)
    if job is None:
        return _error(f"Job '{job_id}' not found in {get_jobs_dir()}.")

    status = job.get("status")
    if status == "running":
        # Check if the PID is still alive
        pid = job.get("pid")
        if pid and is_pid_alive(pid):
            return _error(
                f"Job {job_id} is still running (PID {pid}). "
                "Wait for the webhook notification, then call load_hunt_results() again."
            )
        # PID gone but status not updated — monitor may have been lost; try loading results
    elif status == "error":
        return _error(f"Job {job_id} failed: {job.get('error', 'unknown error')}")

    rpath = results_path(job_id)
    if not rpath.exists() or rpath.stat().st_size == 0:
        return _error(f"Results file for job {job_id} is empty or missing: {rpath}")

    hits = load_job_results(job_id)
    state.hits = hits
    state.output_file = str(rpath)
    state.hunt_status = "done"
    state.hunt_started_at = None
    state.hunt_finished_at = None
    state.hunt_error = ""

    completed_at = job.get("completed_at", "unknown time")
    hit_count = len(hits)
    rules_triggered = job.get("rules_triggered") or len({
        str(h.get("name") or h.get("rule_name") or (h.get("document") or {}).get("name", ""))
        for h in hits if h
    })

    return _ok(
        f"Loaded {hit_count} hit(s) from job {job_id}.\n"
        f"  Rules triggered: {rules_triggered}\n"
        f"  Completed: {completed_at}\n\n"
        "Call chainsaw_report for a structured summary, or get_detections to drill into specific rules."
    )


async def _chainsaw_hunt(args: dict) -> CallToolResult:
    if not state.evidence:
        return _error("No evidence staged. Call prepare_evidence first.")

    if state.hunt_status == "running":
        elapsed = time.time() - (state.hunt_started_at or time.time())
        return _error(
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

    # Run Chainsaw in the background so this call returns immediately.
    # Large evidence sets can take minutes; awaiting here exhausts the
    # MCP client's tool-call budget via tight hunt_status polling.
    state._hunt_task = asyncio.create_task(
        _run_hunt_background(evtx_dir, rules, sigma, mapping, extra)
    )

    return _ok(
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


async def _hunt_status(_args: dict) -> CallToolResult:
    status = state.hunt_status

    if status == "idle":
        return _ok("No hunt has been started. Call chainsaw_hunt first.")

    # If the hunt is running, block here (polling every 5 s, up to 60 s) so the
    # LLM client naturally waits without needing to understand sleep semantics.
    if status == "running":
        deadline = time.time() + 60
        while state.hunt_status == "running" and time.time() < deadline:
            await asyncio.sleep(5)
        status = state.hunt_status

    elapsed = _fmt_elapsed(
        ((state.hunt_finished_at or time.time()) - (state.hunt_started_at or time.time()))
    )

    if status == "running":
        return _ok(
            f"Hunt still running — {elapsed} elapsed.\n"
            "Call hunt_status again to keep waiting."
        )

    if status == "done":
        summary = _hits_summary(state.hits)
        file_line = f"\n  Results file: {state.output_file}" if state.output_file else ""
        return _ok(
            f"Hunt complete in {elapsed} — {len(state.hits)} hit(s) found.{file_line}\n\n"
            f"{summary}\n\n"
            "Call chainsaw_report for a summary with severity breakdown."
        )

    return _ok(f"Hunt failed after {elapsed}: {state.hunt_error}")


async def _chainsaw_report(_args: dict) -> CallToolResult:
    if not state.evidence:
        return _error("No evidence staged. Call prepare_evidence first.")

    if state.hunt_status == "running":
        return _error("Hunt is still running. Call hunt_status to check progress.")

    if state.hunt_status != "done":
        return _error("No completed hunt results. Call chainsaw_hunt first.")

    report_file = write_full_report(
        state.hits,
        evtx_path=state.evidence_path,
        output_dir=get_output_dir(),
    )
    state.report_file = str(report_file)

    summary = format_summary(state.hits, evtx_path=state.evidence_path, report_file=report_file)
    return _ok(summary)


async def _get_detections(args: dict) -> CallToolResult:
    if state.hunt_status != "done":
        return _error("No completed hunt results. Call chainsaw_hunt and wait for it to finish.")

    rule = args.get("rule") or None
    severity = args.get("severity") or None
    limit = int(args.get("limit") or 25)

    text = get_detections(state.hits, rule=rule, severity=severity, limit=limit)
    return _ok(text)


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


def _ok(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)])


def _error(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=f"ERROR: {text}")], isError=True)


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
    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    asyncio.run(_run())


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
        app=app,
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

    # Windows proactor event loop raises ConnectionResetError when the remote
    # closes an SSE connection, which is normal OpenWebUI behaviour. The selector
    # loop handles this cleanly.
    if is_windows():
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    uvicorn.run(starlette_app, host=host, port=port)


if __name__ == "__main__":
    main()
