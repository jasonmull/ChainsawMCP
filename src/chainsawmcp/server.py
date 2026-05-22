"""MCP server entry point — exposes Chainsaw tools over the Model Context Protocol."""

import asyncio
import time
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

from .chainsaw import ChainsawError, HuntResult, run_hunt_async
from .config import get_http_host, get_http_port, get_output_dir
from .evidence import EvidenceError, PreparedEvidence, prepare_evidence
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
                "Start a Chainsaw hunt against staged EVTXs in the background. "
                "Returns immediately — call hunt_status to poll for completion."
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
                "Check the status of a running or completed Chainsaw hunt. "
                "Poll this after calling chainsaw_hunt until status is 'done' or 'error'."
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

    async def _run() -> None:
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

    state._hunt_task = asyncio.create_task(_run())

    return _ok(
        f"Hunt started against {evtx_count} EVTX file(s).\n"
        "Call hunt_status to check progress."
    )


async def _hunt_status(_args: dict) -> CallToolResult:
    status = state.hunt_status

    if status == "idle":
        return _ok("No hunt has been started. Call chainsaw_hunt first.")

    elapsed = _fmt_elapsed(
        ((state.hunt_finished_at or time.time()) - (state.hunt_started_at or time.time()))
    )

    if status == "running":
        return _ok(f"Hunt running — {elapsed} elapsed. Call hunt_status again to check.")

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
    import uvicorn
    from starlette.middleware.cors import CORSMiddleware

    host = get_http_host()
    port = get_http_port()

    starlette_app = app.streamable_http_app(event_store=None, json_response=False)
    starlette_app = CORSMiddleware(
        starlette_app,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "DELETE"],
        expose_headers=["Mcp-Session-Id"],
    )

    print(f"ChainsawMCP listening on http://{host}:{port}/mcp")
    print(f"Add this URL to OpenWebUI: Admin → External Tools → Add Server (MCP Streamable HTTP)")
    if is_windows():
        print(f"  To change host/port (PowerShell): $env:CHAINSAWMCP_HOST='0.0.0.0'; $env:CHAINSAWMCP_PORT='8000'")
    else:
        print(f"  To change host/port: CHAINSAWMCP_HOST=0.0.0.0 CHAINSAWMCP_PORT=8000 chainsawmcp --transport streamable-http")
    uvicorn.run(starlette_app, host=host, port=port)


if __name__ == "__main__":
    main()
