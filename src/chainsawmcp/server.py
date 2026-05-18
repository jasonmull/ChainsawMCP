"""MCP server entry point — exposes Chainsaw tools over the Model Context Protocol."""

import asyncio
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

from .chainsaw import ChainsawError, run_hunt_async
from .evidence import EvidenceError, PreparedEvidence, prepare_evidence
from .report import format_report

app = Server("ChainsawMCP")


class _SessionState:
    """Module-level session state for a single analysis session."""
    evidence: PreparedEvidence | None = None
    hits: list[dict] = []
    evidence_path: str = ""


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
                "Run Chainsaw hunt against staged EVTXs. "
                "Returns all detections grouped by rule for the client to analyse."
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
            name="chainsaw_report",
            description=(
                "Format hunt results into a structured analyst report. "
                "Call chainsaw_hunt first."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
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
        "chainsaw_report": _chainsaw_report,
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

    if state.evidence:
        state.evidence.cleanup()

    try:
        ev = prepare_evidence(path)
    except EvidenceError as e:
        return _error(str(e))

    state.evidence = ev
    state.hits = []
    state.evidence_path = path

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

    rules = Path(args["rules_path"]) if args.get("rules_path") else None
    sigma = Path(args["sigma_path"]) if args.get("sigma_path") else None
    mapping = Path(args["mapping_path"]) if args.get("mapping_path") else None
    extra = args.get("extra_args") or []

    try:
        hits = await run_hunt_async(state.evidence.evtx_dir, rules_path=rules, sigma_path=sigma, mapping_path=mapping, extra_args=extra)
    except ChainsawError as e:
        return _error(str(e))

    state.hits = hits

    summary = _hits_summary(hits)
    return _ok(
        f"Hunt complete — {len(hits)} hit(s) found.\n\n"
        f"{summary}\n\n"
        "Call chainsaw_report for a formatted report."
    )


async def _chainsaw_report(_args: dict) -> CallToolResult:
    if not state.evidence:
        return _error("No evidence staged. Call prepare_evidence first.")

    report = format_report(state.hits, evtx_path=state.evidence_path)
    return _ok(report)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()
