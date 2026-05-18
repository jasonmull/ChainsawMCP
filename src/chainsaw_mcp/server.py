"""MCP server entry point — exposes Chainsaw tools over the Model Context Protocol."""

import asyncio
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

from .chainsaw import ChainsawError, run_hunt
from .config import get_batch_size
from .enrichment import EnrichmentError, EnrichmentResult, enrich_hits
from .evidence import EvidenceError, PreparedEvidence, prepare_evidence
from .report import format_report

app = Server("chainsaw-mcp")


class _SessionState:
    """Module-level session state for a single analysis session."""
    evidence: PreparedEvidence | None = None
    hits: list[dict] = []
    evidence_path: str = ""
    enrichment: EnrichmentResult | None = None


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
                "Returns a summary of detections. Does NOT require Ollama."
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
            name="chainsaw_enrich",
            description=(
                "Send Chainsaw hits to the local LLM (Ollama) for narrative enrichment. "
                "Batches hits by rule/tactic, enriches each batch, then synthesises a roll-up. "
                "Requires Ollama at OLLAMA_BASE_URL."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "batch_size": {
                        "type": "integer",
                        "description": f"Hits per LLM batch (default: {get_batch_size()}).",
                        "minimum": 1,
                        "maximum": 100,
                    }
                },
                "required": [],
            },
        ),
        Tool(
            name="chainsaw_report",
            description=(
                "Format enriched results into a structured analyst report. "
                "Call chainsaw_enrich first."
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
        "chainsaw_enrich": _chainsaw_enrich,
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
    state.enrichment = None

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
    extra = args.get("extra_args") or []

    try:
        hits = run_hunt(state.evidence.evtx_dir, rules_path=rules, sigma_path=sigma, extra_args=extra)
    except ChainsawError as e:
        return _error(str(e))

    state.hits = hits
    state.enrichment = None

    summary = _hits_summary(hits)
    return _ok(
        f"Hunt complete — {len(hits)} hit(s) found.\n\n"
        f"{summary}\n\n"
        "Next step: call chainsaw_enrich (requires Ollama) or chainsaw_report for a raw report."
    )


async def _chainsaw_enrich(args: dict) -> CallToolResult:
    if not state.evidence:
        return _error("No evidence staged. Call prepare_evidence first.")
    if not state.hits:
        return _ok("No hits to enrich — Chainsaw found 0 detections.")

    batch_size = int(args.get("batch_size") or get_batch_size())

    try:
        result = await enrich_hits(state.hits, batch_size=batch_size)
    except EnrichmentError as e:
        return _error(str(e))

    state.enrichment = result

    confidence_counts = {
        "HIGH": sum(1 for b in result.batches if b.confidence == "HIGH"),
        "MEDIUM": sum(1 for b in result.batches if b.confidence == "MEDIUM"),
        "LOW": sum(1 for b in result.batches if b.confidence == "LOW"),
    }

    return _ok(
        f"Enrichment complete — {len(result.batches)} batch(es) analysed.\n"
        f"  HIGH: {confidence_counts['HIGH']}  MEDIUM: {confidence_counts['MEDIUM']}  LOW: {confidence_counts['LOW']}\n\n"
        "ROLL-UP SUMMARY\n"
        "---------------\n"
        f"{result.rollup}\n\n"
        "Next step: call chainsaw_report for the full formatted report."
    )


async def _chainsaw_report(_args: dict) -> CallToolResult:
    if state.enrichment is None:
        return _error("No enrichment data. Call chainsaw_enrich first.")

    report = format_report(
        state.enrichment,
        evtx_path=state.evidence_path,
        total_hits=len(state.hits),
    )
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
