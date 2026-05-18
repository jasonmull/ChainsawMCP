# Chainsaw MCP — Project Context

## What This Is
An MCP server that wraps Chainsaw (Windows Event Log hunting tool) and surfaces
its findings to an LLM client for analysis. Goal: help analysts quickly understand
Chainsaw findings during IR engagements where there's no EDR or SIEM.

The server handles evidence preparation and Chainsaw execution. The MCP client
(Claude Desktop, OpenWebUI, etc.) provides the LLM reasoning — no server-side
LLM calls are made.

## The Stack
- **MCP server:** Python, using the `mcp` SDK
- **Chainsaw:** Invoked as a subprocess. Must work on both Windows and Linux.
  - Typical invocation: `chainsaw hunt <evtx_path> --rules <rules_path> --sigma <sigma_path> --json`
  - Rules: SigmaHQ core rules
- **LLM client:** Claude Desktop or OpenWebUI — the client drives analysis, the server just provides tools

## Evidence Input
The server must handle two input types:
1. **EVTX directory** — a folder of `.evtx` files ready for Chainsaw
2. **E01 disk image** — a forensic image that must be mounted and EVTXs extracted first

The `prepare_evidence()` step detects which type it has, handles accordingly,
and stages EVTXs to a temp directory before handing off to Chainsaw.

### E01 Mounting
- **Linux:** `ewfmount` + `ntfs-3g` via subprocess. Mount point managed by the server.
- **Windows:** Arsenal Image Mounter CLI (`aim_cli.exe`) via subprocess.
- Always mount read-only. Always clean up mount points on exit.
- E01 images may be split across multiple files (`.E01`, `.E02`, etc.) — handle this.

## Cross-Platform Requirements
All file paths and subprocess calls must handle both Windows and Linux.
- Use `pathlib.Path` everywhere. Never hardcode path separators.
- Chainsaw binary: `chainsaw` on Linux, `chainsaw.exe` on Windows — detect via `platform.system()`
- Arsenal Image Mounter only exists on Windows; `ewfmount` only on Linux — enforce this

## MCP Tools
1. `prepare_evidence` — mount E01 or validate EVTX directory, stage files for Chainsaw
2. `chainsaw_hunt` — run hunt against staged EVTXs, return parsed hits for client analysis
3. `chainsaw_report` — format hits into a structured analyst report

## Key Design Decisions
- Chainsaw runs as a subprocess — keep it decoupled, don't reimplement its logic
- The server makes no LLM calls — the MCP client provides all reasoning
- JSON output from Chainsaw is the interface contract — parse defensively
- Hits are returned to the client grouped by rule for easy analysis

## What NOT to Do
- Don't hardcode paths or binary names
- Don't make server-side LLM calls — the client handles reasoning
- Don't rewrite Chainsaw logic in Python

## Project Structure (target)
```
ChainsawMCP/
├── CLAUDE.md
├── README.md
├── pyproject.toml
├── src/
│   └── chainsawmcp/
│       ├── __init__.py
│       ├── server.py        # MCP server entry point
│       ├── evidence.py      # E01 mounting + EVTX staging (prepare_evidence)
│       ├── chainsaw.py      # Subprocess wrapper for chainsaw hunt
│       ├── report.py        # Report formatting
│       └── config.py        # Env/config handling (paths, binary names, etc.)
└── tests/
    ├── sample_evtx/         # Small test EVTX files
    └── test_chainsaw.py
```

## Session Startup Checklist
Before writing code, confirm:
1. Are we on Windows or Linux right now? (affects binary names and mount tooling)
2. Is this a new feature, bug fix, or refactor?
3. Do we have sample EVTX data available for testing?