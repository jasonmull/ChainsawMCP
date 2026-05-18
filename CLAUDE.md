# Chainsaw MCP — Project Context

## What This Is
An MCP server that wraps Chainsaw (Windows Event Log hunting tool) and enriches
its output using a local LLM. Goal: help junior analysts quickly understand what
Chainsaw findings mean during IR engagements where there's no EDR or SIEM.

## The Stack
- **MCP server:** Python, using the `mcp` SDK
- **Chainsaw:** Invoked as a subprocess. Must work on both Windows and Linux.
  - Typical invocation: `chainsaw hunt <evtx_path> --rules <rules_path> --sigma <sigma_path> --json`
  - Rules: SigmaHQ core rules
- **LLM backend:** Ollama (remote host), model: `foundationsec:8b`
  - Ollama base URL is read from env var `OLLAMA_BASE_URL` (default: http://localhost:11434)
  - Uses OpenAI-compatible `/v1/chat/completions` endpoint so swapping models is trivial
  - Hardware: RTX 5060 16GB VRAM — comfortable context windows up to ~32K tokens
- **Dev/test LLM:** Claude (via Anthropic API) — same interface, different backend

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

## MCP Tools (build in this order)
1. `prepare_evidence` — mount E01 or validate EVTX directory, stage files for Chainsaw
2. `chainsaw_hunt` — run hunt against staged EVTXs, return parsed JSON hits
3. `chainsaw_enrich` — send hits to LLM, get back narrative summary with confidence tier
4. `chainsaw_report` — format enriched results into a structured analyst report

## Enrichment Design
- **Batching by design (not hardware constraint):** Group hits by rule/tactic before
  sending to the LLM. Smaller focused batches produce better analysis than one large dump.
  Batch size should be a configurable parameter (default: 20 hits per batch).
- **Roll-up step:** After per-batch enrichment, a final LLM call synthesizes
  batch summaries into a coherent overall narrative.
- LLM receives: rule name, event IDs, timestamps, process/user context from hits
- LLM returns: narrative explanation, severity assessment, recommended next steps
- **Confidence tiering:** HIGH / MEDIUM / LOW based on corroborating hit count
- LLM must flag uncertainty explicitly — never invent context not in the data
- Pre-filter: LOW severity hits get templated responses without LLM enrichment

## Key Design Decisions
- Chainsaw runs as a subprocess — keep it decoupled, don't reimplement its logic
- Ollama URL always from config/env, never hardcoded
- JSON output from Chainsaw is the interface contract — parse defensively
- `chainsaw_hunt` must work standalone without Ollama being available
- Enrichment is an optional enhancement layer, not a hard dependency

## What NOT to Do
- Don't hardcode paths, binary names, or Ollama URLs
- Don't send all Chainsaw hits to the LLM in one call — always batch
- Don't hallucinate threat context the data doesn't support
- Don't rewrite Chainsaw logic in Python
- Don't make the Ollama connection block the hunt step

## Project Structure (target)
```
chainsaw-mcp/
├── CLAUDE.md
├── README.md
├── pyproject.toml
├── src/
│   └── chainsaw_mcp/
│       ├── __init__.py
│       ├── server.py        # MCP server entry point
│       ├── evidence.py      # E01 mounting + EVTX staging (prepare_evidence)
│       ├── chainsaw.py      # Subprocess wrapper for chainsaw hunt
│       ├── enrichment.py    # LLM enrichment + batching logic
│       ├── report.py        # Report formatting
│       └── config.py        # Env/config handling (OLLAMA_BASE_URL, paths, etc.)
└── tests/
    ├── sample_evtx/         # Small test EVTX files
    └── test_chainsaw.py
```

## Session Startup Checklist
Before writing code, confirm:
1. Are we on Windows or Linux right now? (affects binary names and mount tooling)
2. Is this a new feature, bug fix, or refactor?
3. Do we have sample EVTX data available for testing?
4. Is Ollama reachable at OLLAMA_BASE_URL? (only needed for enrichment testing)