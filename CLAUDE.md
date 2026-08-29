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
4. `get_report_spec` — return the canonical incident report specification (stateless)
5. `build_incident_report` — write `reports/incident_report.md` + `.json` with all
   server-rendered sections pre-filled and slots for the narrative ones
6. `validate_report` — check a finished report against the spec and resolve every cited `hit_id`

### Report format is server-owned
The incident report structure lives in `report_spec.py` and is served to every client, so it
does not vary with the inference provider. Sections 2 (MITRE ATT&CK), 3 (Timeline), 4 (IOCs),
5 (Accounts and Systems) and 9 (Evidence & Provenance) are rendered deterministically in Python
from the hunt output — never ask a model to write or rewrite them. Only sections 1, 6, 7 and 8
are model-authored, and they go in the marked slots.

Do not add a report template to a client, a skill, or a prompt. If the format needs to change,
change `report_spec.py`.

## Key Design Decisions
- Chainsaw runs as a subprocess — keep it decoupled, don't reimplement its logic
- The server makes no LLM calls — the MCP client provides all reasoning
- JSON output from Chainsaw is the interface contract — parse defensively
- Hits are returned to the client grouped by rule for easy analysis

## Path handling for MCP arguments
Any filesystem path built from a value that arrived over MCP (`job_id`, a report `path`,
an output directory) must go through `config.ensure_within()` or `config.safe_child()`.
Both resolve before comparing, so `..` segments and symlinks are covered.

This is not routine defensiveness: the server feeds adversary-authored text — command
lines and script blocks pulled from a compromised host's event logs — to an LLM that can
call these tools, so a path argument is reachable by prompt injection, not just by the
analyst. `prepare_evidence` and `start_hunt` take arbitrary paths by design (they have to
reach the evidence); everything else should be confined.

## What NOT to Do
- Don't hardcode paths or binary names
- Don't make server-side LLM calls — the client handles reasoning
- Don't rewrite Chainsaw logic in Python
- Don't join an MCP-supplied value onto a path directly — use the helpers above

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
│       ├── report.py        # Report formatting (fixed-width text, hunt_report.txt)
│       ├── report_spec.py   # Canonical incident report spec — single source of truth
│       ├── report_markdown.py # Deterministic Markdown rendering of server sections
│       ├── report_validate.py # Conformance + citation checking for finished reports
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

---

<!--
SUGGESTIONS FOR IMPROVING THIS FILE
Based on the initial build session (2026-05-18)

1. CHAINSAW CLI VERSION
   Add a note stating which exact version of Chainsaw is installed and tested
   against, with output of `chainsaw --version`. Flags change across versions
   and this caused real bugs in session 1 (--rules vs --rule, missing --mapping,
   false report of --no-progress). A pinned version removes ambiguity.
   Example addition:
     ## Chainsaw Version
     Tested against: Chainsaw v2.x.x (run `chainsaw --version` to confirm)
     Key flags for this version: --rule, --sigma, --mapping, --json
     Before adding any new subprocess flag, verify with: `chainsaw hunt --help`

2. LLM CLIENT CONTEXT
   The server makes zero LLM calls — the client handles all reasoning. This
   took a full design-then-undo cycle to settle. State it earlier and more
   explicitly so it's the first constraint an AI assistant sees, not something
   discovered mid-build. Add to "What NOT to Do":
     - Don't add server-side LLM calls under any framing (enrichment, summarisation,
       confidence scoring). The client IS the LLM. This is a deliberate design choice,
       not a gap to fill.

3. TARGET DEPLOYMENT ENVIRONMENT
   Add a short section describing where this actually runs — Windows machine,
   specific Python version, how Chainsaw is installed, where rules/sigma/mappings
   live on disk. This would have prevented the cross-platform ambiguity early in
   the session and grounded flag discussions in the actual deployment target.
   Example addition:
     ## Deployment Environment
     - OS: Windows (primary), Linux (secondary)
     - Python: 3.11+
     - Chainsaw: installed at C:\Tools\chainsaw\chainsaw.exe (or on PATH)
     - Rules: C:\Tools\chainsaw\rules\
     - Sigma: C:\Tools\chainsaw\sigma\rules\
     - Mapping: C:\Tools\chainsaw\mappings\sigma-event-logs-all.yml

4. KNOWN OPEN ISSUES
   Add a section for known issues/TODOs so an AI assistant picks them up at
   session start rather than discovering them mid-task. Based on this session:
     ## Known Issues / Next Steps
     - chainsaw_hunt blocks the asyncio event loop on large evidence sets
       (fix: asyncio.to_thread — see main branch ADR-001)
     - config.py has dead Ollama functions (get_ollama_base_url, get_ollama_model)
       left over from the enrichment design — remove before next feature work
     - No end-to-end test of E01 mounting against a real image
     - No hunt cancellation mechanism

## ADDITIONAL SUGGESTIONS FROM FOLLOW-UP SESSION (2026-05-18)

## Suggestions for improving this file (added 2026-05-18)

These are things that would have made guidance more accurate or saved
debugging time in the session on 2026-05-18:

### 1. Pin the Chainsaw version and document its exact CLI
The installed Chainsaw version differs from what online docs describe.
The CLI surface has changed across releases. Add something like:

  **Chainsaw version in use:** v2.x.x (check with `chainsaw --version`)
  **Verified hunt invocation:**
    chainsaw hunt --json --preprocess <RULES_DIR> <EVTX_DIR>

  Before adding any new CLI flag, verify it exists:
    chainsaw hunt --help

### 2. Note that MCP tool handlers must never block the event loop
Add to Key Design Decisions:
  - MCP tool handlers are async. Never call blocking I/O (subprocess.run,
    open, os.walk on large trees) directly in a handler. Use
    asyncio.to_thread() for any blocking subprocess or file operation.

### 3. Document the hunt_status polling tool
The MCP Tools list is now out of date. It should include:
  4. `hunt_status` — poll for background hunt progress (idle/running/done/error)

### 4. Add a Chainsaw output parsing note
The JSON output format from Chainsaw is not well-documented and varies.
Note that _parse_output() handles both JSON arrays and newline-delimited
JSON, and silently drops non-JSON lines. Any future parser changes should
preserve that resilience.

### 5. Clarify the expected hunt duration range
"Chainsaw runs can take a while" is vague. In practice, 296 EVTX files
took approximately 3 minutes on the test system. Documenting a rough
benchmark (files → expected minutes) would help set timeout defaults and
alert the developer when something is actually hung vs. just slow.
-->

---

## Protocol SIFT Compliance

**Evidence Mode: Strict read-only**
Never write to `/cases/`, `/mnt/`, `/media/`, or any `evidence/` directory.
Original evidence must remain immutable for chain-of-custody and legal defensibility.

**Case Directory**
Protocol SIFT places case roots at `/cases/[CASE_ID]/`. Launch Claude Code from within that
directory — `CHAINSAWMCP_CASE_DIR` defaults to `cwd`, so no explicit env var is needed in the
standard workflow. All generated artifacts are written to subdirectories relative to this root.

**Artifact Routing (relative to `CHAINSAWMCP_CASE_DIR`)**
- `./analysis/`  — job state, raw Chainsaw output, EVTX staging, chainsaw_provenance.json, forensic_audit.log, agent_execution.jsonl
- `./exports/`   — structured exports: CSVs, extracted registry keys, super-timelines
- `./reports/`   — final hunt reports (`hunt_report.txt`) and forensic summaries

**UTC Standardization**
All timestamps in generated reports and audit logs MUST use UTC (ISO 8601, e.g. `2026-06-07T14:30:00Z`).
Never use local time. Chainsaw provenance records and report headers already enforce this.

**Deterministic Execution**
Use only the Chainsaw binary (invoked as a subprocess) for detection logic. Do not substitute
internal probabilistic reasoning for Chainsaw output. The server makes no LLM calls — the MCP
client provides all reasoning.

**Chain-of-Custody**
Every hunt writes `chainsaw_provenance.json` alongside `hunt_results.json` in `./analysis/<job_id>/`.
This record includes the exact command, Chainsaw version, and SHA-256 of the output file.
`load_hunt_results` surfaces this provenance into the session so it travels with findings.
A Stop hook appends a timestamped entry to `./analysis/forensic_audit.log` at the end of each
Claude session — see `.claude/settings.json`.
