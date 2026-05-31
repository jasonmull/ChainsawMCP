# Architecture Decision Records — ChainsawMCP

Combined document. Decisions recorded in chronological order.

---

# ADR-0001: OpenWebUI / Ollama Integration Strategy

**Date:** 2026-05-24  
**Status:** Accepted  
**Deciders:** Jason Mull  

---

## Context

ChainsawMCP was initially built with a single transport target: Claude Desktop
via stdio. The goal of this session was to extend it to work with a local Ollama
stack (OpenWebUI v0.9.2 frontend, Ollama backend) so that analysts running
air-gapped or cost-sensitive environments can use open-weight models instead of
Claude.

Several interrelated decisions were required:

- How to expose the MCP server to OpenWebUI
- Which Ollama models can actually call tools
- How to handle the synchronous/asynchronous mismatch between the server's hunt
  design and LLM tool-calling behaviour
- How to support models that cannot call tools at all

---

## Decision 1: Use mcpo (OpenAPI proxy) rather than OpenWebUI's native MCP

### What we tried first

OpenWebUI v0.9 advertises native MCP support via its "External Tools → MCP
(Streamable HTTP)" server type. We added a Streamable HTTP transport to
ChainsawMCP (`--transport streamable-http`) using `StreamableHTTPSessionManager`
from the MCP Python SDK, mounted at `/mcp`.

OpenWebUI successfully connected (200 OK on POST/GET/DELETE to `/mcp/`) and the
MCP session handshake completed. However, the tool schemas were never injected
into Ollama API calls — the model received no tool definitions and could not call
any tools regardless of model or configuration.

### Decision

Use **mcpo** (`pip install mcpo`) as a proxy layer between ChainsawMCP and
OpenWebUI. mcpo wraps the stdio MCP server and exposes it as an OpenAPI
HTTP server. OpenWebUI's "External Tools → OpenAPI" integration reliably injects
tool schemas into model API calls.

```
OpenWebUI → mcpo (OpenAPI, port 8081) → chainsawmcp (stdio)
```

The Streamable HTTP transport is retained in the codebase for future use (Claude
Desktop alternative, other MCP-native clients) but is not the recommended path
for OpenWebUI.

### Rationale

- OpenWebUI's native MCP tool injection did not work in v0.9.2 regardless of
  model or configuration
- mcpo is maintained by the OpenWebUI project and is the documented fallback
- OpenAPI tool injection in OpenWebUI is mature and reliable
- No changes to ChainsawMCP server logic are required; mcpo wraps the existing
  stdio entry point directly

### Consequences

- Analysts must run two processes: `chainsawmcp --transport streamable-http`
  (or simply `chainsawmcp` via mcpo) and `mcpo --port 8081 -- chainsawmcp`
- mcpo becomes a runtime dependency for the OpenWebUI path (not installed by
  default; `pip install mcpo` separately)
- If OpenWebUI's native MCP integration improves in a future release, the
  Streamable HTTP transport is already in place

---

## Decision 2: Make `chainsaw_hunt` synchronous for tool-calling clients

### Context

`chainsaw_hunt` was originally designed as a fire-and-return tool: it starts the
hunt as a background asyncio task and returns immediately with "hunt started,
call hunt_status to poll". This was designed for Claude Desktop's interactive
workflow where the model can poll repeatedly.

When used via tool-calling LLMs (Qwen2.5 via mcpo), models called
`hunt_status` once immediately after `chainsaw_hunt` (within milliseconds),
then called `chainsaw_report` before the hunt had completed, receiving a 500
error ("Hunt is still running").

### Decision

Remove the background task. `chainsaw_hunt` now **awaits `run_hunt_async`
directly** and only returns when the hunt is complete, carrying the hit summary
in the response body.

`hunt_status` is retained as a status check for edge cases (interrupted sessions,
manual inspection) but is no longer part of the primary workflow.

### Rationale

- LLMs do not implement wait/retry loops reliably; synchronous tools remove the
  need entirely
- HTTP connections in uvicorn/mcpo do not have a hard request timeout; long
  hunts (minutes) are handled without issues
- The simplified tool sequence (`prepare → hunt → report → get_detections`) is
  clearer for model prompting and reduces prompt engineering burden
- Claude Desktop (stdio) also benefits: Claude waits for the response rather than
  polling, with no behavioural regression

### Consequences

- `chainsaw_hunt` blocks for the duration of the hunt (seconds to minutes
  depending on evidence volume and rule set)
- The OpenWebUI chat interface will appear unresponsive during a long hunt; this
  is expected and acceptable
- The asynchronous/polling design is no longer the primary path; if true async
  progress reporting is needed in future it would require a different mechanism
  (e.g. SSE progress events)

---

## Decision 3: Streamable HTTP transport on Windows uses `WindowsSelectorEventLoopPolicy`

### Context

Running `chainsawmcp --transport streamable-http` on Windows (Python 3.13) with
the default ProactorEventLoop caused spurious `ConnectionResetError: [WinError
10054]` exceptions logged to the console whenever OpenWebUI closed an SSE
connection. These errors are harmless (connection teardown is normal) but noisy
and alarming to analysts.

### Decision

Set `asyncio.WindowsSelectorEventLoopPolicy()` before calling `uvicorn.run()`
when running on Windows. The SelectorEventLoop handles abrupt connection closure
without raising.

### Rationale

- WinError 10054 is a known Windows Proactor/asyncio interaction issue with
  no functional impact
- The SelectorEventLoop is the recommended workaround for uvicorn on Windows
- One-line fix with no architectural implications

---

## Decision 4: OpenWebUI inlet Filter for base and reasoning models

### Context

Cisco Foundation-Sec-8B-Reasoning is a security-domain reasoning model with
strong analysis capability but no tool-calling support (it is not instruction-
tuned for function calling). Standard tool integration (MCP or mcpo) requires
the model to emit structured tool-call tokens, which Foundation-Sec-8B-Reasoning
does not produce.

### Decision

Provide an **OpenWebUI inlet Filter** (`extras/chainsaw_filter.py`) that
intercepts the user message before the model sees it, executes the full
ChainsawMCP workflow autonomously via mcpo HTTP calls, and replaces the user
message with the complete Chainsaw findings plus a structured IR report prompt.

The model never calls any tools. It receives pre-loaded evidence data and is
asked only to write the analysis — a text generation task it is well-suited for.

Trigger syntax: `!analyse <path>` in any OpenWebUI chat.

```
User: !analyse F:\ChainsawEvals
           ↓
   [Filter: prepare_evidence]
   [Filter: chainsaw_hunt]
   [Filter: chainsaw_report]
   [Filter: get_detections × 3 severities]
           ↓
   Model receives full findings
   + structured report prompt
           ↓
   Model writes IR report
```

### Rationale

- Separates tool orchestration (filter) from threat analysis (model), matching
  each component to what it does best
- Foundation-Sec-8B-Reasoning has strong cybersecurity domain knowledge; the
  constraint is tool orchestration, not analytical ability
- Works with any model regardless of tool-calling support, including future
  security-specialist models
- Filter is OpenWebUI-side only; no changes to ChainsawMCP are required
- Configurable via OpenWebUI Valves: mcpo URL, trigger keyword, timeouts,
  detection limits

### Consequences

- The full workflow (prepare + hunt + report + 3 × get_detections) runs
  synchronously inside the filter before the model responds; the user sees no
  activity during this time (typically 30 seconds to several minutes)
- Filter must be installed separately in OpenWebUI (Admin → Functions); it is not
  auto-deployed
- If mcpo is unreachable, the filter injects the error into the prompt and the
  model explains the failure rather than silently returning a bad response
- Context window limits may be hit for very large evidence sets with many
  detections; `max_detections` Valve can be reduced if needed

---

## Model Compatibility Summary

| Model | Tool calling | Filter | Notes |
|---|---|---|---|
| Foundation-Sec-8B (base) | ❌ | ❌ | Base model; no instruction following |
| Foundation-Sec-8B-Reasoning | ❌ | ✅ | Strong analysis; use with filter |
| Foundation-Sec-8B-Instruct | Unknown | Likely ✅ | Not yet tested in Ollama |
| Qwen2.5:14b+ | ✅ | ✅ | Recommended for autonomous tool use |
| llama3.1:8b | ✅ | ✅ | Reliable tool calling; weaker analysis |
| FoundationSec:8b (Ollama) | ❌ | ❌ | Same as base model above |

---

## Alternatives Considered

### Native MCP only (no mcpo)

Rejected. OpenWebUI v0.9.2 native MCP does not inject tool schemas into Ollama
API calls. The Streamable HTTP transport was implemented and tested; the
integration appeared to work at the protocol level but tools never reached the
model.

### mcpo + prompt engineering only (no filter)

Works for instruction-tuned models (Qwen2.5) but not for base or reasoning-only
models. Both paths are provided: mcpo for tool-capable models, filter for others.

### Rewrite server using FastMCP (high-level SDK)

`streamable_http_app()` was discovered to be a FastMCP method not present on the
low-level `mcp.server.Server` class in mcp v1.27. Using `StreamableHTTPSessionManager`
directly from `mcp.server.streamable_http_manager` achieves the same result
without rewriting the handler layer.

### Server-side LLM enrichment

The original CLAUDE.md described a `chainsaw_enrich` tool that would call Ollama
server-side. This was explicitly rejected by the project's design principles:
the server makes no LLM calls; the MCP client provides all reasoning.

---
---

# ADR-001: Detached Hunt Execution Architecture

**Status:** Accepted  
**Date:** 2026-05-30  
**Deciders:** Jason Mull  

---

## Context

ChainsawMCP's original design embedded Chainsaw execution inside a synchronous MCP tool call. The `chainsaw_hunt` tool launched Chainsaw as an asyncio background task, and a polling tool (`hunt_status`) blocked for up to 60 seconds per call while waiting for completion.

This worked for small evidence sets (~300 MB, ~50 EVTX files) but failed consistently for realistic IR workloads:

- A 3 GB evidence set with 317 EVTX files required 30+ minutes of Chainsaw execution
- MCP clients (Claude Desktop) enforce a finite tool budget — repeated `hunt_status` calls exhausted this budget before Chainsaw finished
- The session timed out with no results, requiring the analyst to restart from scratch
- The intended use case — processing 10+ GB from multiple endpoints — made this worse, not better

The core incompatibility: **MCP is a request/response protocol with client-side timeouts; Chainsaw is a CPU-bound process with unbounded runtime.**

---

## Decision 1: Detached Subprocess Execution

**Chainsaw is spawned as a fully detached process, independent of the MCP server's process lifetime.**

Rather than running Chainsaw as a child process tied to the MCP session, `start_hunt` spawns a Python runner script (`chainsawmcp.monitor`) as a detached process. The runner:

1. Opens its own output and log file handles (within the runner process, avoiding cross-process handle inheritance)
2. Executes Chainsaw with a blocking `subprocess.run()` call
3. Updates job state on disk when Chainsaw exits
4. POSTs a webhook notification on completion

**Why a runner script, not Chainsaw directly?**

Windows `DETACHED_PROCESS` / `CREATE_NEW_PROCESS_GROUP` does not reliably inherit file handles opened in the parent process. Passing `stdout=file_handle` to a detached Chainsaw process caused Chainsaw to panic immediately with `Os { code: 6, message: "The handle is invalid." }`. The runner process opens its own handles, eliminating the inheritance problem entirely.

**Platform flags used:**

| Platform | Flag |
|---|---|
| Windows | `CREATE_NO_WINDOW \| CREATE_NEW_PROCESS_GROUP` |
| Linux | `start_new_session=True` |

**Consequences:**
- `start_hunt` returns in under one second regardless of evidence size
- MCP tool budget is never consumed by Chainsaw execution time
- The MCP session can be closed; Chainsaw keeps running
- Chainsaw execution survives MCP server restarts

---

## Decision 2: Disk-Persisted Job State

**All job state is written to disk, not held in memory.**

Each hunt creates a job directory under `CHAINSAWMCP_JOBS_DIR` containing:

```
<job_id>/
├── job.json            # status, pid, started_at, hit_count, completed_at, error
├── hunt_results.json   # Chainsaw's JSON output
└── chainsaw_stderr.log # Chainsaw's stderr (for diagnostics)
```

`job.json` is updated atomically at each lifecycle transition: `running` → `complete` / `error`.

**Why disk, not in-memory session state?**

The detached execution model means the process that runs Chainsaw (the runner) is different from the process that serves MCP tools (the server). In-memory state cannot be shared across process boundaries. Disk also provides durability — results are available in a future MCP session hours or days after the hunt completed.

**Consequences:**
- `load_hunt_results()` can recover any previous job by ID, or automatically pick up the latest completed job
- Results persist across MCP server restarts and client disconnects
- Job history accumulates in `CHAINSAWMCP_JOBS_DIR` and requires occasional cleanup (not currently automated)

---

## Decision 3: Webhook Notification Instead of Polling

**Completion is communicated via webhook POST, not by polling a status tool.**

The original `hunt_status` tool polled in-memory state, blocking for 60 seconds per call. This was retained initially but ultimately removed because:

1. It kept the MCP session alive — exactly the problem being solved
2. It had no knowledge of detached jobs (always returned "No hunt started")
3. It created pressure on Claude to keep calling it, burning tool budget

The replacement model: when the runner finishes, it POSTs to `CHAINSAWMCP_WEBHOOK_URL`. The analyst receives a notification and opens a fresh MCP session to run `load_hunt_results()`.

**Webhook payload format:**

Discord and Slack each require specific fields (`content` and `text` respectively). Generic receivers accept arbitrary JSON. The payload includes both human-readable fields and raw data:

```json
{
  "content": "✅ ChainsawMCP hunt complete (job abc123)\nHits: 4312 across 23 rules",
  "text":    "✅ ChainsawMCP hunt complete (job abc123)\nHits: 4312 across 23 rules",
  "job_id": "abc123",
  "status": "complete",
  "hit_count": 4312,
  "rules_triggered": 23,
  "completed_at": "2026-05-30T17:53:22Z"
}
```

Webhook failures are written to `<job_dir>/webhook_error.log` rather than silently discarded.

**Consequences:**
- Analyst workflow requires a notification channel to be configured (`CHAINSAWMCP_WEBHOOK_URL`)
- Without a webhook, the analyst must manually call `load_hunt_results()` to check for completion
- The MCP session is completely free between hunt start and result loading

---

## Decision 4: Remove `chainsaw_hunt` and `hunt_status` Tools

**The legacy inline hunt tools were removed from the MCP tool catalogue entirely.**

Keeping them as "legacy" options caused Claude to choose them over `start_hunt` due to their prominent position in the tool list and the `prepare_evidence` response text directing to `chainsaw_hunt`. Marking them "LEGACY" in descriptions was insufficient — Claude still selected them.

Removing them eliminates the ambiguity. The tool catalogue is now unambiguous:

| Tool | Purpose |
|---|---|
| `prepare_evidence` | E01 image mounting only |
| `start_hunt` | Begin a detached hunt |
| `load_hunt_results` | Load completed results |
| `chainsaw_report` | Structured summary |
| `get_detections` | Drill-down queries |

**Consequences:**
- No inline hunt path for small datasets (acceptable — `start_hunt` completes small hunts in seconds anyway)
- Simpler tool catalogue with no ambiguous choices for the LLM client

---

## Decision 5: `--skip-errors` Always Enabled

**Chainsaw is always invoked with `--skip-errors`.**

IR evidence collections frequently contain corrupt, partial, or locked EVTX files. Without `--skip-errors`, a single unreadable file aborts the entire hunt. This is particularly problematic for large multi-endpoint collections where some files may have been collected under active use.

The flag is baked into `_build_command()` rather than exposed as a user option because there is no scenario in which aborting a hunt for a single bad file is preferable to skipping it.

---

## Decision 6: No Server-Side LLM Calls (Retained from Original Design)

**The MCP server makes no LLM calls. All reasoning is provided by the client.**

Automatic report generation on hunt completion was considered during the detached execution design. A fully automatic flow (hunt → LLM analysis → report file) would eliminate the need for an MCP session entirely for basic triage.

This was rejected because:

1. A one-shot report cannot answer follow-up questions — the primary value of the LLM is interactive investigation, not static summarization
2. Server-side LLM calls would require an API key on the server, breaking the privacy model for locally-hosted deployments
3. The client already has a capable model; running a second model on the server provides no benefit

**Consequence:** The analyst must open an MCP session to perform analysis. This is intentional — the session is where the value is delivered.

---

## Decision 7: E01 Preparation Delegated to the Monitor Process

**E01 extraction is no longer performed synchronously in the MCP tool handler. It runs inside the detached monitor, alongside Chainsaw.**

### Problem

`start_hunt` originally called `prepare_evidence()` synchronously before spawning the monitor. For large E01 images (3–5 GB), extraction via pytsk3 or TSK CLI takes 3–5 minutes. The MCP client enforces a ~4 minute per-call timeout and cancels the request with `-32001: Request timed out`. The server continued working after cancellation and the hunt eventually started, but:

1. The tool response was discarded — Claude never received the job ID
2. Calling `prepare_evidence` for a second E01 immediately destroyed the first image's staging directory via `state.evidence.cleanup()`, before the first hunt had started
3. Large images (>4 min extraction) could not be processed at all via `start_hunt`

### Decision

`start_hunt` now returns immediately for E01 inputs — before touching the filesystem — by delegating preparation to the monitor process. The call sequence is:

1. `start_hunt` creates a job record and spawns the monitor with `{"evidence_path": "..."}` config (instead of a pre-built Chainsaw command)
2. The monitor detects the dict payload, calls `stage_evtx()` to extract EVTXs, then builds and runs the Chainsaw command itself
3. The MCP tool call returns in under one second with a job ID

**Consequences:**
- No E01 extraction can ever timeout an MCP tool call
- Multiple E01 hunts can be queued immediately; each gets its own monitor
- The staging directory is no longer tied to the MCP server process lifetime

---

## Decision 8: EVTXs Staged to Job Directory, Not `/tmp`

**Extracted EVTXs are written to `<CHAINSAWMCP_JOBS_DIR>/<job_id>/evtx/<source_stem>/` rather than a temporary directory.**

### Problem

The original staging path was `tempfile.mkdtemp(prefix="chainsawmcp_")` → `/tmp/chainsawmcp_XXXX/evtx/`. This caused two classes of failure:

1. **Path not found after preparation**: The staging dir was created in the MCP server process but the path was referenced by a different process (monitor). System temp cleaners, OS restart, or subtle reference counting issues caused the path to be gone by the time Chainsaw tried to access it.
2. **No persistence**: If the analyst needed to re-run analysis on the same evidence, the staging dir was gone after `PreparedEvidence.cleanup()` and the E01 had to be extracted again.

### Decision

`stage_evtx(source, dest)` was added to `evidence.py`. It extracts EVTXs directly to a caller-specified destination with no temp dir. The monitor uses:

```
<job_dir>/evtx/<source_stem>/
```

For a bulk hunt against three E01 images, the layout is:

```
ChainsawMCPJobs/
└── <job_id>/
    ├── job.json
    ├── hunt_results.json
    ├── chainsaw_stderr.log
    └── evtx/
        ├── base-rd-01-cdrive/
        ├── base-dc-cdrive/
        └── base-file-cdrive/
```

Chainsaw is invoked with `chainsaw hunt <job_dir>/evtx/ --json --skip-errors` and finds all sources recursively.

**Consequences:**
- Staging path is deterministic and stable — derived from `CHAINSAWMCP_JOBS_DIR` and job ID, never from system temp
- No cleanup step; EVTXs persist alongside results for re-analysis
- `PreparedEvidence` and its cleanup lifecycle are no longer used in the monitor path (only retained for the standalone `prepare_evidence` tool)
- Job directory accumulates EVTX files (~hundreds of MB per image); `CHAINSAWMCP_JOBS_DIR` should be on a volume with adequate space

---

## Decision 9: `start_bulk_hunt` Tool — Multiple Sources, One Job

**A new tool `start_bulk_hunt` accepts a list of evidence paths and processes them in a single Chainsaw run under one job ID.**

### Problem

Processing multiple E01 images required calling `start_hunt` once per image, producing N separate job IDs and N separate result sets. Loading and correlating results across multiple jobs required the analyst to call `load_hunt_results` repeatedly with different IDs and mentally merge the findings.

### Decision

`start_bulk_hunt` creates one job, spawns one monitor, and produces one `hunt_results.json`. The monitor prepares each source in sequence (staging to `evtx/<source_stem>/`) and invokes Chainsaw once against the combined `evtx/` directory.

```
start_bulk_hunt(paths=["/evidence/host-dc.E01", "/evidence/host-rd.E01", "/evidence/host-wkstn.E01"])
→ job ID: a1b2c3d4
→ monitor prepares all three in background
→ chainsaw hunt <job_dir>/evtx/ --json
→ one hunt_results.json with combined findings
→ one load_hunt_results() call
```

**Consequences:**
- All endpoint findings are in a single result set; cross-host correlation is immediate
- Analyst workflow is unchanged (`load_hunt_results` → `chainsaw_report` → `get_detections`)
- Sources are prepared sequentially in the monitor; a failure on one source fails the whole job

---

## Updated Tool Catalogue

| Tool | Purpose |
|---|---|
| `prepare_evidence` | Synchronous E01 staging for inspection (may timeout on large images — prefer `start_hunt`) |
| `start_hunt` | Begin a detached hunt against one EVTX dir or E01 image; returns immediately |
| `start_bulk_hunt` | Begin a detached hunt against multiple E01 images; one job, one result set |
| `load_hunt_results` | Load completed results into session for analysis |
| `chainsaw_report` | Structured summary with severity breakdown |
| `get_detections` | Drill-down by rule name or severity |

---

## Alternatives Considered

| Alternative | Reason Rejected |
|---|---|
| Increase `CHAINSAW_TIMEOUT` | Root cause is client tool budget, not server timeout — increasing the limit doesn't help |
| Chunked EVTX processing (batch by N files) | Significantly more complex; Chainsaw's cross-file correlation would be broken |
| Folder-watching daemon | Requires a persistent background service; adds operational complexity for IR deployments |
| Fully automatic LLM report on completion | One-shot, no follow-up questions; breaks local-LLM privacy model |
| asyncio task with longer polling window | Same fundamental problem — MCP session must remain open |
