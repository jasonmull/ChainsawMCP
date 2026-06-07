# Architecture Decision Records — ChainsawMCP

---

# Initial Build

**Date:** 2026-05-18  
**Status:** Accepted  
**Deciders:** Jason Mull  

---

## Context

Initial build of the ChainsawMCP server. Core goals: wrap Chainsaw as an MCP tool, handle E01 evidence preparation, return parsed hits to the LLM client for analysis. No server-side LLM calls.

---

## Decision 1: Run Chainsaw as a background asyncio task, poll for status

`chainsaw_hunt` is an `async` MCP tool handler. Originally it called `subprocess.run()` directly — a blocking call that froze the asyncio event loop for the entire duration of the hunt. On large evidence sets (e.g. 296 EVTX files), hunts can take several minutes. The MCP transport's own keepalive/timeout fires before Chainsaw finishes, causing a silent hang from the client's perspective.

**Decision:** Wrap the blocking `subprocess.run()` in `asyncio.to_thread()` so the event loop stays alive. `chainsaw_hunt` now launches a background `asyncio.Task` and returns immediately. A new `hunt_status` tool exposes task state (`idle / running / done / error`), elapsed time, and hit count on completion. The client polls `hunt_status` until the hunt settles.

**Alternative considered — MCP log notifications:** Use `asyncio.create_subprocess_exec()` to read Chainsaw's stderr line-by-line and forward each line as an MCP `notifications/message`. Ruled out because client support for log notifications is inconsistent (Claude Desktop surfaces them, OpenWebUI may not) and Chainsaw's progress output format is not stable across versions. The polling model works with any MCP client.

**Consequences:**
- Callers must poll `hunt_status` rather than waiting on `chainsaw_hunt` to return results
- `chainsaw_report` guards against being called before a hunt completes
- `prepare_evidence` guards against re-staging while a hunt is in flight
- `CHAINSAW_TIMEOUT` env var (default 1800s) controls the subprocess timeout; previously hardcoded to 600s

---

## Decision 2: Suppress Chainsaw progress output — line-by-line JSON parse, not a flag

Chainsaw writes a progress bar to stdout when `--json` is active. This pollutes the JSON stream and caused parse failures on larger evidence sets.

**Initial attempt:** Pass `--no-progress` to suppress stdout noise. `--no-progress` does not exist in the installed version of Chainsaw — it caused Chainsaw to exit with an error.

**Decision:** Remove `--no-progress`. The `_parse_output()` function parses line-by-line and silently discards any line that fails `json.loads()`, so progress output mixed into stdout is harmlessly dropped. No flag needed.

**Lesson:** Do not add Chainsaw flags without verifying them against the installed binary's `--help` output. Chainsaw's CLI has changed across versions. The usage line from this session: `chainsaw.exe hunt --json --preprocess <RULES> [PATH]...`

---

## Decision 3: No server-side LLM enrichment — client drives analysis

The original design included a `chainsaw_enrich` tool that batched Chainsaw hits by rule/tactic and sent them to Ollama (`foundationsec:8b`) for narrative enrichment before formatting the report. This was built on the assumption that the MCP client might not have strong enough reasoning to analyse raw Chainsaw JSON.

**Decision:** Remove `chainsaw_enrich` entirely. The MCP client — whether Claude Desktop or OpenWebUI with a local model — is already an LLM and can analyse the hunt results directly in conversation. Having the server make its own LLM calls creates a redundant second model invocation and introduces an Ollama dependency that neither target use case actually needs.

**Alternatives considered:**
- *Keep `chainsaw_enrich` as optional with configurable backend:* The "client" mode would be a no-op; the "ollama" mode duplicates what the client model already does with full conversational context.
- *Anthropic API backend:* If you have an Anthropic API key, you have Claude Desktop. If you're using OpenWebUI, your local model is the reasoning engine. No gap to fill.

**Consequences:**
- No Ollama dependency. No API keys. Server makes zero LLM calls.
- `chainsaw_report` formats raw hits directly — hit counts, severity, sample events per rule.
- The client LLM provides all narrative analysis interactively, which is better than fire-and-forget batch prompts anyway.

---

## Decision 4: Chainsaw flag correctness — `--rule` (singular) and `--mapping` required for Sigma

Two flag bugs were present in the initial implementation of `_build_command()`:

1. The rules flag was `--rules` (plural). Chainsaw's actual flag is `--rule` (singular).
2. When using `--sigma`, Chainsaw requires a `--mapping` file that maps Sigma field names to Windows Event Log field names. Without it, Sigma rules load but match nothing silently — no error, no hits.

**Decision:**
- Correct `--rules` → `--rule`
- Add `--mapping` as a first-class parameter alongside `--sigma`. Raise `ChainsawError` early if `sigma_path` is provided without a `mapping_path`, rather than letting Chainsaw silently produce zero hits.
- Add `CHAINSAW_MAPPING` env var. Standard value: `mappings/sigma-event-logs-all.yml` (ships with Chainsaw).

**Lesson:** Do not assume Chainsaw CLI flags match documentation or intuition. Before adding any new subprocess argument, verify it against `chainsaw hunt --help` on the actual installed binary.

**Consequences:**
- `run_hunt()` now accepts `mapping_path` parameter
- Missing mapping with Sigma path is a hard error, not a silent failure
- All three paths (`--rule`, `--sigma`, `--mapping`) are independently configurable via env vars or tool parameters

---

# OpenWebUI / Ollama Integration Strategy

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

## Decision 5: Use mcpo (OpenAPI proxy) rather than OpenWebUI's native MCP

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

## Decision 6: Make `chainsaw_hunt` synchronous for tool-calling clients

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

## Decision 7: Streamable HTTP transport on Windows uses `WindowsSelectorEventLoopPolicy`

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

## Decision 8: OpenWebUI inlet Filter for base and reasoning models

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

## Alternatives Considered (OpenWebUI Integration)

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

# Detached Hunt Execution Architecture

**Date:** 2026-05-30  
**Status:** Accepted  
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

## Decision 9: Detached Subprocess Execution

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

## Decision 10: Disk-Persisted Job State

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

## Decision 11: Webhook Notification Instead of Polling

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

## Decision 12: Remove `chainsaw_hunt` and `hunt_status` Tools

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

## Decision 13: `--skip-errors` Always Enabled

**Chainsaw is always invoked with `--skip-errors`.**

IR evidence collections frequently contain corrupt, partial, or locked EVTX files. Without `--skip-errors`, a single unreadable file aborts the entire hunt. This is particularly problematic for large multi-endpoint collections where some files may have been collected under active use.

The flag is baked into `_build_command()` rather than exposed as a user option because there is no scenario in which aborting a hunt for a single bad file is preferable to skipping it.

---

## Decision 14: No Server-Side LLM Calls (Retained from Original Design)

**The MCP server makes no LLM calls. All reasoning is provided by the client.**

Automatic report generation on hunt completion was considered during the detached execution design. A fully automatic flow (hunt → LLM analysis → report file) would eliminate the need for an MCP session entirely for basic triage.

This was rejected because:

1. A one-shot report cannot answer follow-up questions — the primary value of the LLM is interactive investigation, not static summarization
2. Server-side LLM calls would require an API key on the server, breaking the privacy model for locally-hosted deployments
3. The client already has a capable model; running a second model on the server provides no benefit

**Consequence:** The analyst must open an MCP session to perform analysis. This is intentional — the session is where the value is delivered.

---

## Decision 15: E01 Preparation Delegated to the Monitor Process

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

## Decision 16: EVTXs Staged to Job Directory, Not `/tmp`

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

## Decision 17: `start_bulk_hunt` Tool — Multiple Sources, One Job

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

## Current Tool Catalogue

| Tool | Purpose |
|---|---|
| `prepare_evidence` | Synchronous E01 staging for inspection (may timeout on large images — prefer `start_hunt`) |
| `start_hunt` | Begin a detached hunt against one EVTX dir or E01 image; returns immediately |
| `start_bulk_hunt` | Begin a detached hunt against multiple E01 images; one job, one result set |
| `load_hunt_results` | Load completed results into session for analysis |
| `chainsaw_report` | Structured summary with severity breakdown |
| `get_detections` | Drill-down by rule name or severity |

---

## Alternatives Considered (Detached Hunt Architecture)

| Alternative | Reason Rejected |
|---|---|
| Increase `CHAINSAW_TIMEOUT` | Root cause is client tool budget, not server timeout — increasing the limit doesn't help |
| Chunked EVTX processing (batch by N files) | Significantly more complex; Chainsaw's cross-file correlation would be broken |
| Folder-watching daemon | Requires a persistent background service; adds operational complexity for IR deployments |
| Fully automatic LLM report on completion | One-shot, no follow-up questions; breaks local-LLM privacy model |
| asyncio task with longer polling window | Same fundamental problem — MCP session must remain open |

---

# Protocol SIFT Integration

**Date:** 2026-06-06  
**Status:** Accepted  
**Deciders:** Jason Mull  
**Branch:** `claude/keen-bardeen-e0GOC`  
**PR:** [#47](https://github.com/jasonmull/ChainsawMCP/pull/47)

---

## Context

Protocol SIFT is the SANS Institute initiative to integrate Claude Code into the SIFT Workstation as an agentic DFIR command center built on MCP. The "Find Evil!" hackathon (deadline June 15 2025) defines four judging tracks:

- Track 1 (25%): Forensics MCP Server Engineering — structured/paginated JSON, complex parameters
- Track 2 (25%): Context Engineering / Progressive Disclosure — SKILL.md pattern, no monolithic CLAUDE.md
- Track 3 (20%): Self-Correction Loop — Ralph Wiggum structured errors, retry with fix, iteration cap
- Track 4 (25%): Inference Constraint / Courtroom Track — cryptographic chain of custody for findings
- UX/Vibe (15%): Setup experience, first-run ergonomics

The hackathon brief explicitly calls out thin wrappers as disqualifying. MCP servers must handle complex parameters, paginate massive outputs, and return structured parsed JSON that Claude can reason over.

---

## Decision 18: Migrate server to bundled FastMCP

**Problem:** The raw `mcp.server.Server` API requires a `@app.list_tools()` handler returning a schema list and a separate `@app.call_tool()` dispatch function. Tool descriptions live in `list_tools()` while logic lives in `call_tool()`, creating two places to update for every change. The hackathon brief and SIFT setup guide both reference FastMCP by name — judges will expect it.

**Decision:** Migrate `server.py` to use the **bundled FastMCP** (`from mcp.server.fastmcp import FastMCP`) rather than the standalone FastMCP 2.0+ package.

**Rationale:**
- Single import change — no new dependency, no regression risk to existing logic
- `@mcp.tool()` decorators collocate description (docstring) with implementation
- Auto-schema generation from type hints is correct by construction — critical for paginated JSON parameters and `setup_environment`
- Wire protocol is identical — Claude Code cannot distinguish between server implementations
- Full standalone FastMCP 2.0 migration (Providers, Transforms, OpenTelemetry) is a future option

**Changes:**
- `from mcp.server import Server` → `from mcp.server.fastmcp import FastMCP`
- `app = Server(...)` → `mcp = FastMCP("ChainsawMCP")`
- `@app.list_tools()` / `@app.call_tool()` dispatch → `@mcp.tool()` on each handler
- Errors: `return _error(text)` → `raise ValueError(text)`
- Returns: `return _ok(text)` → `return text`
- stdio: `_run_stdio()` → `mcp.run()`
- HTTP transport: keep existing Starlette/uvicorn setup, access underlying server via `mcp._mcp_server` for `StreamableHTTPSessionManager`

**Import conflict resolution:** `prepare_evidence` and `get_detections` are used as both imported functions and tool names. Resolved with import aliases: `from .evidence import prepare_evidence as _stage_evidence` and `from .report import get_detections as _filter_detections`.

---

## Decision 19: Structured paginated JSON output for Protocol SIFT orchestration

**Problem:** ChainsawMCP's output was plain text formatted for human reading. A 500-hit hunt dumps thousands of tokens at once. The hackathon brief explicitly states: *"Do not just pass raw terminal output… paginate massive outputs (to prevent token bloat)."* Without pagination, a large hunt breaks the orchestration loop.

**Decision:** Add `output_format: str = "text"` and pagination parameters (`page`, `page_size`) to `get_detections`. Add `output_format` to `chainsaw_report`. Default to `"text"` to avoid breaking existing usage.

**JSON output shape for `get_detections`:**
```json
{
  "filters": {"rule": "", "severity": ""},
  "total": 42,
  "page": 1,
  "page_size": 25,
  "total_pages": 2,
  "hits": [{"rule": "...", "severity": "...", "timestamp": "...", "event_id": "...", "computer": "...", "data": {}}]
}
```

**JSON output shape for `chainsaw_report`:**
```json
{
  "generated": "...",
  "evidence": "...",
  "report_file": "...",
  "summary": {"total": 42, "rules_triggered": 5, "critical": 0, "high": 3, "medium": 12, "low": 5, "info": 22},
  "top_rules": [{"rule": "...", "severity": "...", "count": 3}]
}
```

**Pagination applies to `get_detections` only** — `chainsaw_report` returns an aggregated summary (severity counts + top-N rules) that is inherently small.

**New functions in `report.py`:** `format_summary_json()`, `get_detections_json()`, `_hit_to_dict()`.

---

## Decision 20: Inference constraint provenance logging (SHA-256 chain of custody)

**Problem:** The biggest barrier to AI in forensics is the "Courtroom Problem" — a judge cannot accept findings that might have originated from an LLM's imagination rather than from the evidence. The hackathon judging criterion states: *"Your solution must definitively prove the concept of 'High Inference Constraint' — demonstrating to a judge that the evidence came from chainsaw, not from the AI's imagination."*

**Decision:** On hunt completion, write `chainsaw_provenance.json` to the job directory. Surface the provenance record in every `load_hunt_results` response so it travels with the findings into Claude's context.

**Provenance record schema:**
```json
{
  "command": ["chainsaw", "hunt", "..."],
  "output_file": "/tmp/chainsawmcp_jobs/<job_id>/hunt_results.json",
  "output_sha256": "abc123...",
  "completed_at": "2026-06-06T12:00:00Z",
  "chainsaw_version": "2.16.0"
}
```

**Implementation:**
- `_sha256(path)` — 64KB chunk streaming SHA-256 in `monitor.py`
- `_chainsaw_version(binary)` — runs `chainsaw --version`, returns first stdout line or `"unknown"`
- `_write_provenance(job_id, cmd, results_file, completed_at)` — writes the record to `<jobs_dir>/<job_id>/chainsaw_provenance.json`
- `load_hunt_results` reads provenance from job dir and includes it in the response under `"provenance"`

**Chain of custody guarantee:** The SHA-256 hash is computed over the raw Chainsaw output file before any parsing. Any modification to findings after the hunt is detectable by re-hashing.

---

## Decision 21: Structured error responses for Ralph Wiggum self-correction loop

**Problem:** ChainsawMCP hunt failures surfaced as vague text or were invisible to the MCP client (stderr written to a file only the monitor could read). For Claude to self-correct automatically, errors need to be structured and include the raw stderr in the tool response.

**Decision:** `load_hunt_results` on a failed job raises `ValueError(json.dumps(error_payload))` with a structured error payload including all fields needed for automated retry.

**Error payload schema:**
```json
{
  "status": "error",
  "job_id": "...",
  "error": "chainsaw exited with code 1",
  "exit_code": 1,
  "stderr": "error: no sigma rules found at /opt/sigma",
  "suggested_fix": "run setup_environment",
  "attempt": 1
}
```

**`suggested_fix` values and their meanings:**
- `"run setup_environment"` — Chainsaw binary not found or Sigma rules missing
- `"Verify --sigma path"` — Sigma rules path exists but rules failed to load
- `"Verify --mapping path"` — Mapping file not found
- `"Verify evidence path"` — No EVTX files found at the staged path
- `"Check Chainsaw rules directory"` — Rules path missing or empty
- `"Check Chainsaw stderr for details"` — Unclassified error

**Attempt counter:** `jobs.py` initialises each job with `attempt = _count_prior_failures(evidence_path) + 1`. The Ralph Wiggum loop enforces a retry cap at `attempt >= 3` — SKILL.md documents this as the escalation threshold.

**`_classify_error` ordering:** Mapping check runs BEFORE sigma check because the mapping filename (`sigma-event-logs-all.yml`) contains the string "sigma" and would match the sigma branch incorrectly.

---

## Decision 22: `setup_environment` self-bootstrapping tool with no silent privilege escalation

**Problem:** Neither Chainsaw nor Sigma rules are pre-installed on a SIFT Workstation. Analysts must manually configure three separate paths before a hunt can run. The first-run experience is broken before a single tool call.

**Decision:** Add `setup_environment` as an explicit MCP tool that builds and installs all Chainsaw dependencies in one step. Default install targets are XDG user-writable paths — no sudo required on a standard Linux system. When a target directory is not writable, the tool emits exact shell commands for the analyst to run manually rather than escalating privileges silently.

**Install targets (defaults):**
| Component | Source | Path |
|---|---|---|
| `chainsaw` binary + rules + mappings | `cargo build --release` from cloned source | `~/.local/share/chainsaw/` |
| Sigma rules | `git clone --depth=1 https://github.com/SigmaHQ/sigma` | `~/.local/share/sigma/` |

**Build method:** `git clone --depth=1 https://github.com/WithSecureLabs/chainsaw` to a temp dir → `cargo build --release` → copy `target/release/chainsaw` to `<chainsaw_dir>/chainsaw` → copy `rules/` and `mappings/` from source tree → clean up temp dir. Requires `cargo` in PATH; if absent, the tool returns the rustup install command rather than failing with a subprocess error.

**Why `~/.local/share/` not `/opt/`:** XDG Base Directory spec — standard for user application data on Linux, no sudo required, survives OS upgrades. `/opt` is still supported via the `chainsaw_dir` / `sigma_dir` arguments; the tool emits sudo instructions when write access is lacking.

**Why `~/.local/share/sigma/` separate from `~/.local/share/chainsaw/`:** Other SIFT tools reference Sigma rules. A shared, conventional path avoids duplication and prevents version skew between tools.

**Why not auto-sudo:** Silent privilege escalation from within an MCP server process is a liability in an evidentiary context (Track 4). The tool is unprivileged and auditable.

**Post-install:** Resolved paths are written to `~/.chainsawmcp/config.json`. Subsequent `start_hunt` calls load them automatically — no manual path arguments needed.

**New module `src/chainsawmcp/setup.py`:**
- `check_environment()` — read-only status check; binary expected at `<chainsaw_dir>/chainsaw`
- `setup_environment()` — main entry point
- `_can_write(path)` — walks to nearest existing ancestor before checking `os.access(W_OK)`
- `_cargo_available()` — checks `shutil.which("cargo")`
- `_build_and_install_chainsaw(chainsaw_dir)` — clone → `cargo build --release` → copy binary + data files

---

## Decision 23: MCP registration + SKILL.md Progressive Disclosure pattern

**Problem:** ChainsawMCP is invisible to Protocol SIFT orchestration without explicit MCP registration. Stuffing all tool knowledge into a monolithic CLAUDE.md causes "context rot" — the brief identifies this as the primary failure mode for naive integrations. Judges explicitly require Progressive Disclosure.

**Decision:** Ship a `skills/evtx-analysis/SKILL.md` file that Claude loads on demand when EVTX artifacts or Windows investigation keywords are encountered, not on every session start. Add MCP registration instructions to README.

**SKILL.md responsibilities:**
- When to load (EVTX files, E01 images, Windows authentication/execution/lateral-movement questions)
- First-run setup with `setup_environment` (with ⚠️ analyst-confirmation warning)
- Standard four-step workflow: `start_hunt` → `load_hunt_results` → `chainsaw_report` → `get_detections`
- Completion promise: `<promise>CHAINSAW_HUNT_COMPLETE</promise>` (used by orchestration loop to gate follow-on skill loading)
- Ralph Wiggum error handling procedure including `attempt >= 3` escalation rule
- Severity interpretation table
- Follow-on skill references: memory-analysis, timeline, registry, network

**Registration command:**
```
claude mcp add ChainsawMCP -- python -m chainsawmcp.server
```

**`autoApprove` note:** `setup_environment` clones and compiles Chainsaw — takes several minutes. README recommends analyst confirmation before adding it to `autoApprove`.

---

## Updated Tool Catalogue

| Tool | Purpose |
|---|---|
| `prepare_evidence` | Synchronous E01 staging for inspection (may timeout on large images — prefer `start_hunt`) |
| `start_hunt` | Begin a detached hunt against one EVTX dir or E01 image; returns immediately |
| `start_bulk_hunt` | Begin a detached hunt against multiple E01 images; one job, one result set |
| `load_hunt_results` | Load completed results into session; includes provenance record for chain of custody |
| `chainsaw_report` | Structured summary with severity breakdown; supports `output_format="json"` |
| `get_detections` | Drill-down by rule name or severity; supports `output_format="json"` with pagination |
| `setup_environment` | Install Chainsaw and Sigma rules; write paths to `~/.chainsawmcp/config.json` |
