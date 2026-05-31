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


| Alternative | Reason Rejected |
|---|---|
| Increase `CHAINSAW_TIMEOUT` | Root cause is client tool budget, not server timeout — increasing the limit doesn't help |
| Chunked EVTX processing (batch by N files) | Significantly more complex; Chainsaw's cross-file correlation would be broken |
| Folder-watching daemon | Requires a persistent background service; adds operational complexity for IR deployments |
| Fully automatic LLM report on completion | One-shot, no follow-up questions; breaks local-LLM privacy model |
| asyncio task with longer polling window | Same fundamental problem — MCP session must remain open |
