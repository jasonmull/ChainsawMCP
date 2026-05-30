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

## Alternatives Considered

| Alternative | Reason Rejected |
|---|---|
| Increase `CHAINSAW_TIMEOUT` | Root cause is client tool budget, not server timeout — increasing the limit doesn't help |
| Chunked EVTX processing (batch by N files) | Significantly more complex; Chainsaw's cross-file correlation would be broken |
| Folder-watching daemon | Requires a persistent background service; adds operational complexity for IR deployments |
| Fully automatic LLM report on completion | One-shot, no follow-up questions; breaks local-LLM privacy model |
| asyncio task with longer polling window | Same fundamental problem — MCP session must remain open |
