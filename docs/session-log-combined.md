# Session Logs — ChainsawMCP

---

# Session Log — 2026-05-18 (Part 1: Initial build)

**Branch:** `claude/build-mcp-server-Our54`

---

## Key Decisions and Findings

1. **The server should make zero LLM calls.** The original design had a full enrichment pipeline (batching, confidence tiering, roll-up synthesis via Ollama). After understanding the actual use cases — Claude Desktop and OpenWebUI — it became clear the client LLM handles this natively. Removing `chainsaw_enrich` simplified the server significantly and eliminated the only external dependency beyond Chainsaw itself.

2. **Chainsaw's CLI has sharp edges.** In a single session: `--rules` should be `--rule`, `--sigma` silently produces nothing without `--mapping`, and a reported `--no-progress` flag doesn't exist. The installed binary's `--help` output is the only reliable source of truth — not docs, not inference from similar tools.

3. **`--mapping` is mandatory for Sigma, not optional.** This is the most dangerous silent failure mode: Sigma rules load without error but match nothing if the mapping file is absent. The guard in `run_hunt()` (raise early if sigma without mapping) prevents a confusing "0 hits" result that looks like clean evidence.

## What Didn't Work

- **`chainsaw_enrich` with Ollama backend:** Built out fully — batching, confidence tiering (HIGH/MEDIUM/LOW), templated responses for LOW-severity rules, roll-up LLM call. Removed after clarifying that both target clients (Claude Desktop, OpenWebUI) are themselves LLMs that handle analysis naturally in conversation.
- **`--rules` flag (plural):** Rejected by Chainsaw. Corrected to `--rule`.
- **`--no-progress` flag:** Reported as needed by an external source; does not exist in the installed Chainsaw version. The existing line-by-line JSON parser discards non-JSON lines (including progress output) gracefully — no flag needed.

## Watch Points for Next Session

- **Chainsaw version on the deployment machine matters.** Verify all subprocess flags with `chainsaw hunt --help`. The main branch BUILD_LOG documents a `--preprocess` flag appearing in usage output — not yet explored.
- **`chainsaw_hunt` blocks the asyncio event loop.** On large evidence sets the MCP transport will hang. Needs `asyncio.to_thread()` + background task + `hunt_status` polling.
- **State is in-process only.** `_SessionState` lives in memory. Server restart = lost session.
- **No E01 mounting tested end-to-end.** Linux (`ewfmount`) and Windows (Arsenal Image Mounter) paths implemented but untested against real images.
- **Dead code in `config.py`:** `get_ollama_base_url()` and `get_ollama_model()` are leftovers from the enrichment design. Clean up before next feature addition.

---

# Session Log — 2026-05-18 (Part 2: Fix asyncio blocking hang)

**Branch:** `claude/fix-chainsaw-timeout-5XwnG`

---

## Key Decisions and Findings

1. **The hang was an asyncio blocking bug, not a timeout config problem.** `subprocess.run()` inside an `async` function blocks the entire event loop — there is no MCP-level timeout you can tune your way out of. The fix is structural: move blocking work to a thread via `asyncio.to_thread()`.

2. **Background task + polling is the right UX pattern for long-running tools in MCP.** The alternative (MCP log notifications) is cleaner in theory but unreliable in practice because client support varies. Polling via a status tool works everywhere.

3. **Don't assume Chainsaw CLI flags are stable across versions.** `--no-progress` was added based on reasonable inference but doesn't exist in the installed binary. Any future flag additions need to be verified against `chainsaw hunt --help` on the actual deployment target.

## What Didn't Work

- **`--no-progress` flag:** Added to suppress progress bar output from polluting the JSON stream. Chainsaw rejected it. Removed. The existing line-by-line JSON parser already handles mixed output gracefully.

## Watch Points for Next Session

- **Chainsaw version mismatch:** Before adding any subprocess arguments, run `chainsaw hunt --help` and confirm the flag exists. Usage line from this session: `chainsaw.exe hunt --json --preprocess <RULES> [PATH]...`
- **`--preprocess` flag:** Appeared in the usage line but not explored. May affect rule-loading performance.
- **Poll interval is client-controlled:** The server doesn't enforce how often `hunt_status` is called. An LLM client driving this autonomously will naturally space out calls.
- **No cancellation yet:** No way to cancel a running hunt. A `cancel_hunt` tool would be a reasonable addition.
- **State is in-process only:** `_SessionState` lives in memory. MCP server crash mid-hunt = all state lost.

---

# Session Log — 2026-05-30 (Part 1: E01 extraction overhaul)

**Topic:** Remove FUSE mount path, rootless E01 extraction via pytsk3, stdin fix  
**Branch:** `claude/adoring-lovelace-L4rWE`  
**Tests:** 47 passed, 0 failed

---

## What Was Fixed This Session

### 1. Removed FUSE / privileged mount path entirely
- `ewfmount` + `ntfs-3g` requires `CAP_SYS_ADMIN` — not viable in most environments
- Replaced entirely with rootless extraction using pytsk3 + TSK CLI fallback
- No FUSE, no kernel mounts, no root required

### 2. Dropped pyewf dependency
- pyewf is NOT on PyPI — `pip install pyewf` always fails
- pytsk3's `Img_Info()` opens E01 files directly when libtsk is compiled with libewf (the default for system packages)
- Removed pyewf from `pyproject.toml` completely

### 3. Two-tier E01 extraction chain (`evidence.py`)
```
_extract_e01()
  ├── _extract_e01_rootless()   # pytsk3 Python API (preferred)
  │     - pytsk3.Img_Info(path) opens E01 natively
  │     - Walks partition table, finds NTFS partitions
  │     - Falls back to raw-partition (offset 0) if no partition table
  │     - Copies all .evtx files to staging dir
  └── _extract_e01_via_tsk_cli()  # fls + icat (fallback if pytsk3 fails)
        - Uses mmls to find NTFS partition offset
        - Uses fls -r -p to list all files
        - Uses icat to extract each .evtx by inode
```

### 4. Fixed OSError escaping pytsk3 and showing as raw C++ error text
- Wrapped offset-0 `FS_Info()` attempt in try/except → EvidenceError
- Added `OSError` to `_extract_e01()` catch clause so it falls through to CLI
- Added broad `except Exception` in `_prepare_evidence()` server handler

### 5. Fixed MCP stdio transport stdin contention
- Chainsaw subprocess was inheriting stdin from the MCP process
- MCP stdio transport uses stdin for the protocol; subprocess inheritance caused corruption
- Fix: `stdin=subprocess.DEVNULL` in `subprocess.run()` call in `chainsaw.py`

### 6. Made `chainsaw_hunt` non-blocking (fire-and-forget)
- Previously blocked until Chainsaw finished — exhausted LLM tool-call budget
- Now uses `asyncio.create_task(_run_hunt_background(...))` and returns immediately
- `hunt_status` tells the LLM to wait 60 seconds between checks
- Tool descriptions updated with explicit "Do NOT poll more than once per 60 seconds" instruction

### 7. Removed fabricated CLI flags
- `--accept-license` and `--no-progress` were added incorrectly — these flags DO NOT EXIST in Chainsaw
- Chainsaw would fail immediately on launch with these flags
- Reverted `_build_command` to: `[binary, "hunt", evtx_dir, "--json"]`

---

## Outstanding Issue: Hunt Still Not Completing

The user reports the hunt completes the extraction step (EVTX files pulled from E01) but then times out or hangs during the actual Chainsaw run. This was not resolved before the session was closed.

### Suspected causes to investigate:

**A. Chainsaw interactive prompt**  
Chainsaw may be displaying an interactive license acceptance prompt (even without `--accept-license`). Check if `chainsaw hunt` requires any interactive input on first run.
- Try running manually: `chainsaw hunt <evtx_dir> --json --rules <rules>` and see if it pauses
- If it prompts, look for a `--accept-license` equivalent in the actual installed Chainsaw version
- Run `chainsaw --help` and `chainsaw hunt --help` to see real flags

**B. Chainsaw binary version mismatch**  
The MCP server logs showed version `1.27.1` still running after code changes — the old installed binary was cached. After any change to `chainsaw.py`, reinstall: `pip install --force-reinstall .`

**C. No rules path = no output**  
If neither `CHAINSAW_RULES` nor `CHAINSAW_SIGMA` env vars are set, and no `rules_path`/`sigma_path` is passed to `chainsaw_hunt`, Chainsaw runs with no rules and produces empty output. This is not a hang, but looks like one if the LLM waits for detections that never come.
- Confirm rules/sigma paths are set: `echo $CHAINSAW_RULES` and `echo $CHAINSAW_SIGMA`

**D. Output file parsing on large result sets**  
The raw output file is `hunt_results.json`. If Chainsaw produces very large output, the in-memory parse in `_parse_output_file()` could be slow (not a hang, but could look like one).

**E. Timeout too short**  
Default timeout is 1800 seconds (30 min). For large EVTX sets this may not be enough.
- Override: `export CHAINSAW_TIMEOUT=3600`

### Debugging steps for next session:
1. SSH into the environment and run Chainsaw manually against the staged EVTX dir
2. Check `/tmp/chainsawmcp/hunt_results.json` while the hunt is running — is Chainsaw writing to it?
3. Run `ps aux | grep chainsaw` to confirm it's actually running
4. Check `chainsaw hunt --help` output for the real flag list (especially any license flag)

---

## Architecture at Session Close (`_build_command`)

```python
cmd = [str(binary), "hunt", str(evtx_dir), "--json"]
if rules_path:
    cmd += ["--rule", str(rules_path)]
if sigma_path:
    cmd += ["--sigma", str(sigma_path)]
if mapping_path:
    cmd += ["--mapping", str(mapping_path)]
cmd += extra_args
```

`subprocess.run` called with `stdout=fh`, `stderr=subprocess.PIPE`, `stdin=subprocess.DEVNULL`, `text=True`, `timeout=get_hunt_timeout()` (default 1800s).

---

## Key Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `CHAINSAW_BIN` | `chainsaw` / `chainsaw.exe` | Path to Chainsaw binary |
| `CHAINSAW_RULES` | (none) | Path to Chainsaw rules dir |
| `CHAINSAW_SIGMA` | (none) | Path to Sigma rules dir |
| `CHAINSAW_MAPPING` | (none) | Path to Sigma mapping file |
| `CHAINSAW_TIMEOUT` | `1800` | Hunt timeout in seconds |
| `CHAINSAW_OUTPUT_DIR` | `/tmp/chainsawmcp` | Where hunt_results.json is written |
| `AIM_CLI` | (PATH lookup) | Windows only: path to aim_cli.exe |

---

## File State at Session Close

- `src/chainsawmcp/chainsaw.py` — clean, flags removed, stdin=DEVNULL present
- `src/chainsawmcp/evidence.py` — rootless E01 extraction, no FUSE code
- `src/chainsawmcp/server.py` — fire-and-forget hunt, 60s polling contract
- `src/chainsawmcp/config.py` — unchanged from prior session
- `tests/test_chainsaw.py` — 47 tests, all passing
- `pyproject.toml` — pytsk3 in deps, pyewf removed

---

# Session Log — 2026-05-30 (Part 2: Detached hunt execution)

**Topic:** Architectural overhaul — detached hunt execution, webhook notification, README polish  
**Branch:** `claude/dazzling-thompson-0gIpU`  
**Commits:** 10

---

## Problem Statement

The existing MCP server embedded Chainsaw execution inside a synchronous tool call. A polling tool (`hunt_status`) blocked for 60 seconds per call while waiting for Chainsaw to finish. This worked for small evidence sets (~300 MB) but failed consistently for realistic IR workloads:

- 3 GB / 317 EVTX files → 30+ minute Chainsaw run → MCP client tool budget exhausted → timeout with no results
- Target use case (10+ GB, multiple endpoints) was completely intractable

---

## Design Exploration

**Round 1 — Standalone hunt script**  
Initial proposal: a CLI script that runs the hunt outside MCP, writes `hunt_results.json`, and a new `load_hunt_results` MCP tool reads it. Clean separation of concerns; all existing logic reused.

**Round 2 — Prompt-triggered agent flow**  
User refined the goal: the analyst should be able to say *"Run a hunt on the event logs"* to trigger everything, without running a CLI script manually. This led to `start_hunt` as an MCP tool that spawns the hunt as a detached process.

**Round 3 — Folder-watching daemon**  
Considered a persistent daemon that watches a folder and auto-triggers on new files. Rejected in favour of the prompt-triggered model — simpler operationally, no persistent service required.

**Round 4 — Automatic LLM reporting**  
Considered firing an LLM analysis automatically when the hunt finishes (fully hands-off). Rejected: a one-shot report cannot handle follow-up questions, which is where the investigative value lives. The interactive MCP session is the product.

**Final design:** `start_hunt` → detached runner → disk-persisted job state → webhook → `load_hunt_results` → interactive analysis session.

---

## Implementation

### New files

| File | Purpose |
|---|---|
| `src/chainsawmcp/jobs.py` | Disk-persisted job state: create, update, read, find latest completed job, cross-platform PID liveness check |
| `src/chainsawmcp/monitor.py` | Detached runner: opens its own file handles, executes Chainsaw (blocking), updates `job.json`, POSTs webhook |
| `assets/workflow.svg` | Workflow diagram for README |
| `docs/ADR-001-detached-hunt-architecture.md` | ADR for this session's architecture decisions |

### Modified files

**`chainsaw.py`**
- Added `spawn_hunt_detached()` — spawns `chainsawmcp.monitor` as a detached process, passing the Chainsaw command as JSON via argv; returns runner PID
- Added `parse_output_file()` public alias
- Added `import json, sys` to support the above
- Added `encoding="utf-8", errors="replace"` to `subprocess.run()` stderr capture — fixes `UnicodeDecodeError` on Windows where the default encoding (cp1252) cannot decode all bytes Chainsaw emits
- Added `--skip-errors` to `_build_command()` — prevents hunt abort on single corrupt EVTX file

**`config.py`**
- Added `get_jobs_dir()` — reads `CHAINSAWMCP_JOBS_DIR`, defaults to system temp / `chainsawmcp_jobs/`
- Added `get_webhook_url()` — reads `CHAINSAWMCP_WEBHOOK_URL`

**`server.py`**
- Added `start_hunt` tool and handler — prepares evidence, creates job, spawns detached runner, returns immediately
- Added `load_hunt_results` tool and handler — finds latest completed job or loads by ID, populates session state
- Removed `chainsaw_hunt` tool from catalogue — was causing Claude to select the legacy blocking path
- Removed `hunt_status` tool from catalogue — kept MCP session alive, defeating the purpose of detached execution
- Updated `prepare_evidence` description and response text to direct toward `start_hunt`, not `chainsaw_hunt`
- Updated `chainsaw_report` description to reference `load_hunt_results` instead of `hunt_status`

---

## Bugs Found and Fixed

### 1. Windows `DETACHED_PROCESS` invalid handle (critical)
**Symptom:** Chainsaw panicked immediately with `Os { code: 6, message: "The handle is invalid." }` on Windows.  
**Cause:** File handles opened in the Python MCP process are not valid in a detached child process on Windows. The original design passed `stdout=file_handle` to a `DETACHED_PROCESS` Chainsaw invocation.  
**Fix:** The detached process is now the Python runner (`monitor.py`), which opens its own file handles and then runs Chainsaw with a normal blocking `subprocess.run()`. No handle crosses a process boundary.

### 2. `UnicodeDecodeError` on Windows stderr capture
**Symptom:** `UnicodeDecodeError: 'charmap' codec can't decode byte 0x90` in `subprocess.py` thread.  
**Cause:** `subprocess.run(..., text=True)` defaults to the system encoding (cp1252 on Windows). Chainsaw's stderr output contains bytes outside the cp1252 range.  
**Fix:** Added `encoding="utf-8", errors="replace"` to the `subprocess.run()` call in `run_hunt()`.

### 3. Webhook payload rejected by Discord
**Symptom:** Webhook URL was valid (verified externally) but no notification was received.  
**Cause:** The webhook payload contained only raw data fields (`job_id`, `hit_count`, etc.). Discord requires a `content` field containing the message text. Slack requires `text`. Neither was present.  
**Fix:** Payload now includes both `content` (Discord) and `text` (Slack) set to a formatted human-readable message, plus the raw data fields for generic receivers.  
**Additional fix:** Webhook POST failures now write to `webhook_error.log` in the job directory instead of being silently discarded.

### 4. Claude selecting legacy tools despite `start_hunt` being available
**Symptom:** Claude consistently called `prepare_evidence` → `chainsaw_hunt` → `hunt_status` even after `start_hunt` was added to the tool catalogue.  
**Cause:** `prepare_evidence`'s description said "Must be called before any other tool" and its response said "Next step: call chainsaw_hunt." `chainsaw_hunt` appeared earlier in the tool list than `start_hunt`.  
**Fix 1:** Updated tool descriptions — `chainsaw_hunt` marked LEGACY, `prepare_evidence` directed to `start_hunt`.  
**Fix 2:** Removed `chainsaw_hunt` and `hunt_status` from the tool catalogue entirely. With no ambiguous alternatives, Claude consistently uses `start_hunt`.

---

## Configuration Added

| Variable | Purpose | Default |
|---|---|---|
| `CHAINSAWMCP_JOBS_DIR` | Job state and results storage | system temp / `chainsawmcp_jobs/` |
| `CHAINSAWMCP_WEBHOOK_URL` | Webhook POST target on completion | None (silent if unset) |

---

## README Changes

- Rewrote for hackathon submission — clearer problem statement, workflow diagram, design rationale section
- Added local LLM emphasis (OpenWebUI, LM Studio, Ollama) throughout
- Added OpenWebUI HTTP mode setup instructions
- Corrected Linux E01 requirements: `pytsk3` (rootless, in-process) replaces the incorrect `ewf-tools`/`ntfs-3g` listing
- Reordered Tools section to match execution order (1–5)
- Added `--skip-errors` note to `start_hunt` reference
- Attempted SVG workflow diagram (two iterations); reverted to ASCII chart pending external image generation

---

## Test Results

All 47 existing tests passed throughout. The test suite mocks all subprocess calls and remained valid across all changes — no new tests were added in this session, which is a gap worth addressing before a public release.

---

## State at Session End

- Branch `claude/dazzling-thompson-0gIpU` is ahead of `main` by 10 commits
- All changes pushed to remote
- **Not yet merged to main**
- **Not yet published to PyPI**
- Recommended next steps before release:
  1. End-to-end test on Windows: large evidence set, confirmed webhook delivery, confirmed `load_hunt_results` → analysis flow
  2. Merge branch to `main`
  3. Tag `v0.1.0`
  4. Create GitHub release
  5. Publish to PyPI (optional for hackathon; `pip install git+https://github.com/...` works immediately)

---

# Session Log — 2026-05-31: Bulk hunt, MCP timeout elimination, job-dir staging

**Topic:** Bulk E01 hunt support, MCP timeout elimination, job-dir staging  
**Branch:** `claude/compassionate-davinci-ZjqwT`  
**Commits:** 3

---

## Problem Statement

After the detached execution architecture landed (2026-05-30), two new failure modes appeared during bulk IR processing:

1. **MCP timeout on E01 preparation**: `start_hunt` called `prepare_evidence()` synchronously before spawning the monitor. For large E01 images (3–5 GB), pytsk3/TSK extraction takes 3–5 minutes. The MCP client cancels requests at ~4 minutes with `-32001: Request timed out`. The server continued working but the tool response was discarded — Claude never received the job ID and the hunt effectively vanished.

2. **Staging directory destroyed between calls**: Calling `prepare_evidence(second.E01)` triggered `state.evidence.cleanup()` which deleted the first image's staging directory before its hunt had started. `start_hunt('/tmp/chainsawmcp_XXX/evtx')` then returned "Path does not exist."

3. **No bulk workflow**: Processing five E01 images required five sequential `start_hunt` calls, producing five separate job IDs and result sets that the analyst had to load and correlate independently.

---

## Design Decisions

### Move E01 preparation into the monitor

The root cause of the timeout was performing preparation synchronously in the MCP tool handler. The fix is to defer it entirely: `start_hunt` now returns immediately after creating a job record and spawning the monitor, passing `{"evidence_path": "..."}` as a config dict. The monitor detects this, calls `stage_evtx()`, then builds and runs the Chainsaw command.

The monitor's payload type determines its mode:
- `list` → legacy direct-command (EVTX dir already prepared, used by the EVTX-dir path of `start_hunt`)
- `dict` with `"evidence_path"` → single E01; monitor does prep then hunt
- `dict` with `"evidence_paths"` → bulk; monitor preps all sources, runs chainsaw once

### Stage EVTXs into the job directory

`/tmp/chainsawmcp_XXXX/evtx` was replaced with `<CHAINSAWMCP_JOBS_DIR>/<job_id>/evtx/<source_stem>/`.

The new `stage_evtx(source, dest)` function in `evidence.py` writes directly to a caller-specified path with no intermediate temp dir. For E01 on Linux this wraps `_extract_e01()` directly. For Windows it wraps the AIM mount/copy/unmount sequence.

The job directory layout is now:

```
<job_id>/
├── job.json
├── hunt_results.json
├── chainsaw_stderr.log
└── evtx/
    ├── base-dc-cdrive/
    ├── base-rd-01-cdrive/
    └── base-wkstn-01/
```

Chainsaw is pointed at `<job_id>/evtx/` and recurses into all source subdirectories. No cleanup required; EVTXs persist alongside results.

### `start_bulk_hunt` — one job, one result set

New MCP tool. Accepts a `paths` array. Creates one job, spawns one monitor with all source paths. The monitor stages each source to `evtx/<stem>/` in sequence, then runs Chainsaw once against `evtx/`. One `load_hunt_results()` call loads the combined findings from all endpoints.

`_build_command()` in `chainsaw.py` was updated to accept `Path | list[Path]` for the evidence argument, enabling `chainsaw hunt /path/a /path/b --json` syntax (used as a fallback if needed).

---

## Implementation

### New/modified files

| File | Change |
|---|---|
| `evidence.py` | Add `stage_evtx(source, dest)` — extracts/copies EVTXs to specified dir; add `_stage_e01_windows` for AIM path |
| `monitor.py` | Full rewrite: three payload modes (list/single/bulk); stage to job dir; no PreparedEvidence/cleanup |
| `chainsaw.py` | `_build_command` accepts `Path \| list[Path]`; add `spawn_detached_config()` helper; add `spawn_detached_from_evidence()` |
| `jobs.py` | `create_job()` takes `evidence_path` (original source path); `evtx_path` updated by monitor post-staging |
| `server.py` | `start_hunt` returns immediately for E01 (no sync prep); add `start_bulk_hunt` tool; fix `chainsaw_report` guard; `load_hunt_results` sets `state.evidence_path` from job record |

### Removed

- Synchronous `prepare_evidence()` call inside `start_hunt` for E01 inputs
- `spawn_detached_from_evidence()` standalone function (replaced by `spawn_detached_config()`)
- `PreparedEvidence` objects and `ev.cleanup()` lifecycle from the monitor path

---

## Bugs Resolved

### 1. MCP timeout on E01 preparation (critical)
**Symptom:** `start_hunt` with a large E01 cancelled with `-32001: Request timed out` after 4 minutes. Claude never received the job ID.  
**Fix:** E01 preparation moved to monitor process. `start_hunt` now returns in under one second for all evidence types.

### 2. Staging dir destroyed by sequential `prepare_evidence` calls (critical)
**Symptom:** `start_hunt('/tmp/chainsawmcp_XXX/evtx')` returned "Path does not exist" immediately after a successful `prepare_evidence`.  
**Cause:** The second `prepare_evidence` call called `state.evidence.cleanup()` on the first image's staging dir.  
**Fix:** Staging is now per-job, inside the job directory. No global `state.evidence` to conflict between calls.

### 3. "Specified path does not exist" from Chainsaw
**Symptom:** Chainsaw stderr showed the staging path but reported it missing.  
**Root cause:** Staging was done in the MCP server process (`/tmp/chainsawmcp_XXX/`), but the path was referenced by the detached monitor process in a new session. Combined with the cleanup bug above, paths were reliably gone by the time Chainsaw ran.  
**Fix:** Staging to job dir eliminates the path ambiguity entirely.

---

## Configuration

No new environment variables. Existing `CHAINSAWMCP_JOBS_DIR` now also controls where EVTXs are staged. Ensure the volume has enough space for extracted EVTXs (~100–500 MB per image depending on host activity).

---

## Validation

Tested end-to-end on Linux with five E01 images (165–317 EVTXs each):
- `start_hunt` with single E01: returns job ID in < 2 seconds ✓
- `start_bulk_hunt` with five E01s: returns job ID in < 1 second; all five staged and hunted ✓
- Staging layout confirmed at `<CHAINSAWMCP_JOBS_DIR>/<job_id>/evtx/<source_stem>/` ✓
- Webhook fired on completion ✓
- `load_hunt_results` → `chainsaw_report` → `get_detections` chain working ✓

---

## State at Session End

- Branch `claude/compassionate-davinci-ZjqwT` pushed; not yet merged to `main`
- All five E01 images successfully processed
- Recommended next: merge to `main`, reinstall on analysis workstation from `main`

---

# Session Log — 2026-06-06 (Protocol SIFT Integration)

**Branch:** `claude/keen-bardeen-e0GOC`  
**PR:** [#47](https://github.com/jasonmull/ChainsawMCP/pull/47)

---

## Objective

Make ChainsawMCP a native, first-class SIFT tool targeting the Protocol SIFT "Find Evil!" hackathon (deadline June 15 2025). Four official tracks, all touched by this session. Official requirement: MCP servers must handle complex parameters, paginate massive outputs, and return structured parsed JSON — thin wrappers disqualified.

---

## Work Completed

### 1. FastMCP migration (`server.py`)

Migrated from the raw `mcp.server.Server` API to bundled FastMCP (`from mcp.server.fastmcp import FastMCP`). The old pattern required two separate handler functions per tool (`list_tools` + `call_tool` dispatch). FastMCP uses `@mcp.tool()` decorators that collocate description with implementation and auto-generate schemas from type hints.

Key changes:
- `app = Server(...)` → `mcp = FastMCP("ChainsawMCP")`
- Errors: `return _error(text)` → `raise ValueError(text)`
- Returns: `return _ok(text)` → `return text`
- Import aliases added to avoid name collisions with tool function names
- HTTP transport kept on Starlette/uvicorn using `mcp._mcp_server` for `StreamableHTTPSessionManager`

No new dependency — bundled FastMCP is included in the `mcp` SDK package already in use.

### 2. Structured paginated JSON output (`report.py`, `server.py`)

Added `output_format: str = "text"` to `chainsaw_report` and `get_detections`. Added `page` and `page_size` parameters to `get_detections`. Default remains `"text"` — existing usage unchanged.

New functions in `report.py`:
- `format_summary_json()` — severity counts + top-rules for `chainsaw_report`
- `get_detections_json()` — paginated hits with filters and pagination metadata
- `_hit_to_dict()` — normalises a raw Chainsaw hit to `{rule, severity, timestamp, event_id, computer, data}`

Pagination applies to `get_detections` (individual events, potentially thousands). `chainsaw_report` returns an aggregated summary that is inherently small — no pagination needed.

### 3. Inference constraint provenance logging (`monitor.py`)

On every successful hunt completion, `monitor.py` now writes `chainsaw_provenance.json` to the job directory containing the exact Chainsaw command, raw output file path, SHA-256 of that file, completion timestamp, and Chainsaw version string. `load_hunt_results` reads and surfaces this record in every response so it travels into Claude's context alongside the findings.

This provides a cryptographic audit trail proving findings came from Chainsaw, not from AI inference — the "Courtroom Track" requirement.

New helpers: `_sha256()` (streaming), `_chainsaw_version()` (runs `--version`), `_write_provenance()`.

### 4. Ralph Wiggum structured error responses (`monitor.py`, `jobs.py`, `server.py`)

Hunt failures now produce a structured JSON error payload returned via `ValueError` from `load_hunt_results`. Payload includes `status`, `job_id`, `error`, `exit_code`, `stderr` (first 2KB), `suggested_fix`, and `attempt` counter.

`_classify_error()` maps stderr patterns to actionable fix strings. The `attempt` counter is initialised by scanning the jobs directory for prior failed jobs against the same evidence path — the Ralph Wiggum loop can enforce a retry cap at `attempt >= 3` without external state.

**Critical ordering fix:** Mapping check in `_classify_error` runs before sigma check because the mapping filename (`sigma-event-logs-all.yml`) contains "sigma" and would otherwise hit the wrong branch.

### 5. `setup_environment` self-bootstrapping tool (`setup.py`, `config.py`, `server.py`)

New `setup.py` module and `setup_environment` MCP tool. Installs Chainsaw (from `chainsaw_all_platforms+rules+examples.zip` — the only GitHub release asset that includes `rules/`) to `/opt/chainsaw/` and Sigma rules (shallow git clone) to `/opt/sigma/`. When `/opt` requires `sudo`, the tool returns exact shell commands instead of escalating privileges silently.

After successful install, paths are written to `~/.chainsawmcp/config.json`. All `get_*_path()` functions in `config.py` now check this file as a fallback between env var and PATH default — no manual path arguments needed after first setup.

### 6. MCP registration + SKILL.md (`skills/evtx-analysis/SKILL.md`, `README.md`)

Created `skills/evtx-analysis/SKILL.md` implementing the Protocol SIFT Progressive Disclosure pattern. The skill is loaded on demand when the investigation involves EVTX files, E01 images, or Windows artifact questions — not on every session start.

SKILL.md documents the four-step workflow, the Ralph Wiggum error handling procedure with `attempt >= 3` escalation, a severity interpretation table, and the completion promise token `<promise>CHAINSAW_HUNT_COMPLETE</promise>` used by the orchestration loop to gate follow-on skill loading.

README updated with Protocol SIFT registration command, SKILL.md setup instructions, and updated tool parameter tables for `chainsaw_report`, `get_detections`, and the new `setup_environment` tool.

---

## Bugs Found and Fixed

### 1. `_classify_error` misrouting mapping errors to sigma branch
**Symptom:** `"error: Mapping file not found: sigma-event-logs-all.yml"` was returning `suggested_fix: "Verify --sigma path"` instead of `"Verify --mapping path"`.  
**Root cause:** The filename contains "sigma", so the sigma pattern matched before the mapping pattern.  
**Fix:** Reordered checks — mapping check runs first.

### 2. `_classify_error` missing "no sigma rules found" pattern
**Symptom:** `"error: no sigma rules found at /opt/sigma"` was falling through to the unclassified catch-all.  
**Root cause:** Pattern list checked for `"sigma rules"` but not `"no sigma"`.  
**Fix:** Added `"no sigma"` to the sigma branch pattern list.

### 3. HTTP transport incompatibility with FastMCP `mcp.run()`
**Symptom:** HTTP mode lost CORS middleware and Windows event loop policy after FastMCP migration.  
**Fix:** Keep existing Starlette/uvicorn setup; access underlying MCP server via `mcp._mcp_server` for `StreamableHTTPSessionManager`.

### 4. `needs_sudo` test false-positive in root environment
**Symptom:** `_can_write` test always returned `True` in CI (running as UID 0), even for chmod 0o500 directories.  
**Root cause:** `os.access()` bypasses permission bits for root. Expected behavior — production runs as a normal analyst user on SIFT where this works correctly.

---

## Configuration Changes

No new environment variables. New persistent config file: `~/.chainsawmcp/config.json` (written by `setup_environment`). Keys: `chainsaw_bin`, `rules_path`, `mapping_path`, `sigma_path`. All `get_*_path()` functions in `config.py` respect this file.

---

## State at Session End

- Branch `claude/keen-bardeen-e0GOC` pushed; PR #47 open
- All six Protocol SIFT integration items committed
- FastMCP migration complete and verified
- Provenance logging active for all future hunts
- `setup_environment` tested against writable and non-writable install targets
- SKILL.md and README updated
