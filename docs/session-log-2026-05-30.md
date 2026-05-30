# Session Log — 2026-05-30

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
| `docs/ADR-001-detached-hunt-architecture.md` | This ADR |

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
