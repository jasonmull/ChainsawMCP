# Session Log — 2026-05-31

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
