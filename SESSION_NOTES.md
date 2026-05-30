# Session Notes — 2026-05-30

Branch: `claude/adoring-lovelace-L4rWE`
Tests: 47 passed, 0 failed

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

## Current Architecture (`_build_command`)

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

subprocess.run is called with:
- `stdout=fh` (file handle, avoids pipe buffer exhaustion)
- `stderr=subprocess.PIPE`
- `stdin=subprocess.DEVNULL` (prevents MCP stdio contention)
- `text=True`
- `timeout=get_hunt_timeout()` (default 1800s)

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

All changes committed and pushed to `claude/adoring-lovelace-L4rWE`.
