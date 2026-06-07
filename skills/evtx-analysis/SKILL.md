# SKILL: Windows Event Log Analysis via ChainsawMCP

## When to load this skill

Load this skill when the investigation involves any of the following:
- `.evtx` files or a directory of Windows Event Logs
- A `.E01` forensic disk image that may contain Windows artifacts
- Questions about Windows authentication, process execution, lateral movement, persistence, or privilege escalation
- A completed ChainsawMCP hunt job awaiting analysis

Do not load this skill for memory forensics, network captures, or Linux artifacts — those require separate skills.

---

## First-run setup

Before hunting for the first time on a SIFT Workstation, confirm the environment is ready:

```
call: setup_environment()
```

This builds Chainsaw from source via `cargo install` and clones Sigma rules, installing both to `~/.local/share/` (no sudo required). Saves paths to `~/.chainsawmcp/config.json` — after setup, no path arguments are needed for `start_hunt`.

**Prerequisite:** Rust must be installed (`cargo` in PATH). If it isn't, `setup_environment` will return the install command:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

> ⚠️ `setup_environment` clones and compiles Chainsaw — this takes several minutes. Always confirm with the analyst before calling it.

---

## Standard workflow

### Step 1 — Start the hunt

```
call: start_hunt(path="<evidence path>")
```

- `path` can be an EVTX directory or a `.E01` image
- Returns immediately with a job ID — Chainsaw runs detached
- If rules/sigma/mapping paths are needed and setup has not been run, pass them explicitly:
  ```
  start_hunt(path=..., rules_path="/opt/chainsaw/rules", sigma_path="/opt/sigma/rules/windows", mapping_path="/opt/chainsaw/mappings/sigma-event-logs-all.yml")
  ```
- Tell the analyst the hunt is running and they will be notified by webhook when it finishes
- **Do NOT call `load_hunt_results` until notified or the analyst returns asking for results**

### Step 2 — Load results

```
call: load_hunt_results()
```

- Loads the most recently completed hunt automatically (omit `job_id` unless loading a specific past job)
- Response includes a provenance record (SHA-256, command, Chainsaw version) — preserve this in your context for chain-of-custody reporting
- If the job errored, the response is a JSON payload with `suggested_fix` — act on it before retrying (max 3 attempts)

### Step 3 — Summary

```
call: chainsaw_report()
```

- Returns severity breakdown and top rules by hit count
- For automated orchestration use `chainsaw_report(output_format="json")` to get a machine-readable summary

### Step 4 — Drill into detections

```
call: get_detections(severity="critical")
call: get_detections(rule="lateral movement")
call: get_detections(output_format="json", page=1, page_size=25)
```

- Filter by severity (`critical`, `high`, `medium`, `low`) or rule name (substring match)
- Use `output_format="json"` with pagination when feeding results to downstream tools
- Use `output_format="text"` (default) for conversational analysis with the analyst

---

## Completion promise

When all required detections have been retrieved and the analyst has their findings, emit:

```
<promise>CHAINSAW_HUNT_COMPLETE</promise>
```

The self-correction loop uses this token to confirm the workflow step completed before moving to the next stage (memory analysis, timeline correlation, IOC extraction, etc.).

---

## Error handling (Ralph Wiggum loop)

If `load_hunt_results` returns a JSON error payload:

1. Read `suggested_fix` — it will be one of:
   - `"run setup_environment"` → call `setup_environment()` then retry `start_hunt`
   - `"Verify --sigma path"` → check sigma path exists; pass it explicitly to `start_hunt`
   - `"Verify evidence path"` → confirm the path contains `.evtx` files
2. Check `attempt` — if `attempt >= 3`, stop retrying and escalate to the analyst
3. After applying the fix, call `start_hunt` again with corrected parameters

---

## Key severity levels

| Level    | Meaning                                        | Typical next step                     |
|----------|------------------------------------------------|---------------------------------------|
| critical | High-confidence IOC, direct threat evidence    | Immediate triage, escalate            |
| high     | Strong indicator, warrants investigation       | Drill into rule with `get_detections` |
| medium   | Suspicious activity, may be benign             | Correlate with timeline/memory        |
| low      | Informational, baseline noise expected         | Review only if other IOCs present     |

---

## Follow-on tools (after this skill completes)

- **Memory forensics**: Volatility — load `skills/memory-analysis/SKILL.md`
- **Super timeline**: log2timeline/plaso — load `skills/timeline/SKILL.md`
- **Registry analysis**: RegRipper / EZ Tools — load `skills/registry/SKILL.md`
- **Network captures**: Wireshark/Zeek — load `skills/network/SKILL.md`

Emit `<promise>CHAINSAW_HUNT_COMPLETE</promise>` before loading the next skill.
