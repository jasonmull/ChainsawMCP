# ChainsawMCP — Build Log

ADR and session entries in reverse-chronological order (newest first).

---

## ADR-001: Run Chainsaw as a background asyncio task, poll for status

**Date:** 2026-05-18
**Status:** Accepted

### Context
`chainsaw_hunt` is an `async` MCP tool handler. Originally it called `subprocess.run()` directly — a blocking call that froze the asyncio event loop for the entire duration of the hunt. On large evidence sets (e.g. 296 EVTX files), hunts can take several minutes. The MCP transport's own keepalive/timeout fires before Chainsaw finishes, causing a silent hang from the client's perspective.

### Decision
- Wrap the blocking `subprocess.run()` in `asyncio.to_thread()` so the event loop stays alive.
- `chainsaw_hunt` now launches a background `asyncio.Task` and returns immediately.
- A new `hunt_status` tool exposes task state (`idle / running / done / error`), elapsed time, and hit count on completion.
- The client polls `hunt_status` until the hunt settles.

### Alternatives considered
**MCP log notifications (Option B):** Use `asyncio.create_subprocess_exec()` to read Chainsaw's stderr line-by-line and forward each line as an MCP `notifications/message`. Ruled out because: (a) client support for log notifications is inconsistent — Claude Desktop surfaces them, OpenWebUI may not; (b) Chainsaw's progress output format is not stable across versions, making parsing fragile. The polling model works with any MCP client and requires no protocol extensions.

### Consequences
- Callers must now poll `hunt_status` rather than waiting on `chainsaw_hunt` to return results.
- `chainsaw_report` guards against being called before a hunt completes.
- `prepare_evidence` guards against re-staging while a hunt is in flight.
- A `CHAINSAW_TIMEOUT` env var (default 1800s) controls the subprocess timeout; previously hardcoded to 600s.

---

## ADR-002: Suppress Chainsaw progress output — flag approach depends on version

**Date:** 2026-05-18
**Status:** Superseded by runtime finding

### Context
Chainsaw writes a progress bar to stdout when `--json` is active. This pollutes the JSON stream and caused parse failures on larger evidence sets. The intent was to suppress it.

### Decision (initial)
Pass `--no-progress` to suppress stdout noise.

### What actually happened
`--no-progress` does not exist in the installed version of Chainsaw. The correct CLI syntax for this version is `chainsaw hunt --json --preprocess <RULES> [PATH]...` — `--no-progress` is not a valid flag and caused Chainsaw to exit with an error.

### Revised approach
Removed `--no-progress`. The `_parse_output()` function already handles this correctly: it parses line-by-line and silently discards any line that fails `json.loads()`, so progress output mixed into stdout is harmlessly dropped.

### Lesson
Do not add Chainsaw flags without verifying them against the installed binary's `--help` output. Chainsaw's CLI has changed across versions. Before adding any new flag, check: `chainsaw hunt --help`.

---

## Session Entry — 2026-05-18

### What were the most important decisions or findings?

1. **The hang was an asyncio blocking bug, not a timeout config problem.** `subprocess.run()` inside an `async` function blocks the entire event loop — there is no MCP-level timeout you can tune your way out of. The fix is structural: move blocking work to a thread.

2. **Background task + polling is the right UX pattern for long-running tools in MCP.** The alternative (MCP log notifications) is cleaner in theory but unreliable in practice because client support varies. Polling via a status tool works everywhere.

3. **Don't assume Chainsaw CLI flags are stable across versions.** `--no-progress` was added based on reasonable inference but doesn't exist in the installed binary. Any future flag additions need to be verified against `chainsaw hunt --help` on the actual deployment target.

### What did we try that didn't work?

- **`--no-progress` flag:** Added to suppress progress bar output from polluting the JSON stream. Chainsaw rejected it with a non-zero exit code. Removed in a follow-up commit. The existing line-by-line JSON parser already handles mixed output gracefully.

### What to watch out for going into the next session?

- **Chainsaw version mismatch:** The installed Chainsaw version may differ from documentation. Before adding any subprocess arguments, run `chainsaw hunt --help` and confirm the flag exists. The usage line from this session was: `chainsaw.exe hunt --json --preprocess <RULES> [PATH]...`
- **`--preprocess` flag:** Appeared in the usage line but was not explored. It may affect how rules are loaded and could be relevant if rule-loading performance becomes an issue.
- **Poll interval is client-controlled:** The server doesn't enforce how often `hunt_status` is called. A very aggressive poll (every second) is harmless but noisy. If an LLM client is driving this autonomously, it will naturally space out calls.
- **No cancellation yet:** There is no way to cancel a running hunt. If a hunt is started with wrong arguments, the user must wait for it to time out or restart the MCP server. A `cancel_hunt` tool would be a reasonable addition.
- **State is in-process only:** `_SessionState` lives in memory. If the MCP server crashes or restarts mid-hunt, all state is lost. This is acceptable for now but worth noting.
