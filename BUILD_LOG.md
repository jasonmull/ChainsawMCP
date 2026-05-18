# ChainsawMCP — Build Log

ADR and session entries in reverse-chronological order (newest first).

---

## ADR-003: No server-side LLM enrichment — client drives analysis

**Date:** 2026-05-18
**Status:** Accepted

### Context
The original design included a `chainsaw_enrich` tool that batched Chainsaw hits by rule/tactic and sent them to Ollama (`foundationsec:8b`) for narrative enrichment before formatting the report. This was built on the assumption that the MCP client might not have strong enough reasoning to analyse raw Chainsaw JSON.

### Decision
Remove `chainsaw_enrich` entirely. The MCP client — whether Claude Desktop or OpenWebUI with a local model — is already an LLM and can analyse the hunt results directly in conversation. Having the server make its own LLM calls creates a redundant second model invocation and introduces an Ollama dependency that neither target use case actually needs.

The three-tool flow is: `prepare_evidence` → `chainsaw_hunt` → `chainsaw_report`. The client reads the hunt results and reasons over them natively.

### Alternatives considered
**Keep `chainsaw_enrich` as optional:** Would add a configurable backend parameter (`ollama` or `client`). Ruled out because the "client" mode would have been a no-op (return raw data the client already has), and the "ollama" mode duplicates what the client model already does better with full conversational context.

**Anthropic API backend:** Add `ANTHROPIC_API_KEY` support so the server could call Claude directly for enrichment when used from a non-Claude client. Ruled out — if you have an Anthropic API key, you have Claude Desktop. If you're using OpenWebUI, your local model is the reasoning engine.

### Consequences
- No Ollama dependency. No API keys. Server makes zero LLM calls.
- `chainsaw_report` formats raw hits directly — hit counts, severity, sample events per rule.
- The client LLM provides all narrative analysis interactively, which is better than fire-and-forget batch prompts anyway.

---

## ADR-004: Chainsaw flag correctness — `--rule` (singular) and `--mapping` required for Sigma

**Date:** 2026-05-18
**Status:** Accepted

### Context
Two flag bugs were present in the initial implementation of `_build_command()`:

1. The rules flag was `--rules` (plural). Chainsaw's actual flag is `--rule` (singular), per `chainsaw hunt --help`.
2. When using `--sigma`, Chainsaw requires a `--mapping` file that maps Sigma field names to Windows Event Log field names. Without it, Sigma rules load but match nothing silently — no error, no hits.

### Decision
- Correct `--rules` → `--rule`.
- Add `--mapping` as a first-class parameter alongside `--sigma`. Raise `ChainsawError` early if `sigma_path` is provided without a `mapping_path`, rather than letting Chainsaw silently produce zero hits.
- Add `CHAINSAW_MAPPING` env var. Standard value: `mappings/sigma-event-logs-all.yml` (ships with Chainsaw).

### Lesson
Do not assume Chainsaw CLI flags match documentation or intuition. Before adding any new subprocess argument, verify it against `chainsaw hunt --help` on the actual installed binary. The flag set has changed across Chainsaw versions.

### Consequences
- `run_hunt()` now accepts `mapping_path` parameter.
- Missing mapping with Sigma path is a hard error, not a silent failure.
- All three paths (`--rule`, `--sigma`, `--mapping`) are independently configurable via env vars or tool parameters.

---

## Session Entry — 2026-05-18 (Initial Build)

### What were the 2-3 most important decisions or findings?

1. **The server should make zero LLM calls.** The original design had a full enrichment pipeline (batching, confidence tiering, roll-up synthesis via Ollama). After understanding the actual use cases — Claude Desktop and OpenWebUI — it became clear the client LLM handles this natively. Removing `chainsaw_enrich` simplified the server significantly and eliminated the only external dependency beyond Chainsaw itself.

2. **Chainsaw's CLI has sharp edges.** In a single session: `--rules` should be `--rule`, `--sigma` silently produces nothing without `--mapping`, and a reported `--no-progress` flag doesn't exist. The installed binary's `--help` output is the only reliable source of truth — not docs, not inference from similar tools.

3. **`--mapping` is mandatory for Sigma, not optional.** This is the most dangerous silent failure mode: Sigma rules load without error but match nothing if the mapping file is absent. The guard in `run_hunt()` (raise early if sigma without mapping) prevents a confusing "0 hits" result that looks like clean evidence.

### What did we try that didn't work?

- **`chainsaw_enrich` with Ollama backend:** Built out fully — batching, confidence tiering (HIGH/MEDIUM/LOW), templated responses for LOW-severity rules, roll-up LLM call. Removed after clarifying that both target clients (Claude Desktop, OpenWebUI) are themselves LLMs that handle analysis naturally in conversation.
- **`--rules` flag (plural):** Rejected by Chainsaw. Corrected to `--rule`.
- **`--no-progress` flag:** Reported as needed by an external source; does not exist in the installed Chainsaw version. Not added. The existing line-by-line JSON parser discards non-JSON lines (including progress output) gracefully.

### What to watch out for going into the next session?

- **Chainsaw version on the deployment machine matters.** Verify all subprocess flags with `chainsaw hunt --help` before assuming they exist. The main branch BUILD_LOG (ADR-002) documents a `--preprocess` flag appearing in usage output — that was not explored and may affect rule-loading behaviour.
- **`chainsaw_hunt` blocks the asyncio event loop.** The main branch has already addressed this with `asyncio.to_thread()` and a background task + `hunt_status` polling pattern. This branch does not have that fix yet — on large evidence sets the MCP transport will hang. Merging or cherry-picking that work should be a priority.
- **State is in-process only.** `_SessionState` lives in memory. Server restart = lost session. Acceptable for now.
- **No E01 mounting has been tested end-to-end.** The Linux (`ewfmount`) and Windows (Arsenal Image Mounter) paths are implemented but untested against real images. The first real IR engagement will surface any issues.
- **The `config.py` module still has `get_ollama_base_url()` and `get_ollama_model()` left over from the enrichment design.** These are dead code — clean them up before the next feature addition.

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
