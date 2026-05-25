# ADR-0001: OpenWebUI / Ollama Integration Strategy

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

## Decision 1: Use mcpo (OpenAPI proxy) rather than OpenWebUI's native MCP

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

## Decision 2: Make `chainsaw_hunt` synchronous for tool-calling clients

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

## Decision 3: Streamable HTTP transport on Windows uses `WindowsSelectorEventLoopPolicy`

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

## Decision 4: OpenWebUI inlet Filter for base and reasoning models

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

## Alternatives Considered

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
