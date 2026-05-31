# ChainsawMCP

> **Incident response at scale — drop evidence, get answers.**

ChainsawMCP is a [Model Context Protocol](https://modelcontextprotocol.io/) server that bridges [Chainsaw](https://github.com/WithSecureLabs/chainsaw) — WithSecure's fast Windows Event Log threat hunting tool — with AI assistants. It is built for incident responders who need to analyse large volumes of Windows event logs quickly, without an EDR or SIEM in place.

Because the server makes no LLM calls of its own, it works equally well with **cloud models** (Claude Desktop) and **locally hosted models** (OpenWebUI + Ollama, LM Studio, or any MCP-compatible client) — keeping sensitive evidence off the internet if your engagement requires it.

---

## How It Works

```
  Analyst prompt:
  "Run a hunt on F:\ChainsawEvals"
          │
          ▼
  ┌───────────────────┐
  │   start_hunt      │  ← spawns Chainsaw as detached process
  │   (returns in     │    no MCP session kept alive
  │    < 1 second)    │    --skip-errors on by default
  └───────────────────┘
          │
          │  [Chainsaw runs independently — minutes to hours]
          │
          ▼
  ┌───────────────────┐
  │  Webhook fires    │  ← Discord, Slack, or any HTTP endpoint
  │  "Hunt complete   │    7,098 hits · 74 rules · job f2ef9e2d
  │   — 7098 hits"    │
  └───────────────────┘
          │
  Analyst returns:
  "Analyze the results"
          │
          ▼
  ┌───────────────────┐
  │ load_hunt_results │  ← instant — reads pre-computed results
  └───────────────────┘
          │
          ▼
  ┌───────────────────┐
  │  chainsaw_report  │  ← severity breakdown, top rules
  │  get_detections   │  ← drill into specific rules or severity
  │  [follow-up Q&A]  │  ← unlimited interactive analysis
  └───────────────────┘
```

The MCP server handles evidence preparation and Chainsaw execution. The AI client — Claude Desktop, OpenWebUI, LM Studio, or anything MCP-compatible — provides all the reasoning. The server makes no LLM calls.

---

## Key Design Decisions

### Detached Execution — No More Timeouts

The original approach embedded Chainsaw execution inside an MCP tool call. MCP clients have finite tool budgets, and a 30-minute Chainsaw run against 3+ GB of logs exceeded them. Every attempt to wait inline hit a timeout.

The fix: `start_hunt` spawns Chainsaw (via a Python runner process) using `CREATE_NEW_PROCESS_GROUP` on Windows and `start_new_session` on Linux. The process is fully independent — it survives MCP session close, client disconnect, and long idle periods. Job state is written to disk so results persist across sessions.

### Webhook Notification

A completion monitor runs alongside Chainsaw. When the hunt finishes, it updates the job record on disk and POSTs a notification to your configured webhook. Discord, Slack, and generic HTTP endpoints are all supported out of the box.

### Interactive Analysis, Not One-Shot Reports

Automatic report generation was considered and rejected. A one-shot report cannot answer follow-up questions. The right model: Chainsaw does the slow mechanical work offline; the MCP session is reserved for fast, interactive investigation where the analyst drives the conversation.

---

## Features

- **Detached hunt execution** — Chainsaw runs as an independent process; `start_hunt` returns in under one second regardless of image size
- **Bulk hunt support** — `start_bulk_hunt` accepts a list of E01 images and processes them in a single Chainsaw run under one job ID
- **No E01 timeouts** — extraction happens inside the detached monitor, not in the MCP tool call; even a 5+ minute extraction cannot timeout the client
- **Stable staging paths** — EVTXs are extracted to `<CHAINSAWMCP_JOBS_DIR>/<job_id>/evtx/<source_name>/`; no temp dirs that can disappear
- **Webhook notifications** — Discord, Slack, and generic HTTP receivers supported
- **Persistent job state** — results survive session restarts; load any previous job by ID or automatically pick up the latest
- **E01 disk image support** — forensic images mounted and EVTXs extracted automatically on both Windows and Linux
- **Split E01 handling** — pass the first segment (`.E01`); multi-segment images resolved automatically
- **Cross-platform** — full support for Windows and Linux; binary names, mount tools, and process management all handled
- **Fault-tolerant hunting** — `--skip-errors` is always enabled; a single corrupt log file does not abort the entire hunt
- **Local LLM support** — works with OpenWebUI, LM Studio, Ollama, and any MCP-compatible client; sensitive evidence never has to leave your network
- **No server-side LLM calls** — the server is purely operational; all reasoning is provided by the client

---

## Requirements

### Runtime

| Requirement | Notes |
|---|---|
| Python 3.11+ | |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw/releases) | On `PATH` or set `CHAINSAW_BIN` |

### E01 Mounting — Linux

E01 images are extracted using `pytsk3` (The Sleuth Kit Python bindings) — **no root access, no FUSE mounts required.** pytsk3 is included in the package dependencies.

If pytsk3 is unavailable, the server falls back to the Sleuth Kit CLI tools:

```bash
sudo apt install sleuthkit
```

### E01 Mounting — Windows

[Arsenal Image Mounter CLI](https://arsenalrecon.com/products/arsenal-image-mounter) must be on `PATH` or set via `AIM_CLI`.

---

## Installation

```bash
git clone https://github.com/jasonmull/ChainsawMCP.git
cd ChainsawMCP
pip install -e .
```

---

## Configuration

All settings are environment variables, set in your MCP client config.

| Variable | Default | Description |
|---|---|---|
| `CHAINSAW_BIN` | `chainsaw` / `chainsaw.exe` | Path to Chainsaw binary |
| `CHAINSAW_RULES` | _(none)_ | Path to Chainsaw rules directory |
| `CHAINSAW_SIGMA` | _(none)_ | Path to Sigma detections directory |
| `CHAINSAW_MAPPING` | _(none)_ | Sigma mapping file — required when using Sigma rules |
| `CHAINSAWMCP_JOBS_DIR` | system temp / `chainsawmcp_jobs` | Where job state and results are stored |
| `CHAINSAWMCP_WEBHOOK_URL` | _(none)_ | Webhook URL to POST on hunt completion |
| `AIM_CLI` | `aim_cli.exe` | Windows only: path to Arsenal Image Mounter CLI |

> **Sigma mapping:** Chainsaw requires a mapping file to match Sigma field names to Windows Event Log fields. Chainsaw ships these in its `mappings/` directory — `sigma-event-logs-all.yml` is the standard choice.

---

## MCP Client Setup

ChainsawMCP works with any MCP-compatible client. Use **Claude Desktop** for cloud-based analysis or **OpenWebUI / LM Studio** to keep evidence entirely on your local network.

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ChainsawMCP": {
      "command": "ChainsawMCP",
      "env": {
        "CHAINSAW_BIN": "C:\\Tools\\chainsaw\\chainsaw.exe",
        "CHAINSAW_RULES": "C:\\Tools\\chainsaw\\rules",
        "CHAINSAW_SIGMA": "C:\\Tools\\chainsaw\\sigma\\rules",
        "CHAINSAW_MAPPING": "C:\\Tools\\chainsaw\\mappings\\sigma-event-logs-all.yml",
        "CHAINSAWMCP_JOBS_DIR": "C:\\ChainsawJobs",
        "CHAINSAWMCP_WEBHOOK_URL": "https://discord.com/api/webhooks/..."
      }
    }
  }
}
```

### Claude Code CLI

```bash
claude mcp add ChainsawMCP ChainsawMCP \
  -e CHAINSAW_BIN=/usr/local/bin/chainsaw \
  -e CHAINSAW_RULES=/opt/chainsaw/rules \
  -e CHAINSAW_SIGMA=/opt/chainsaw/sigma/rules \
  -e CHAINSAW_MAPPING=/opt/chainsaw/mappings/sigma-event-logs-all.yml \
  -e CHAINSAWMCP_JOBS_DIR=/opt/chainsawjobs \
  -e CHAINSAWMCP_WEBHOOK_URL=https://hooks.slack.com/...
```

### OpenWebUI (local LLM)

OpenWebUI's native MCP integration does not inject tool schemas into model API calls (tested v0.9.2). Use **mcpo** as an OpenAPI proxy instead:

```bash
pip install mcpo

CHAINSAW_BIN=/usr/local/bin/chainsaw \
CHAINSAW_RULES=/opt/chainsaw/rules \
CHAINSAWMCP_JOBS_DIR=/opt/chainsawjobs \
CHAINSAWMCP_WEBHOOK_URL=https://discord.com/api/webhooks/... \
mcpo --port 8081 -- ChainsawMCP
```

Then add `http://localhost:8081` as an **OpenAPI** server in OpenWebUI under **Admin → External Tools → OpenAPI**. Pair with any locally hosted model with tool-calling support — Qwen2.5, Llama 3.1, or Mistral. Evidence never leaves your network.

For models without tool-calling support (e.g. Foundation-Sec-8B-Reasoning), use the OpenWebUI inlet filter in `extras/chainsaw_filter.py` — it runs the full workflow autonomously and passes the results to the model for analysis.

---

## Tools

Tools are listed in execution order for a standard workflow.

---

### 1. `start_hunt`

Start a Chainsaw hunt against an EVTX directory or E01 image. Returns in under one second — all evidence preparation and Chainsaw execution happen inside a fully detached background process with no connection to the MCP session.

For E01 images, extraction is performed by the background process, so even a 5-minute extraction will not timeout the tool call.

| Argument | Type | Description |
|---|---|---|
| `path` | string, **required** | Absolute path to an EVTX directory or `.E01` file |
| `rules_path` | string, optional | Override `CHAINSAW_RULES` |
| `sigma_path` | string, optional | Override `CHAINSAW_SIGMA` |
| `mapping_path` | string, optional | Override `CHAINSAW_MAPPING` |
| `extra_args` | array, optional | Extra flags passed verbatim to `chainsaw hunt` |

Returns a job ID immediately. EVTXs are staged to `<CHAINSAWMCP_JOBS_DIR>/<job_id>/evtx/<source_name>/`. A webhook POST fires when the hunt completes. `--skip-errors` is always enabled.

---

### 2. `start_bulk_hunt`

Start a single Chainsaw hunt across multiple E01 images or EVTX directories. All sources are staged and analyzed in one Chainsaw run, producing a single combined result set under one job ID.

Use this when processing multiple endpoints from the same engagement — all findings land in one `hunt_results.json` and are loaded with a single `load_hunt_results()` call.

| Argument | Type | Description |
|---|---|---|
| `paths` | array, **required** | List of absolute paths to `.E01` files or EVTX directories |
| `rules_path` | string, optional | Override `CHAINSAW_RULES` for all sources |
| `sigma_path` | string, optional | Override `CHAINSAW_SIGMA` for all sources |
| `mapping_path` | string, optional | Override `CHAINSAW_MAPPING` for all sources |
| `extra_args` | array, optional | Extra flags passed verbatim to `chainsaw hunt` |

Each source is staged to its own subdirectory: `<job_dir>/evtx/<source_stem>/`. Chainsaw is pointed at `<job_dir>/evtx/` and finds all sources recursively.

---

### 3. `load_hunt_results`

Load results from a completed hunt into the session for analysis. If `job_id` is omitted, the most recently completed hunt is loaded automatically. Call this after receiving the webhook notification.

| Argument | Type | Description |
|---|---|---|
| `job_id` | string, optional | Job ID from `start_hunt` or `start_bulk_hunt`. Omit to load the latest. |

---

### 4. `chainsaw_report`

Write the full hunt report to disk and return a structured summary including severity breakdown (critical / high / medium / low / info), hit counts by rule, and top detections.

---

### 5. `get_detections`

Return individual events from the completed hunt, filtered by rule name or severity. Use this to drill into specific detections surfaced by `chainsaw_report`.

| Argument | Type | Description |
|---|---|---|
| `rule` | string, optional | Case-insensitive substring match on rule name |
| `severity` | string, optional | Exact severity level: `critical`, `high`, `medium`, `low`, `info` |
| `limit` | integer, optional | Max events to return (default: 25) |

---

### `prepare_evidence` _(optional, diagnostic use)_

Synchronously mount a forensic E01 image and stage its EVTXs to a temp directory for inspection. **Not needed for normal hunts** — `start_hunt` and `start_bulk_hunt` handle E01 preparation internally without blocking.

> ⚠️ Large E01 images (3–5 GB) take 3–5 minutes to extract and may hit MCP client timeouts. Use `start_hunt` directly for all production workflows.

| Argument | Type | Description |
|---|---|---|
| `path` | string, **required** | Absolute path to an `.E01` file |

---

## Typical Sessions

### Single image

```
Analyst:  "Run a hunt on the DC image"

Claude:   [calls start_hunt("/evidence/base-dc-cdrive.E01")]
          Hunt started (job ID: 47962594). EVTXs staging to:
          /ChainsawJobs/47962594/evtx — Chainsaw will follow.
          You'll receive a webhook notification when it's done.

          [Monitor extracts 317 EVTXs, Chainsaw runs — ~10 minutes total]

Discord:  ✅ ChainsawMCP hunt complete (job 47962594)
          Hits: 4312 across 23 rules · Completed: 2026-05-31T00:45:11Z

Analyst:  "Analyze the results"

Claude:   [calls load_hunt_results()]
          [calls chainsaw_report()]
          42 critical · 75 high · 413 medium · 155 low

          Top detections: Security Audit Logs Cleared, Remote Service Creation,
          Suspicious PowerShell Execution...
```

### Multiple endpoints (bulk)

```
Analyst:  "Hunt all five images — DC, file server, two RD hosts, workstation"

Claude:   [calls start_bulk_hunt([
            "/evidence/base-dc-cdrive.E01",
            "/evidence/base-file-cdrive.E01",
            "/evidence/base-rd-01-cdrive.E01",
            "/evidence/base-rd-02-cdrive.E01",
            "/evidence/base-wkstn-01-c-drive.E01"
          ])]
          Bulk hunt started (job ID: a1b2c3d4).
          5 sources — all staging in background.

          [Monitor extracts ~1300 EVTXs across 5 images, Chainsaw runs once]

Discord:  ✅ ChainsawMCP hunt complete (job a1b2c3d4)
          Hits: 7,098 across 74 rules

Analyst:  "Analyze the results"

Claude:   [calls load_hunt_results()]
          [calls chainsaw_report()]
          78 critical · 75 high · 413 medium · 155 low · 6377 info

          Top detections: RDP Session Disconnected, Security Audit Logs Cleared,
          Suspicious Remote Logon with Explicit Credentials...

Analyst:  "Show me the critical detections"

Claude:   [calls get_detections(severity="critical", limit=50)]
          [analyses 78 critical events across all five hosts]

Analyst:  "The audit log clearing and RDP activity — do these suggest a specific
           attack pattern?"

Claude:   [pivots on timestamps and hostnames across all endpoints]
          Logs were cleared on win10-test at 22:14 UTC, followed immediately
          by RDP logons from the DC to the workstation...
```

---

## Architecture

```
ChainsawMCP/
├── src/
│   └── chainsawmcp/
│       ├── server.py       # MCP server, tool dispatch, session state
│       ├── evidence.py     # E01 mounting (ewfmount / Arsenal) and EVTX staging
│       ├── chainsaw.py     # Chainsaw subprocess wrapper; detached process spawning
│       ├── monitor.py      # Detached completion monitor; webhook notification
│       ├── jobs.py         # Disk-persisted job state management
│       ├── report.py       # Report formatter and severity summary
│       └── config.py       # Environment variable configuration
└── tests/
    └── test_chainsaw.py    # Full test suite; no Chainsaw binary required
```

### Job Lifecycle

```
start_hunt("host.E01")  /  start_bulk_hunt(["host1.E01", "host2.E01"])
    │
    ├─ create_job()          writes job.json { status: "running", pid: ... }
    │
    ├─ spawn monitor         python -m chainsawmcp.monitor <job_id> <config_json>
    │       │
    │       ├─ status → "preparing"
    │       ├─ stage_evtx(source) → <job_dir>/evtx/<source_stem>/   (one per source)
    │       ├─ status → "running"
    │       ├─ chainsaw hunt <job_dir>/evtx/ --json --skip-errors
    │       ├─ updates job.json { status: "complete", hit_count: ..., completed_at: ... }
    │       └─ POSTs webhook
    │
    └─ returns job ID immediately  (< 1 second)

load_hunt_results()
    │
    ├─ reads job.json         finds latest completed job if no job_id given
    ├─ parses hunt_results.json
    └─ populates session state → chainsaw_report / get_detections ready
```

### Staging Layout

```
CHAINSAWMCP_JOBS_DIR/
└── <job_id>/
    ├── job.json
    ├── hunt_results.json
    ├── chainsaw_stderr.log
    └── evtx/
        ├── base-dc-cdrive/       ← EVTXs from base-dc-cdrive.E01
        ├── base-rd-01-cdrive/    ← EVTXs from base-rd-01-cdrive.E01
        └── base-wkstn-01/        ← EVTXs from base-wkstn-01.E01
```

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite mocks all subprocess calls — no Chainsaw binary or evidence files required.

---

## License

MIT
