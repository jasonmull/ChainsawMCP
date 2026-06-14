# ChainsawMCP

> **Incident response at scale — drop evidence, get answers.**

ChainsawMCP is a [Model Context Protocol](https://modelcontextprotocol.io/) server that bridges [Chainsaw](https://github.com/WithSecureLabs/chainsaw) — WithSecure's fast Windows Event Log threat hunting tool — with AI assistants. It is built for incident responders who need to analyse large volumes of Windows event logs quickly, without an EDR or SIEM in place.

The server makes no LLM calls of its own. It runs Chainsaw, stages evidence, and returns results over MCP, with all reasoning supplied by the connected client. That separation means evidence locality is a property of which client you choose, not of the server: paired with a locally hosted model (OpenWebUI + Ollama, LM Studio, or any local MCP client), evidence stays on your network end to end; paired with a cloud client like Claude Desktop, the client transmits the detection records it analyzes to that provider, exactly as any MCP tool's output would be. Pick the client that matches your engagement's data-handling requirements.

---

## How It Works

```
  Analyst prompt:
  "Run a hunt on /evidence/dc-cdrive.E01"
          │
          ▼
  ┌───────────────────┐
  │   start_hunt      │  ← returns in < 1 second
  │   (job ID issued) │    spawns monitor as independent process
  └───────────────────┘
          │
          ▼
  ┌───────────────────┐
  │  Monitor process  │  ← fully detached; survives session close
  │  stages EVTXs     │    writes status to job.json throughout
  │  runs Chainsaw    │    optional: POSTs webhook on completion
  └───────────────────┘
          │
          │  [Chainsaw runs independently — minutes to hours]
          │
          ▼
  ┌───────────────────┐
  │  job.json updated │  ← status: "complete", hit_count, provenance
  │  (webhook fires)  │    Discord / Slack / any HTTP endpoint
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

The MCP server handles evidence preparation and Chainsaw execution. The connected AI client — Claude Desktop, OpenWebUI, or anything MCP-compatible — provides all the reasoning, which means it is the client, not the server, that places evidence into a model's context. The server itself makes no LLM calls and opens no connection to any model.

---

## Key Design Decisions

### Background Monitor — No More Timeouts

The original approach ran Chainsaw inline inside an MCP tool call. MCP clients have finite tool budgets, and a 30-minute Chainsaw run against 3+ GB of logs exceeded them reliably.

The fix: `start_hunt` spawns `chainsawmcp.monitor` as a fully independent Python process (`start_new_session` on Linux). The monitor handles all evidence preparation and Chainsaw execution, writing status updates to `job.json` throughout. The process survives MCP session close, client disconnect, and long idle periods. Results persist on disk across sessions.

### Webhook Notifications (Optional)

When the monitor finishes, it optionally POSTs a notification to your configured webhook. Discord, Slack, and generic HTTP endpoints are all supported. If no webhook is configured, you can simply call `load_hunt_results()` at any point — it reads `job.json` and returns immediately if the hunt is still running.

### Interactive Analysis, Not One-Shot Reports

Automatic report generation was considered and rejected. A one-shot report cannot answer follow-up questions. The right model: Chainsaw does the slow mechanical work offline; the MCP session is reserved for fast, interactive investigation where the analyst drives the conversation.

---

## Features

- **Background monitor execution** — `start_hunt` returns in under one second; a detached monitor process handles all staging and Chainsaw execution
- **Bulk hunt support** — `start_bulk_hunt` accepts multiple E01 images or EVTX directories and processes them in a single Chainsaw run under one job ID
- **Stable staging paths** — EVTXs are extracted to `<case_dir>/analysis/<job_id>/evtx/<source_name>/`; no temp dirs that can disappear
- **Persistent job state** — results survive session restarts; load any previous job by ID or automatically pick up the latest
- **E01 disk image support** — forensic images mounted and EVTXs extracted automatically via `pytsk3` (no FUSE/root required); falls back to Sleuth Kit CLI if pytsk3 is unavailable
- **Split E01 handling** — pass the first segment (`.E01`); multi-segment images resolved automatically
- **Fault-tolerant hunting** — `--skip-errors` is always enabled; a single corrupt log file does not abort the hunt
- **Webhook notifications** — optional; Discord, Slack, and generic HTTP receivers supported; not required when polling via `load_hunt_results()`
- **Chain-of-custody provenance** — every hunt writes `chainsaw_provenance.json` with the exact command, Chainsaw version, and SHA-256 of results
- **Per-hit citations** — every detection carries a unique `hit_id`; `get_hit` resolves it back to the hash-verified record, so findings are traceable rather than trusted (see [`docs/ACCURACY.md`](docs/ACCURACY.md))
- **No server-side LLM calls** — the server is purely operational (mount, extract, hunt, report); all reasoning is provided by the connected client. The server never sends evidence to a model itself.
- **Client-determined evidence locality** — because reasoning lives in the client, where your evidence goes is your choice: a local client (OpenWebUI + Ollama, LM Studio) keeps everything on-network; a cloud client sends the records it reasons over to that provider. Local-client integration is functional but still maturing (see Local LLM Integration below).

---

## Requirements

### Runtime

| Requirement | Notes |
|---|---|
| Python 3.11+ | |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw/releases) | On `PATH` or set `CHAINSAW_BIN`; or run `setup_environment` to install automatically |

### E01 Mounting

E01 images are extracted using `pytsk3` (The Sleuth Kit Python bindings) — **no root access, no FUSE mounts required.** `pytsk3` is included in the package dependencies.

If `pytsk3` is unavailable, the server falls back to the Sleuth Kit CLI tools:

```bash
sudo apt install sleuthkit
```

---

## Installation

```bash
git clone https://github.com/jasonmull/ChainsawMCP.git
cd ChainsawMCP
pip install -e .
```

---

## Configuration

All settings are environment variables, set in your MCP client config or shell environment.

| Variable | Default | Description |
|---|---|---|
| `CHAINSAW_BIN` | `chainsaw` | Path to Chainsaw binary |
| `CHAINSAW_RULES` | _(none)_ | Path to Chainsaw rules directory |
| `CHAINSAW_SIGMA` | _(none)_ | Path to Sigma detections directory |
| `CHAINSAW_MAPPING` | _(none)_ | Sigma mapping file — required when using Sigma rules |
| `CHAINSAWMCP_CASE_DIR` | current working directory | Case root — all generated artifacts land under `analysis/`, `exports/`, and `reports/` here |
| `CHAINSAWMCP_JOBS_DIR` | `<case_dir>/analysis` | Override job state and results location (advanced) |
| `CHAINSAW_OUTPUT_DIR` | `<case_dir>/reports` | Override hunt report output location (advanced) |
| `CHAINSAWMCP_WEBHOOK_URL` | _(none)_ | Optional: webhook URL to POST on hunt completion |

> **Auto-discovery:** If `CHAINSAW_BIN`, `CHAINSAW_RULES`, `CHAINSAW_SIGMA`, and `CHAINSAW_MAPPING` are not set, `start_hunt` checks `~/.chainsawmcp/config.json` (written by `setup_environment`) and falls back gracefully — you only need to set these explicitly if you have a non-standard install.

> **Sigma mapping:** Chainsaw requires a mapping file to match Sigma field names to Windows Event Log fields. Chainsaw ships these in its `mappings/` directory — `sigma-event-logs-all.yml` is the standard choice.

---

## Setup

### Default Setup (SIFT Workstation or any Linux system)

Navigate into your case directory first — this anchors all generated artifacts automatically:

```bash
cd /cases/ACME-2026-001
claude mcp add ChainsawMCP -- python -m chainsawmcp.server
```

Verify the server is connected:

```
/mcp
```

Because `CHAINSAWMCP_CASE_DIR` defaults to the current working directory, launching from within `/cases/[CASE_ID]/` means all artifacts land in the correct Protocol SIFT subdirectories with no additional configuration:

```
/cases/ACME-2026-001/
├── analysis/           ← job state, raw Chainsaw output, EVTX staging, forensic_audit.log
├── exports/            ← structured exports (future)
└── reports/            ← hunt_report.txt
```

On first use, ask Claude to run `setup_environment` to install Chainsaw and Sigma rules into `/opt/chainsaw/` and `/opt/sigma/` — no explicit path configuration needed afterward. Paths are saved to `~/.chainsawmcp/config.json` and picked up automatically.

**Progressive Disclosure**: copy `skills/evtx-analysis/SKILL.md` from this repo into your case's skill directory. Claude loads it automatically when EVTX artifacts are encountered, preserving token headroom for other SIFT tools until it's needed:

```bash
mkdir -p /cases/ACME-2026-001/skills/evtx-analysis
cp /path/to/ChainsawMCP/skills/evtx-analysis/SKILL.md /cases/ACME-2026-001/skills/evtx-analysis/
```

Reference it from your case `CLAUDE.md`:

```markdown
## Available skills
- skills/evtx-analysis/SKILL.md  — Windows Event Log hunting (load when .evtx or E01 artifacts present)
```

**autoApprove**: Do not add `setup_environment` to `autoApprove`. It downloads and extracts Chainsaw (takes a minute or two) and must always have explicit analyst approval.

### Advanced Setup (explicit path configuration)

If Chainsaw is already installed at a custom path, or you need to override any default:

```bash
cd /cases/ACME-2026-001
claude mcp add ChainsawMCP -- python -m chainsawmcp.server \
  -e CHAINSAW_BIN=/custom/path/chainsaw \
  -e CHAINSAW_RULES=/custom/rules \
  -e CHAINSAW_SIGMA=/custom/sigma/rules \
  -e CHAINSAW_MAPPING=/custom/mappings/sigma-event-logs-all.yml
```

Add `CHAINSAWMCP_WEBHOOK_URL` if you want completion notifications:

```bash
  -e CHAINSAWMCP_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

### OpenWebUI / Local LLM Integration _(in development)_

ChainsawMCP supports a `--transport streamable-http` mode for OpenWebUI integration. Because the server makes no model calls, pairing it with a locally hosted model keeps all evidence — and all analysis of that evidence — on your local network; nothing is transmitted off-host.

```bash
CHAINSAWMCP_CASE_DIR=/cases/current-engagement \
chainsawmcp --transport streamable-http
```

Then add `http://localhost:8000/mcp` as an MCP server in OpenWebUI under **Admin → External Tools → Add Server**.

> **Note:** OpenWebUI MCP integration and local LLM tool-calling support are actively evolving. Results may vary depending on model and OpenWebUI version.

---

## MCP Tools

Tools are listed in execution order for a standard workflow.

---

### 1. `start_hunt`

Start a Chainsaw hunt against an EVTX directory or E01 image. Returns in under one second — all evidence preparation and Chainsaw execution happen inside a fully independent background monitor process with no connection to the MCP session.

| Argument | Type | Description |
|---|---|---|
| `path` | string, **required** | Absolute path to an EVTX directory or `.E01` file |
| `rules_path` | string, optional | Override `CHAINSAW_RULES` |
| `sigma_path` | string, optional | Override `CHAINSAW_SIGMA` |
| `mapping_path` | string, optional | Override `CHAINSAW_MAPPING` |
| `extra_args` | array, optional | Extra flags passed verbatim to `chainsaw hunt` |

Returns a job ID immediately. EVTXs are staged to `<case_dir>/analysis/<job_id>/evtx/<source_name>/`. If `CHAINSAWMCP_WEBHOOK_URL` is configured, a webhook POST fires when the hunt completes. `--skip-errors` is always enabled.

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

Load results from a completed hunt into the session for analysis. If `job_id` is omitted, the most recently completed hunt is loaded automatically.

You can call this at any time — it reads `job.json` and returns immediately if the hunt is still running. No webhook required.

| Argument | Type | Description |
|---|---|---|
| `job_id` | string, optional | Job ID from `start_hunt` or `start_bulk_hunt`. Omit to load the latest. |

---

### 4. `chainsaw_report`

Write the full hunt report to disk and return a structured summary including severity breakdown (critical / high / medium / low / info), hit counts by rule, and top detections.

| Argument | Type | Description |
|---|---|---|
| `output_format` | string, optional | `text` (default, human-readable) or `json` (machine-readable, for orchestration) |

---

### 5. `get_detections`

Return individual events from the completed hunt, filtered by rule name or severity. Use this to drill into specific detections surfaced by `chainsaw_report`. Each detection carries a unique `hit_id` (shown as `ref=<id>`) — the citation handle for `get_hit`.

| Argument | Type | Description |
|---|---|---|
| `rule` | string, optional | Case-insensitive substring match on rule name |
| `severity` | string, optional | Exact severity level: `critical`, `high`, `medium`, `low`, `info` |
| `limit` | integer, optional | Max events to return in text mode (default: 25) |
| `output_format` | string, optional | `text` (default) or `json` (paginated, for orchestration) |
| `page` | integer, optional | Page number when `output_format=json` (default: 1) |
| `page_size` | integer, optional | Events per page when `output_format=json` (default: 25) |

---

### 6. `get_hit`

Resolve one or more `hit_id` citations back to their full raw Chainsaw records — the citation verifier. Each record in `hunt_results.json` is stamped with a unique, deterministic `hit_id` (`<job_id>-<index>`) plus intrinsic dereference fields (`event_record_id`, `source` EVTX, `channel`) before the provenance hash is taken, so a cited finding can be confirmed against the hash-verified hunt output. A `hit_id` that does not resolve is, by definition, an unsupported claim. See [`docs/ACCURACY.md`](docs/ACCURACY.md) for the full chain-of-custody rationale.

| Argument | Type | Description |
|---|---|---|
| `hit_ids` | list of strings, **required** | The `hit_id` values to resolve (max 20 per call). Returns the matching records, any unresolved ids, and the provenance `output_sha256`. |

---

### 7. `setup_environment`

Install Chainsaw and Sigma rules. Installs to `/opt/chainsaw/` and `/opt/sigma/` by default — no sudo required if those paths are writable. If they are not, the tool returns the exact shell commands to run manually rather than escalating privileges silently. Resolved paths are saved to `~/.chainsawmcp/config.json` so `start_hunt` picks them up automatically with no explicit path arguments.

> ⚠️ Do not add to `autoApprove` — downloads and extracts Chainsaw, takes a minute or two.

| Argument | Type | Description |
|---|---|---|
| `chainsaw_dir` | string, optional | Override install path (default: `/opt/chainsaw`) |
| `sigma_dir` | string, optional | Override Sigma rules path (default: `/opt/sigma`) |

---

### `prepare_evidence` _(optional, diagnostic use)_

Synchronously mount a forensic E01 image and stage its EVTXs for inspection. **Not needed for normal hunts** — `start_hunt` and `start_bulk_hunt` handle E01 preparation inside the background monitor without blocking.

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
          /cases/ACME-2026-001/analysis/47962594/evtx — Chainsaw will follow.

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
│       ├── evidence.py     # E01 extraction (pytsk3 / Sleuth Kit) and EVTX staging
│       ├── chainsaw.py     # Chainsaw subprocess wrapper; monitor process spawning
│       ├── monitor.py      # Background hunt runner; job state updates; webhook dispatch
│       ├── jobs.py         # Disk-persisted job state management
│       ├── report.py       # Report formatter and severity summary
│       ├── setup.py        # setup_environment: Chainsaw + Sigma install
│       └── config.py       # Environment variable + config.json resolution
└── tests/
    └── test_chainsaw.py    # Full test suite; no Chainsaw binary required
```

### Job Lifecycle

```
start_hunt("host.E01")  /  start_bulk_hunt(["host1.E01", "host2.E01"])
    │
    ├─ create_job()          writes job.json { status: "running" }
    │
    ├─ spawn monitor         python -m chainsawmcp.monitor <job_id> <config_json>
    │       │                (independent process — survives session close)
    │       ├─ status → "preparing"
    │       ├─ stage_evtx(source) → <case_dir>/analysis/<job_id>/evtx/<source_stem>/
    │       ├─ status → "running"
    │       ├─ chainsaw hunt <job_dir>/evtx/ --json --skip-errors
    │       ├─ writes hunt_results.json + chainsaw_provenance.json
    │       ├─ status → "complete" (or "error")
    │       └─ POSTs webhook (if CHAINSAWMCP_WEBHOOK_URL is set)
    │
    └─ returns job ID immediately  (< 1 second)

load_hunt_results()            ← call any time; works with or without webhook
    │
    ├─ reads job.json           finds latest completed job if no job_id given
    ├─ parses hunt_results.json
    ├─ surfaces chainsaw_provenance.json into session context
    └─ populates session state → chainsaw_report / get_detections ready
```

### Staging Layout

Artifacts are written relative to `CHAINSAWMCP_CASE_DIR` (defaults to cwd — typically `/cases/[CASE_ID]/` on a SIFT Workstation):

```
<case_dir>/
├── analysis/
│   ├── forensic_audit.log        ← appended at end of each Claude session
│   └── <job_id>/
│       ├── job.json
│       ├── hunt_results.json
│       ├── chainsaw_provenance.json   ← chain-of-custody: command, SHA-256, version
│       ├── chainsaw_stderr.log
│       └── evtx/
│           ├── base-dc-cdrive/        ← EVTXs from base-dc-cdrive.E01
│           ├── base-rd-01-cdrive/     ← EVTXs from base-rd-01-cdrive.E01
│           └── base-wkstn-01/         ← EVTXs from base-wkstn-01.E01
├── exports/                      ← structured exports (future)
└── reports/
    └── hunt_report.txt
```

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite mocks all subprocess calls — no Chainsaw binary or evidence files required.

---

## Documentation

- [`docs/ACCURACY.md`](docs/ACCURACY.md) — accuracy & evidence-integrity self-assessment: false positives, missed-artifact classes, hallucination handling, and how the citation/provenance chain makes findings verifiable
- [`docs/ADR-combined.md`](docs/ADR-combined.md) — architecture decision records
- [`docs/session-log-combined.md`](docs/session-log-combined.md) — development session log

---

## License

MIT
