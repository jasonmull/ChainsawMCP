# Chainsaw MCP

An [MCP](https://modelcontextprotocol.io/) server that wraps [Chainsaw](https://github.com/WithSecureLabs/chainsaw) — the fast Windows Event Log hunting tool — and enriches its findings with a local LLM. Built for incident responders working without an EDR or SIEM, where raw Chainsaw output needs rapid analyst-grade interpretation.

```
Evidence (EVTX dir / E01 image)
        │
        ▼
  prepare_evidence        ← mount, validate, stage
        │
        ▼
  chainsaw_hunt           ← run Chainsaw, parse hits
        │
        ▼
  chainsaw_enrich         ← batch → Ollama LLM → roll-up
        │
        ▼
  chainsaw_report         ← structured analyst report
```

---

## Features

- **Two evidence input types** — point it at a directory of `.evtx` files or a forensic E01 image; it figures out the rest
- **Cross-platform** — Linux (`ewfmount` + `ntfs-3g`) and Windows (Arsenal Image Mounter) E01 mounting
- **Standalone hunt** — `chainsaw_hunt` works without Ollama; enrichment is a separate optional step
- **Batched LLM enrichment** — hits grouped by rule/tactic, sent in configurable batches (default 20) to avoid context overload
- **Confidence tiering** — HIGH / MEDIUM / LOW based on corroborating hit count
- **LOW-severity fast-path** — templated responses for noisy low-confidence rules, no LLM tokens wasted
- **Roll-up synthesis** — a final LLM call stitches batch summaries into a coherent incident narrative
- **Ollama-compatible** — uses the OpenAI-compatible `/v1/chat/completions` endpoint; swap models by changing an env var

---

## Requirements

### Runtime

| Requirement | Notes |
|---|---|
| Python 3.11+ | |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw/releases) | Must be on `PATH` or set `CHAINSAW_BIN` |
| [Ollama](https://ollama.com/) | Required for enrichment only (`chainsaw_hunt` works without it) |
| `foundationsec:8b` model | `ollama pull foundationsec:8b` — or set `OLLAMA_MODEL` to any chat model |

### For E01 mounting (Linux)

```bash
sudo apt install ewf-tools ntfs-3g
```

### For E01 mounting (Windows)

[Arsenal Image Mounter CLI](https://arsenalrecon.com/products/arsenal-image-mounter) must be on `PATH` or pointed to via `AIM_CLI`.

---

## Installation

```bash
git clone https://github.com/jasonmull/ChainsawMCP.git
cd ChainsawMCP
pip install -e .
```

---

## Configuration

All configuration is via environment variables — nothing is hardcoded.

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `foundationsec:8b` | Model for enrichment |
| `CHAINSAW_BIN` | `chainsaw` / `chainsaw.exe` | Path to Chainsaw binary |
| `CHAINSAW_RULES` | _(none)_ | Path to Chainsaw rules directory |
| `CHAINSAW_SIGMA` | _(none)_ | Path to Sigma rules directory |
| `ENRICHMENT_BATCH_SIZE` | `20` | Hits per LLM enrichment batch |
| `AIM_CLI` | `aim_cli.exe` | Windows only: path to Arsenal Image Mounter CLI |

---

## MCP Server Setup

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ChainsawMCP": {
      "command": "ChainsawMCP",
      "env": {
        "OLLAMA_BASE_URL": "http://your-ollama-host:11434",
        "CHAINSAW_BIN": "/usr/local/bin/chainsaw",
        "CHAINSAW_RULES": "/opt/chainsaw/rules",
        "CHAINSAW_SIGMA": "/opt/chainsaw/sigma/rules"
      }
    }
  }
}
```

### Claude Code CLI

```bash
claude mcp add ChainsawMCP ChainsawMCP \
  -e OLLAMA_BASE_URL=http://your-ollama-host:11434 \
  -e CHAINSAW_BIN=/usr/local/bin/chainsaw \
  -e CHAINSAW_RULES=/opt/chainsaw/rules \
  -e CHAINSAW_SIGMA=/opt/chainsaw/sigma/rules
```

---

## Tools

### `prepare_evidence`

Mount an E01 image or validate an EVTX directory and stage files for Chainsaw. **Call this first.**

```
path  (string, required)  Absolute path to an EVTX directory or .E01 file
```

Detects evidence type automatically. For E01 images, locates all `.evtx` files across the mounted filesystem and copies them to a temporary staging directory. Cleans up mount points when a new session starts or the server exits.

---

### `chainsaw_hunt`

Run `chainsaw hunt` against the staged evidence and return a summary of detections.

```
rules_path   (string, optional)  Override CHAINSAW_RULES env var
sigma_path   (string, optional)  Override CHAINSAW_SIGMA env var
extra_args   (array,  optional)  Extra flags passed verbatim to chainsaw hunt
```

Does not require Ollama. Parses both JSON-array and newline-delimited JSON output from Chainsaw. Non-JSON lines (progress messages) are silently skipped.

---

### `chainsaw_enrich`

Send hunt results to the LLM for analysis. Groups hits by rule/tactic, enriches each batch, then synthesises a roll-up narrative. Requires Ollama.

```
batch_size  (integer, optional)  Hits per LLM call — default from ENRICHMENT_BATCH_SIZE (20)
```

**Confidence tiers:**

| Tier | Condition |
|---|---|
| HIGH | 5+ corroborating hits for a rule |
| MEDIUM | 2–4 hits |
| LOW | 1 hit, or rule severity is low/informational |

LOW-severity rules receive a pre-written templated response — no LLM call is made for them.

The LLM is instructed to flag uncertainty explicitly and never invent context not present in the event data.

---

### `chainsaw_report`

Format enriched results into a structured analyst report. Requires `chainsaw_enrich` to have run first.

Outputs:
- Generated timestamp and evidence path
- Executive summary (the roll-up narrative)
- Findings grouped by confidence tier with hit counts
- Per-rule analysis with sample events

---

## Typical Session

```
You: Analyse this evidence — /cases/IR-2024-042/images/disk.E01

Claude: [calls prepare_evidence] → 847 EVTX files staged

Claude: [calls chainsaw_hunt] → 23 hits across 6 rules

Claude: [calls chainsaw_enrich] → 3 HIGH, 2 MEDIUM, 1 LOW

Claude: [calls chainsaw_report] → structured report delivered
```

---

## Architecture Notes

**Why batch enrichment?** Smaller focused batches produce better LLM analysis than dumping all hits at once. The per-batch prompts include rule name, event IDs, timestamps, and process/user context. The roll-up call synthesises batch outputs into a coherent narrative without re-processing raw events.

**Why is `chainsaw_hunt` independent?** Ollama may not be available in all IR environments. The hunt step should always work — enrichment is an enhancement layer.

**Why Ollama?** Local inference keeps evidence data off external networks, which matters in real IR engagements. The `foundationsec:8b` model is tuned for security analysis and fits comfortably on a 16GB VRAM GPU.

**E01 split images** (`.E01`, `.E02`, ...) are handled automatically — pass the first segment and `ewfmount` / Arsenal Image Mounter resolves the rest.

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

Tests mock all subprocess and LLM calls — no Chainsaw binary or Ollama instance required to run the suite.

---

## Project Structure

```
ChainsawMCP/
├── pyproject.toml
├── src/
│   └── chainsawmcp/
│       ├── server.py       # MCP server and tool dispatch
│       ├── evidence.py     # E01 mounting and EVTX staging
│       ├── chainsaw.py     # Chainsaw subprocess wrapper
│       ├── enrichment.py   # LLM batching and confidence tiering
│       ├── report.py       # Report formatter
│       └── config.py       # Env-var configuration
└── tests/
    └── test_chainsaw.py
```

---

## License

MIT
