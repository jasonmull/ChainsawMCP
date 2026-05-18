# ChainsawMCP

An [MCP](https://modelcontextprotocol.io/) server that wraps [Chainsaw](https://github.com/WithSecureLabs/chainsaw) — the fast Windows Event Log hunting tool — and surfaces its findings to an LLM client for analysis. Built for incident responders working without an EDR or SIEM.

```
Evidence (EVTX dir / E01 image)
        │
        ▼
  prepare_evidence        ← mount, validate, stage
        │
        ▼
  chainsaw_hunt           ← run Chainsaw, return hits
        │
        ▼
  [client LLM analyses]   ← Claude, OpenWebUI, etc.
        │
        ▼
  chainsaw_report         ← structured formatted report
```

The LLM client — whether Claude Desktop, OpenWebUI, or anything else — drives the analysis. The server handles the evidence handling and Chainsaw execution; the client handles the reasoning.

---

## Features

- **Two evidence input types** — point it at a directory of `.evtx` files or a forensic E01 image; it figures out the rest
- **Cross-platform** — Linux (`ewfmount` + `ntfs-3g`) and Windows (Arsenal Image Mounter) E01 mounting
- **Client-agnostic** — works with Claude Desktop, OpenWebUI, or any MCP-compatible client
- **No external LLM dependency** — the server itself makes no LLM calls; your client provides the intelligence
- **Structured report output** — hits grouped by rule with severity, hit counts, and sample events

---

## Requirements

### Runtime

| Requirement | Notes |
|---|---|
| Python 3.11+ | |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw/releases) | Must be on `PATH` or set `CHAINSAW_BIN` |

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

| Variable | Default | Description |
|---|---|---|
| `CHAINSAW_BIN` | `chainsaw` / `chainsaw.exe` | Path to Chainsaw binary |
| `CHAINSAW_RULES` | _(none)_ | Path to Chainsaw rules directory |
| `CHAINSAW_SIGMA` | _(none)_ | Path to Sigma rules directory |
| `AIM_CLI` | `aim_cli.exe` | Windows only: path to Arsenal Image Mounter CLI |

---

## MCP Client Setup

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ChainsawMCP": {
      "command": "ChainsawMCP",
      "env": {
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
  -e CHAINSAW_BIN=/usr/local/bin/chainsaw \
  -e CHAINSAW_RULES=/opt/chainsaw/rules \
  -e CHAINSAW_SIGMA=/opt/chainsaw/sigma/rules
```

### OpenWebUI

Configure ChainsawMCP as an MCP tool server in your OpenWebUI instance and select your preferred local model for analysis.

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

Run `chainsaw hunt` against the staged evidence and return all detections.

```
rules_path   (string, optional)  Override CHAINSAW_RULES env var
sigma_path   (string, optional)  Override CHAINSAW_SIGMA env var
extra_args   (array,  optional)  Extra flags passed verbatim to chainsaw hunt
```

Returns hits grouped by rule for the client LLM to analyse. Parses both JSON-array and newline-delimited JSON output from Chainsaw.

---

### `chainsaw_report`

Format hunt results into a structured analyst report. Call `chainsaw_hunt` first.

Outputs:
- Generated timestamp and evidence path
- Total hits and rules fired
- Detections grouped by rule with severity, hit count, and sample events

---

## Typical Session

```
You: Analyse this evidence — /cases/IR-2024-042/images/disk.E01

Claude: [calls prepare_evidence] → 847 EVTX files staged

Claude: [calls chainsaw_hunt] → 23 hits across 6 rules
        Here's what I found: [analysis of hits]

You: Generate a report

Claude: [calls chainsaw_report] → structured report delivered
```

---

## Architecture Notes

**Why no server-side LLM calls?** The client — Claude, OpenWebUI, or anything else — already has a capable model attached. Having the server make its own LLM calls would mean running two models for no benefit. The server handles what only the server can do (filesystem access, subprocess execution, E01 mounting); the client handles reasoning.

**E01 split images** (`.E01`, `.E02`, ...) are handled automatically — pass the first segment and `ewfmount` / Arsenal Image Mounter resolves the rest.

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

Tests mock all subprocess calls — no Chainsaw binary required to run the suite.

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
│       ├── report.py       # Report formatter
│       └── config.py       # Env-var configuration
└── tests/
    └── test_chainsaw.py
```

---

## License

MIT
