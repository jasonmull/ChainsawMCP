"""
OpenWebUI Pipe — Chainsaw MCP Interactive Analysis (Qwen -> FoundationSec)
===========================================================================

Unlike chainsaw_filter.py (a Filter, which only rewrites the incoming
message before OpenWebUI's single selected model responds), a Pipe
registers as its own selectable "model" and has full control over
generating each turn's response. This lets it drive two separate models
per turn:

  1. tool_model (e.g. a Qwen model) — a real tool-calling agent, called
     against Ollama's native API with the Chainsaw MCP tools available. It
     decides which tools to call and in what order, and can keep drilling
     in across a conversation (e.g. "tell me more about hit abc123" on a
     later turn calls get_hit again against the same loaded results).
  2. analysis_model (e.g. Foundation-Sec-8B-Reasoning) — has no tool-calling
     support. It never sees the tool schema; it only receives the findings
     tool_model already gathered, plus the analyst's actual question, and
     writes the answer.

Hiding the detached hunt from tool_model
-----------------------------------------
start_hunt on the MCP server returns almost immediately with a job_id while
Chainsaw runs detached in the background; results must be polled for via
load_hunt_results. Tool-calling LLMs cannot reliably wait/retry across
turns (this is the same problem ADR Decision 6 fixed for the old synchronous
design). Because this Pipe's own code — not tool_model — is what executes
each tool call, the start_hunt tool call is handled specially: it starts the
hunt, then polls load_hunt_results internally until the hunt is actually
done, and only then returns the finished results to tool_model as if
start_hunt were one ordinary synchronous call. tool_model never sees a
"still running" state and load_hunt_results is not exposed as a separate
tool at all.

Valves (config)
---------------
mcpo_url           : base URL of the mcpo instance wrapping ChainsawMCP
                      default: http://localhost:8081
ollama_url          : base URL of Ollama's native API (used directly, not
                      through OpenWebUI's model routing, so this Pipe can
                      drive two separate models in one turn)
                      default: http://localhost:11434
tool_model          : the tool-calling model, e.g. "qwen2.5:14b"
analysis_model      : the non-tool-calling analysis model, e.g.
                      "foundation-sec-8b-reasoning"
hunt_timeout        : total seconds to wait for a detached hunt started via
                      the start_hunt tool call to complete
                      default: 600
poll_interval       : seconds to sleep between load_hunt_results polls
                      default: 10
max_tool_iterations : max tool-call rounds tool_model may make in a single
                      turn, to bound runaway loops
                      default: 6

Note on shared code
--------------------
The _call/_extract_result/_extract_job_id/_poll_load_results helpers below
are intentionally duplicated from chainsaw_filter.py rather than imported
from a shared module — OpenWebUI Functions are typically installed as a
single self-contained file via the Admin UI, so cross-file imports are not
assumed to work reliably across installs.
"""

from __future__ import annotations

import asyncio
import json
import textwrap
from typing import Any

import requests
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# mcpo helpers (duplicated from chainsaw_filter.py — see module docstring)
# ---------------------------------------------------------------------------

def _extract_result(response_json: Any) -> str:
    """
    mcpo can return the tool result as:
      - a plain JSON string (the entire body is a string)
      - {"result": "<string>"}
      - any other dict/list (serialise it)
    """
    if isinstance(response_json, str):
        return response_json
    if isinstance(response_json, dict):
        if "result" in response_json:
            value = response_json["result"]
            if isinstance(value, str):
                return value
            return json.dumps(value, indent=2)
        return json.dumps(response_json, indent=2)
    return json.dumps(response_json, indent=2)


def _call(url: str, body: dict, timeout: int = 60) -> tuple[bool, str]:
    """
    POST *body* to *url*.  Returns (success, text_result).
    Never raises — errors are captured and returned as (False, error_message).
    """
    try:
        resp = requests.post(url, json=body, timeout=timeout)
        resp.raise_for_status()
        try:
            data = resp.json()
        except ValueError:
            data = resp.text
        return True, _extract_result(data)
    except requests.exceptions.Timeout:
        return False, f"Request timed out after {timeout}s calling {url}"
    except requests.exceptions.ConnectionError as exc:
        return False, f"Connection error calling {url}: {exc}"
    except requests.exceptions.HTTPError as exc:
        body_text = ""
        try:
            body_text = exc.response.text[:500]
        except Exception:
            pass
        return False, f"HTTP {exc.response.status_code} from {url}: {body_text}"
    except Exception as exc:
        return False, f"Unexpected error calling {url}: {exc}"


def _extract_job_id(start_hunt_text: str) -> str | None:
    """
    Extract the job ID from start_hunt's response text, e.g.
    "Hunt started (job ID: abc123).\n  Evidence : ..."
    Returns None if the pattern cannot be found.
    """
    import re
    match = re.search(r"job ID:\s*([0-9a-fA-F]+)\)", start_hunt_text)
    return match.group(1) if match else None


async def _poll_load_results(
    base: str, job_id: str, timeout: int, interval: int
) -> tuple[bool, str]:
    """
    Poll POST {base}/load_hunt_results with {"job_id": job_id} until it
    succeeds, fails with a non-"still running" error, or timeout elapses.
    Returns (success, text) — same contract as _call().
    """
    import time as _time
    deadline = _time.monotonic() + timeout
    while True:
        ok, result = await asyncio.to_thread(
            _call, f"{base}/load_hunt_results", {"job_id": job_id}, 60
        )
        if ok:
            return True, result
        if "still running" not in result.lower():
            return False, result
        if _time.monotonic() >= deadline:
            return False, (
                f"Timed out after {timeout}s waiting for job {job_id} to "
                f"complete. Last status: {result}"
            )
        await asyncio.sleep(interval)


# ---------------------------------------------------------------------------
# Tool execution — this is what hides the detached hunt from tool_model
# ---------------------------------------------------------------------------

async def _execute_tool(
    base: str, name: str, args: dict, hunt_timeout: int, poll_interval: int
) -> str:
    """
    Execute one tool call requested by tool_model against mcpo. start_hunt is
    special-cased to poll load_hunt_results to completion before returning,
    so tool_model always sees a finished result for a single tool call.
    """
    if name == "start_hunt":
        ok, result = await asyncio.to_thread(_call, f"{base}/start_hunt", args, 120)
        if not ok:
            return f"start_hunt failed: {result}"
        job_id = _extract_job_id(result)
        if job_id is None:
            return (
                "start_hunt succeeded but no job ID could be parsed from "
                f"its response:\n\n{result}"
            )
        ok, result = await _poll_load_results(
            base, job_id, timeout=hunt_timeout, interval=poll_interval
        )
        if not ok:
            return f"Hunt did not complete: {result}"
        return result

    if name in ("chainsaw_report", "get_detections", "get_hit"):
        ok, result = await asyncio.to_thread(_call, f"{base}/{name}", args, 120)
        return result if ok else f"{name} failed: {result}"

    return f"Unknown tool requested: {name}"


# ---------------------------------------------------------------------------
# Tool schemas exposed to tool_model — load_hunt_results is deliberately not
# exposed; it is absorbed into start_hunt's execution above.
# ---------------------------------------------------------------------------

TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "start_hunt",
            "description": (
                "Start a Chainsaw hunt against an EVTX directory or E01 disk "
                "image and wait for it to finish. This call blocks until "
                "results are ready and returns the full hunt summary "
                "directly — do not call any other tool to check status."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to an EVTX directory or .E01 file",
                    },
                    "rules_path": {
                        "type": "string",
                        "description": "Optional override for the Chainsaw rules directory",
                    },
                    "sigma_path": {
                        "type": "string",
                        "description": "Optional override for the Sigma rules directory",
                    },
                    "mapping_path": {
                        "type": "string",
                        "description": "Optional override for the Sigma mapping file",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "chainsaw_report",
            "description": (
                "Get a structured summary of the most recently loaded hunt "
                "results, including severity breakdown."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "output_format": {
                        "type": "string",
                        "enum": ["text", "json"],
                        "description": "Output format, defaults to text",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_detections",
            "description": (
                "Drill down into detections from the most recently loaded "
                "hunt, filterable by rule name and/or severity."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "rule": {"type": "string", "description": "Filter by exact rule name"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Filter by severity",
                    },
                    "limit": {"type": "integer", "description": "Max detections to return, defaults to 25"},
                    "page": {"type": "integer", "description": "Page number, defaults to 1"},
                    "page_size": {"type": "integer", "description": "Results per page, defaults to 25"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_hit",
            "description": (
                "Fetch full detail for one or more specific detection hit "
                "IDs from the most recently loaded hunt."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hit_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of hit IDs to fetch",
                    },
                },
                "required": ["hit_ids"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Ollama chat helper
# ---------------------------------------------------------------------------

async def _ollama_chat(
    ollama_base: str, model: str, messages: list[dict], tools: list[dict] | None = None,
    timeout: int = 300,
) -> tuple[bool, Any]:
    """
    POST {ollama_base}/api/chat. On success returns (True, message_dict)
    where message_dict is Ollama's "message" object (may contain
    tool_calls). On failure returns (False, error_text).

    Uses asyncio.to_thread — these calls run LLM inference and can take tens
    of seconds; a plain blocking requests.post here would stall OpenWebUI's
    whole event loop (all users, all chats) for that duration.
    """
    payload: dict = {"model": model, "messages": messages, "stream": False}
    if tools:
        payload["tools"] = tools
    url = f"{ollama_base}/api/chat"
    try:
        resp = await asyncio.to_thread(requests.post, url, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        return True, data.get("message", {})
    except requests.exceptions.Timeout:
        return False, f"Request timed out after {timeout}s calling {url} (model={model})"
    except requests.exceptions.ConnectionError as exc:
        return False, f"Connection error calling {url}: {exc}"
    except requests.exceptions.HTTPError as exc:
        body_text = ""
        try:
            body_text = exc.response.text[:500]
        except Exception:
            pass
        return False, f"HTTP {exc.response.status_code} from {url}: {body_text}"
    except Exception as exc:
        return False, f"Unexpected error calling {url}: {exc}"


# ---------------------------------------------------------------------------
# Analysis prompt construction
# ---------------------------------------------------------------------------

def _build_analysis_prompt(
    user_question: str,
    transcript_sections: list[str],
    tool_error: str | None,
    capped: bool,
    report_spec: str = "",
) -> str:
    if tool_error:
        return textwrap.dedent(f"""\
            <!-- CHAINSAW ANALYSIS: TOOL EXECUTION ERROR -->
            The autonomous hunting step encountered an error and could not
            gather findings.

            ---

            {tool_error}

            ---

            The analyst's original question was:

            {user_question}

            Based on the error information above, explain what went wrong and
            suggest what the analyst should check or do next.
        """)

    findings_block = (
        "\n\n---\n\n".join(transcript_sections)
        if transcript_sections
        else "(No tool calls were made — no Chainsaw data has been gathered yet.)"
    )
    cap_note = (
        "\n\nNote: the tool-calling agent reached its maximum number of "
        "tool-call rounds for this turn; findings below may be incomplete."
        if capped else ""
    )
    # The report structure comes from the MCP server, not from this file, so the
    # Pipe, the Filter, and the Claude Code skill all specify the same report.
    spec_block = f"\n\n---\n\n{report_spec}" if report_spec else ""
    return textwrap.dedent(f"""\
        <!-- CHAINSAW ANALYSIS: FINDINGS GATHERED BY AUTONOMOUS TOOL-CALLING AGENT -->
        The following Chainsaw findings were gathered by an autonomous
        tool-calling agent in response to the analyst's question below. All
        necessary tool calls have already been made; no further tool use is
        possible or required.{cap_note}

        {findings_block}

        ---

        # Analyst's Question

        {user_question}

        ---

        # Instructions

        Answer the analyst's question directly using the findings above. Cite
        every factual claim as ref=<hit_id> using the IDs shown in the findings,
        and use UTC ISO-8601 timestamps ending in Z.

        If the analyst is asking for a full Incident Response report, follow the
        report specification below exactly. Otherwise, answer only what was asked
        — do not pad a narrow follow-up question into a full report.
        {spec_block}
    """)


# ---------------------------------------------------------------------------
# Pipe class
# ---------------------------------------------------------------------------

class Pipe:
    """OpenWebUI Pipe — interactive Qwen (tools) -> FoundationSec (analysis)."""

    class Valves(BaseModel):
        mcpo_url: str = "http://localhost:8081"
        ollama_url: str = "http://localhost:11434"
        tool_model: str = "qwen2.5:14b"
        analysis_model: str = "foundation-sec-8b-reasoning"
        hunt_timeout: int = 600
        poll_interval: int = 10
        max_tool_iterations: int = 6

    def __init__(self):
        self.valves = self.Valves()

    async def pipe(self, body: dict, __user__: dict | None = None) -> str:
        messages: list[dict] = list(body.get("messages", []))
        if not messages:
            return "No message provided."

        last_user_content = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                last_user_content = m.get("content", "")
                break

        base = self.valves.mcpo_url.rstrip("/")
        ollama = self.valves.ollama_url.rstrip("/")

        working_messages = [dict(m) for m in messages]
        transcript_sections: list[str] = []
        tool_error: str | None = None
        capped = False

        for iteration in range(self.valves.max_tool_iterations):
            ok, message = await _ollama_chat(
                ollama, self.valves.tool_model, working_messages, tools=TOOL_SCHEMAS
            )
            if not ok:
                tool_error = message
                break

            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                break

            working_messages.append({
                "role": "assistant",
                "content": message.get("content", ""),
                "tool_calls": tool_calls,
            })

            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except ValueError:
                        args = {}
                result_text = await _execute_tool(
                    base, name, args,
                    hunt_timeout=self.valves.hunt_timeout,
                    poll_interval=self.valves.poll_interval,
                )
                transcript_sections.append(
                    f"## Tool: {name}({json.dumps(args)})\n\n{result_text}"
                )
                working_messages.append({"role": "tool", "name": name, "content": result_text})

            if iteration == self.valves.max_tool_iterations - 1:
                capped = True

        # Fetch the canonical report specification from the MCP server. It is
        # stateless, so this works whether or not a hunt has run this turn; if the
        # server is unreachable the prompt simply omits the spec rather than falling
        # back to a divergent copy embedded here.
        report_spec = ""
        ok, spec_text = await asyncio.to_thread(
            _call, f"{base}/get_report_spec", {}, 60
        )
        if ok:
            report_spec = spec_text

        prompt = _build_analysis_prompt(
            last_user_content, transcript_sections, tool_error, capped, report_spec
        )

        ok, message = await _ollama_chat(
            ollama, self.valves.analysis_model,
            [{"role": "user", "content": prompt}],
            tools=None,
        )
        if not ok:
            return (
                f"The analysis model ({self.valves.analysis_model}) could "
                f"not be reached: {message}"
            )
        return message.get("content", "") or "(The analysis model returned an empty response.)"
