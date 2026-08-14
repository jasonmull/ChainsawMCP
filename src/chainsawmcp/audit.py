"""Structured agent-to-tool execution log for ChainsawMCP.

The server has no central dispatch hook — each MCP tool is an independent
``@mcp.tool()`` handler. The :func:`audited` decorator wraps each handler and
emits one structured JSONL record per call to
``<analysis_dir>/agent_execution.jsonl``, giving a timestamped, ordered audit
trail of which tool the agent invoked, with what arguments, when, and what came
back.

This records only what the server actually observes — the tool-call sequence.
It does *not* record token usage: the server makes zero LLM calls, so token
counts live exclusively in the MCP client and are invisible here.

Logging is best-effort and defensive: a failure to write the log can never
break a tool call (matching ``monitor.py:_write_job``), and tool errors are
logged but always re-raised.
"""

import functools
import inspect
import itertools
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import get_analysis_dir

# One session id per server process; assigned once at import.
_SESSION_ID = uuid.uuid4().hex
# Monotonic ordering counter within the process.
_seq = itertools.count(1)

# Truncation limits to keep records compact.
_MAX_ARG_CHARS = 200
_MAX_LIST_ITEMS = 20
_RESULT_PREVIEW_CHARS = 200


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_path() -> Path:
    return get_analysis_dir() / "agent_execution.jsonl"


def _truncate(value):
    """Render an argument value as a JSON-safe, length-bounded representation."""
    if isinstance(value, str):
        return value if len(value) <= _MAX_ARG_CHARS else value[:_MAX_ARG_CHARS] + "…"
    if isinstance(value, (list, tuple)):
        items = [_truncate(v) for v in value[:_MAX_LIST_ITEMS]]
        if len(value) > _MAX_LIST_ITEMS:
            items.append(f"…(+{len(value) - _MAX_LIST_ITEMS} more)")
        return items
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _truncate(str(value))


def _bind_args(fn, args, kwargs) -> dict:
    """Bind call args to parameter names, truncated. Never raises."""
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
        bound.apply_defaults()
        return {k: _truncate(v) for k, v in bound.arguments.items()}
    except Exception:
        try:
            return {k: _truncate(v) for k, v in kwargs.items()}
        except Exception:
            return {}


def _current_job_id() -> str:
    """Resolve session job_id lazily to avoid an import cycle with server.py."""
    try:
        from . import server
        return server.state.job_id or ""
    except Exception:
        return ""


def _append(record: dict) -> None:
    """Append one JSON line to the execution log. Best-effort; never raises."""
    try:
        path = _log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass


def audited(fn):
    """Wrap an async MCP tool handler to emit a structured execution-log record.

    ``functools.wraps`` preserves the wrapped function's signature so the SDK's
    introspection (and the generated tool schema) is unchanged. Tool errors are
    logged with ``status: "error"`` and re-raised — logging never swallows them.
    """

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        record = {
            "seq": next(_seq),
            "session_id": _SESSION_ID,
            "tool": fn.__name__,
            "args": _bind_args(fn, args, kwargs),
            "started_at": _now(),
        }
        started = datetime.now(timezone.utc)
        try:
            result = await fn(*args, **kwargs)
        except Exception as exc:
            finished = datetime.now(timezone.utc)
            record["finished_at"] = finished.isoformat()
            record["duration_ms"] = round((finished - started).total_seconds() * 1000, 1)
            record["status"] = "error"
            record["error"] = f"{type(exc).__name__}: {exc}"
            job_id = _current_job_id()
            if job_id:
                record["job_id"] = job_id
            _append(record)
            raise

        finished = datetime.now(timezone.utc)
        record["finished_at"] = finished.isoformat()
        record["duration_ms"] = round((finished - started).total_seconds() * 1000, 1)
        record["status"] = "ok"
        text = result if isinstance(result, str) else str(result)
        record["result_chars"] = len(text)
        record["result_preview"] = text[:_RESULT_PREVIEW_CHARS]
        job_id = _current_job_id()
        if job_id:
            record["job_id"] = job_id
        _append(record)
        return result

    return wrapper
