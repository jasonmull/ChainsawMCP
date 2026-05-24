"""
OpenWebUI Filter — Chainsaw MCP Analysis Inlet
===============================================

Trigger syntax
--------------
Type the following in any OpenWebUI chat to start an analysis:

    !analyse <path>

Examples:
    !analyse /mnt/evidence/evtx
    !analyse C:\\Cases\\001\\evtx
    !analyse "/mnt/cases/IR-2026-001/evtx files"
    !analyse 'C:\\Cases\\IR-001\\disk.E01'

The filter intercepts the message before the model sees it, orchestrates the
full Chainsaw MCP workflow via mcpo, then replaces the user message with the
injected findings and a structured report prompt.  This means base/completion
models (e.g. FoundationSec) that cannot call tools directly can still produce
a full IR report — all tool orchestration happens here.

Valves (config)
---------------
mcpo_url         : base URL of the mcpo instance wrapping ChainsawMCP
                   default: http://localhost:8081
keyword          : trigger prefix to watch for
                   default: !analyse
hunt_timeout     : seconds to wait for chainsaw_hunt (may be very long)
                   default: 600
max_detections   : max detections fetched per severity bucket
                   default: 50
"""

from __future__ import annotations

import json
import textwrap
from typing import Any

import requests
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Helper utilities
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


def _parse_path(text: str, keyword: str) -> str | None:
    """
    Extract the evidence path from a trigger message.

    Handles:
      - !analyse /some/path
      - !analyse "path with spaces"
      - !analyse 'path with spaces'
      - !analyse C:\\Windows\\path  (backslashes)
      - Leading/trailing whitespace
    """
    stripped = text.strip()
    lower = stripped.lower()
    kw_lower = keyword.lower()

    if not lower.startswith(kw_lower):
        return None

    remainder = stripped[len(keyword):].strip()
    if not remainder:
        return None

    # Strip matching outer quotes
    if (remainder.startswith('"') and remainder.endswith('"')) or \
       (remainder.startswith("'") and remainder.endswith("'")):
        remainder = remainder[1:-1]

    return remainder if remainder else None


def _count_hits(report_text: str) -> int | None:
    """
    Try to extract a total hit count from the chainsaw_report output.
    Returns None if the count cannot be determined.
    """
    import re
    # Look for patterns like "X hits", "X detections", "Total: X"
    for pattern in (
        r"(\d+)\s+(?:total\s+)?(?:hit|detection|finding|alert)s?",
        r"total[:\s]+(\d+)",
        r"(\d+)\s+rules?\s+matched",
    ):
        match = re.search(pattern, report_text, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


# ---------------------------------------------------------------------------
# Filter class
# ---------------------------------------------------------------------------

class Filter:
    """OpenWebUI v0.9 inlet filter — Chainsaw MCP analysis trigger."""

    class Valves(BaseModel):
        mcpo_url: str = "http://localhost:8081"
        keyword: str = "!analyse"
        hunt_timeout: int = 600
        max_detections: int = 50

    def __init__(self):
        self.valves = self.Valves()

    # ------------------------------------------------------------------
    # Inlet
    # ------------------------------------------------------------------

    async def inlet(
        self,
        body: dict,
        __user__: dict | None = None,
    ) -> dict:
        """
        Intercept the chat payload.  If the last user message starts with the
        trigger keyword, run the full Chainsaw workflow and replace the message
        content with the findings + report prompt.
        """
        messages: list[dict] = body.get("messages", [])
        if not messages:
            return body

        # Find the last user message
        last_user_idx: int | None = None
        for i in range(len(messages) - 1, -1, -1):
            if messages[i].get("role") == "user":
                last_user_idx = i
                break

        if last_user_idx is None:
            return body

        user_message: str = messages[last_user_idx].get("content", "")
        evidence_path = _parse_path(user_message, self.valves.keyword)

        if evidence_path is None:
            # Not a trigger — pass through untouched
            return body

        # ------------------------------------------------------------------
        # Workflow
        # ------------------------------------------------------------------
        base = self.valves.mcpo_url.rstrip("/")
        max_det = self.valves.max_detections
        sections: list[str] = []
        fatal = False
        fatal_message = ""

        # 1. prepare_evidence
        ok, result = _call(
            f"{base}/prepare_evidence",
            {"path": evidence_path},
            timeout=120,
        )
        if not ok:
            fatal = True
            fatal_message = (
                f"prepare_evidence failed: {result}\n\n"
                "Possible causes: path does not exist, unsupported format, "
                "or mcpo is unreachable."
            )
        else:
            sections.append(f"## Evidence Preparation\n\n{result}")

        # 2. chainsaw_hunt  (long-running — use hunt_timeout)
        if not fatal:
            ok, result = _call(
                f"{base}/chainsaw_hunt",
                {},
                timeout=self.valves.hunt_timeout,
            )
            if not ok:
                fatal = True
                fatal_message = (
                    f"chainsaw_hunt failed: {result}\n\n"
                    "The hunt did not complete.  Evidence may still be staged."
                )
            else:
                sections.append(f"## Chainsaw Hunt Results\n\n{result}")

        # 3. chainsaw_report
        report_text = ""
        if not fatal:
            ok, result = _call(
                f"{base}/chainsaw_report",
                {},
                timeout=120,
            )
            if ok:
                report_text = result
                sections.append(f"## Chainsaw Report Summary\n\n{result}")
            else:
                sections.append(
                    f"## Chainsaw Report\n\n[Report generation failed: {result}]"
                )

        # 4. get_detections — critical
        critical_text = ""
        if not fatal:
            ok, result = _call(
                f"{base}/get_detections",
                {"severity": "critical", "limit": max_det},
                timeout=120,
            )
            if ok:
                critical_text = result
                sections.append(
                    f"## Critical Detections (up to {max_det})\n\n{result}"
                )
            else:
                sections.append(
                    f"## Critical Detections\n\n[Fetch failed: {result}]"
                )

        # 5. get_detections — high
        if not fatal:
            ok, result = _call(
                f"{base}/get_detections",
                {"severity": "high", "limit": max_det},
                timeout=120,
            )
            if ok:
                sections.append(
                    f"## High Detections (up to {max_det})\n\n{result}"
                )
            else:
                sections.append(
                    f"## High Detections\n\n[Fetch failed: {result}]"
                )

        # 6. get_detections — medium (capped lower to keep context manageable)
        medium_limit = min(25, max_det)
        if not fatal:
            ok, result = _call(
                f"{base}/get_detections",
                {"severity": "medium", "limit": medium_limit},
                timeout=120,
            )
            if ok:
                sections.append(
                    f"## Medium Detections (up to {medium_limit})\n\n{result}"
                )
            else:
                sections.append(
                    f"## Medium Detections\n\n[Fetch failed: {result}]"
                )

        # ------------------------------------------------------------------
        # Build the injected content
        # ------------------------------------------------------------------
        hit_count = _count_hits(report_text) if report_text else None
        hit_summary = (
            f"{hit_count} hit(s) detected"
            if hit_count is not None
            else "hit count not determined"
        )
        status_header = textwrap.dedent(f"""\
            <!-- CHAINSAW ANALYSIS INJECTED BY OPENWEBUI FILTER -->
            <!--
              Evidence path : {evidence_path}
              Status        : {"FATAL ERROR — see details below" if fatal else "analysis complete"}
              Hits          : {hit_summary if not fatal else "N/A"}
            -->
        """)

        if fatal:
            injected_content = textwrap.dedent(f"""\
                {status_header}
                # Chainsaw Analysis — Error Report

                The automated Chainsaw analysis encountered a fatal error and
                could not complete.  The details are below.

                ---

                {fatal_message}

                ---

                Based on the error information above, please explain what went wrong
                and suggest what the analyst should check or do next.
            """)
        else:
            findings_block = "\n\n---\n\n".join(sections)
            injected_content = textwrap.dedent(f"""\
                {status_header}
                # Chainsaw Analysis Findings — {evidence_path}

                The following data was produced by an automated Chainsaw MCP
                analysis of the evidence at the path shown above.  All tool
                calls have already been made; no further tool use is required.

                {findings_block}

                ---

                # Analyst Report Instructions

                Using ALL of the findings above, write a complete Incident Response
                report.  The report must be written in full — do not summarise or
                defer sections.  Structure it as follows:

                ## 1. Executive Summary
                One paragraph suitable for non-technical stakeholders.  State
                what happened, when, and the likely impact.

                ## 2. MITRE ATT&CK Mapping
                For every detection, map it to the most specific ATT&CK
                technique and sub-technique (e.g. T1059.001 — PowerShell).
                Present as a table: Technique ID | Technique Name | Detection |
                Severity.

                ## 3. Timeline of Events
                Reconstruct the attack timeline in chronological order from the
                event log timestamps present in the findings.  Format as a
                markdown table: Timestamp | Event | Rule | Severity.

                ## 4. Indicators of Compromise (IOCs)
                Extract all IOCs: hashes, IPs, domains, file paths, registry
                keys, process names, command lines.  Group by type.

                ## 5. Compromised Accounts and Systems
                List every account and hostname that appears in the detections,
                noting the role (e.g. domain admin, service account, workstation).

                ## 6. Attack Narrative
                Describe the full attack chain in plain English: initial access
                → execution → persistence → privilege escalation → lateral
                movement → collection → exfiltration/impact.  Cite specific
                detections by rule name where possible.

                ## 7. Recommendations
                Prioritised remediation steps — immediate containment first,
                then hardening, then monitoring.

                ## 8. Gaps and Limitations
                Note any log gaps, missing data sources, or caveats that
                affect confidence in the findings.

                Begin the report now:
            """)

        # Replace the last user message content
        messages[last_user_idx]["content"] = injected_content
        body["messages"] = messages
        return body
