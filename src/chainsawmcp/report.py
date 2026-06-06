"""Format Chainsaw hunt results into analyst reports."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_full_report(hits: list[dict[str, Any]], evtx_path: str, output_dir: Path) -> Path:
    """Write the full report to a file and return the path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    report_file = output_dir / "hunt_report.txt"
    report_file.write_text(format_full_report(hits, evtx_path), encoding="utf-8")
    return report_file


def format_summary(hits: list[dict[str, Any]], evtx_path: str, report_file: Path | None = None) -> str:
    """Return a short summary suitable for MCP response (not the full event list)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    grouped = _group_by_rule(hits)
    by_severity = _count_by_severity(hits)

    lines = [
        "=" * 72,
        "  ChainsawMCP — HUNT SUMMARY",
        "=" * 72,
        f"Generated : {now}",
        f"Evidence  : {evtx_path}",
        f"Total hits: {len(hits)}",
        f"Rules hit : {len(grouped)}",
        "",
        "Severity breakdown:",
    ]
    for sev, count in sorted(by_severity.items(), key=lambda x: -x[1]):
        lines.append(f"  {count:>5}x  {sev}")

    lines += ["", "Top detections (by hit count):"]
    for rule, rule_hits in sorted(grouped.items(), key=lambda x: -len(x[1]))[:15]:
        severity = _extract_severity(rule_hits[0])
        lines.append(f"  {len(rule_hits):>5}x  [{severity}]  {rule}")
    if len(grouped) > 15:
        lines.append(f"  ... and {len(grouped) - 15} more rule(s)")

    lines.append("")
    if report_file:
        lines.append(f"Full report: {report_file}")
        lines.append("")
    lines.append("Use get_detections to drill into a specific rule or severity level.")
    lines.append("=" * 72)
    return "\n".join(lines)


def format_full_report(hits: list[dict[str, Any]], evtx_path: str) -> str:
    """Build the complete report text (written to file, not returned via MCP)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    grouped = _group_by_rule(hits)

    lines: list[str] = [
        "=" * 72,
        "  ChainsawMCP — ANALYST REPORT",
        "=" * 72,
        f"Generated : {now}",
        f"Evidence  : {evtx_path}",
        f"Total hits: {len(hits)}",
        f"Rules hit : {len(grouped)}",
        "",
    ]

    if not hits:
        lines += ["No detections found.", "=" * 72]
        return "\n".join(lines)

    lines += ["-" * 72, "DETECTIONS BY RULE", "-" * 72, ""]

    for rule_name, rule_hits in sorted(grouped.items(), key=lambda x: -len(x[1])):
        severity = _extract_severity(rule_hits[0])
        lines += [
            f"Rule     : {rule_name}",
            f"Severity : {severity}",
            f"Hits     : {len(rule_hits)}",
            "Events:",
        ]
        for hit in rule_hits[:5]:
            lines.append(f"  {_format_hit(hit)}")
        if len(rule_hits) > 5:
            lines.append(f"  ... and {len(rule_hits) - 5} more event(s)")
        lines.append("")

    lines += ["=" * 72, "END OF REPORT", "=" * 72]
    return "\n".join(lines)


def format_summary_json(
    hits: list[dict[str, Any]],
    evtx_path: str,
    report_file: Path | None = None,
) -> dict[str, Any]:
    """Return hunt summary as a structured dict for JSON output."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    grouped = _group_by_rule(hits)
    by_severity = _count_by_severity(hits)

    top_rules = [
        {
            "rule": rule,
            "severity": _extract_severity(rule_hits[0]),
            "count": len(rule_hits),
        }
        for rule, rule_hits in sorted(grouped.items(), key=lambda x: -len(x[1]))[:15]
    ]

    return {
        "generated": now,
        "evidence": evtx_path,
        "report_file": str(report_file) if report_file else None,
        "summary": {
            "total": len(hits),
            "rules_triggered": len(grouped),
            **{sev: count for sev, count in by_severity.items()},
        },
        "top_rules": top_rules,
    }


def get_detections_json(
    hits: list[dict[str, Any]],
    rule: str | None = None,
    severity: str | None = None,
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    """Return paginated detections as a structured dict for JSON output."""
    filtered = hits

    if severity:
        sev_lower = severity.lower()
        filtered = [h for h in filtered if _extract_severity(h).lower() == sev_lower]

    if rule:
        rule_lower = rule.lower()
        filtered = [h for h in filtered if rule_lower in _rule_name(h).lower()]

    total = len(filtered)
    page = max(1, page)
    page_size = max(1, page_size)
    total_pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    page_hits = filtered[start : start + page_size]

    return {
        "filters": {"rule": rule, "severity": severity},
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "hits": [_hit_to_dict(h) for h in page_hits],
    }


def _hit_to_dict(hit: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw Chainsaw hit to a clean structured dict."""
    system = _get_system(hit)

    ts = hit.get("timestamp")
    if not ts:
        tc = system.get("TimeCreated", {})
        ts = (
            tc.get("SystemTime")
            or tc.get("@SystemTime")
            or tc.get("#attributes", {}).get("SystemTime")
        )

    eid = system.get("EventID", "?")
    if isinstance(eid, dict):
        eid = eid.get("#text") or eid.get("@text") or str(eid)

    return {
        "rule": _rule_name(hit),
        "severity": _extract_severity(hit),
        "timestamp": ts,
        "event_id": str(eid) if eid else None,
        "computer": system.get("Computer"),
        "data": _get_event_data(hit),
    }


def get_detections(
    hits: list[dict[str, Any]],
    rule: str | None = None,
    severity: str | None = None,
    limit: int = 25,
) -> str:
    """Return formatted events for a filtered subset of hits."""
    filtered = hits

    if severity:
        sev_lower = severity.lower()
        filtered = [h for h in filtered if _extract_severity(h).lower() == sev_lower]

    if rule:
        rule_lower = rule.lower()
        filtered = [h for h in filtered if rule_lower in _rule_name(h).lower()]

    if not filtered:
        filter_desc = []
        if rule:
            filter_desc.append(f"rule containing '{rule}'")
        if severity:
            filter_desc.append(f"severity '{severity}'")
        return f"No hits matched filters: {', '.join(filter_desc)}."

    total = len(filtered)
    shown = filtered[:limit]

    lines = [
        f"Showing {len(shown)} of {total} hit(s)" +
        (f" matching rule='{rule}'" if rule else "") +
        (f" severity='{severity}'" if severity else "") + ":",
        "",
    ]
    for hit in shown:
        lines.append(f"  [{_extract_severity(hit)}]  {_rule_name(hit)}")
        lines.append(f"    {_format_hit(hit)}")
        event_data = _format_event_data(hit)
        if event_data:
            lines.append(f"    {event_data}")
    if total > limit:
        lines.append(f"\n... {total - limit} more hit(s) — increase limit or narrow filters.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _group_by_rule(hits: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for hit in hits:
        groups.setdefault(_rule_name(hit), []).append(hit)
    return groups


def _count_by_severity(hits: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for hit in hits:
        sev = _extract_severity(hit) or "unknown"
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _rule_name(hit: dict) -> str:
    return str(
        hit.get("name")
        or hit.get("rule_name")
        or hit.get("document", {}).get("name", "Unknown Rule")
    )


def _extract_severity(hit: dict) -> str:
    return (
        hit.get("level")
        or hit.get("severity")
        or hit.get("document", {}).get("level", "unknown")
    )


def _get_event(hit: dict) -> dict:
    """Return the Event block, handling both document.data.Event and document.Event paths."""
    doc = hit.get("document", {})
    # Chainsaw actual output: document.data.Event (lowercase 'data')
    # Fallback: document.Event (older / alternate builds)
    return doc.get("data", doc).get("Event", doc.get("Event", {}))


def _get_system(hit: dict) -> dict:
    """Return the System block."""
    return _get_event(hit).get("System", {})


def _get_event_data(hit: dict) -> dict:
    """Return the EventData block as a flat {name: value} dict."""
    event = _get_event(hit)
    ed = event.get("EventData", {})
    if not ed:
        return {}
    # Some parsers emit EventData.Data as a list of {"#attributes": {"Name": ...}, "#text": ...}
    if isinstance(ed.get("Data"), list):
        result: dict[str, Any] = {}
        for item in ed["Data"]:
            if isinstance(item, dict):
                name = item.get("#attributes", {}).get("Name") or item.get("@Name")
                val = item.get("#text") or item.get("@text")
                if name:
                    result[name] = val
        return result
    # Flat dict: {"TargetUserName": "...", "IpAddress": "...", ...}
    return {k: v for k, v in ed.items() if not k.startswith("#") and not k.startswith("@")}


def _format_hit(hit: dict) -> str:
    system = _get_system(hit)

    # Timestamp: prefer top-level hit.timestamp, fall back to System.TimeCreated
    ts = hit.get("timestamp")
    if not ts:
        tc = system.get("TimeCreated", {})
        ts = (
            tc.get("SystemTime")          # Chainsaw native format
            or tc.get("@SystemTime")      # alternate serialisation
            or tc.get("#attributes", {}).get("SystemTime")
            or "?"
        )

    # EventID may be an int, a string, or a dict
    eid = system.get("EventID", "?")
    if isinstance(eid, dict):
        eid = eid.get("#text") or eid.get("@text") or str(eid)

    computer = system.get("Computer", "?")
    return f"[{ts}] EventID={eid} Computer={computer}"


def _format_event_data(hit: dict) -> str:
    """Return a single-line summary of the most useful EventData fields."""
    ed = _get_event_data(hit)
    if not ed:
        return ""

    # Combine domain + username into a single User field
    parts: list[str] = []
    user = ed.get("TargetUserName") or ed.get("SubjectUserName")
    domain = ed.get("TargetDomainName") or ed.get("SubjectDomainName")
    if user and str(user) not in ("-", "??", ""):
        parts.append(f"User={domain}\\{user}" if domain and str(domain) not in ("-", "??", "") else f"User={user}")

    # Priority fields for common Windows security events
    priority = [
        "IpAddress", "WorkstationName", "LogonType",
        "ServiceName", "ImagePath",
        "CommandLine", "ParentCommandLine",
        "ProcessName", "ParentProcessName",
        "ShareName", "RelativeTargetName",
        "ObjectName", "AccessMask",
    ]
    for key in priority:
        val = ed.get(key)
        if val and str(val) not in ("-", "??", "0x0", ""):
            parts.append(f"{key}={val}")

    # Fall back: show first few non-empty fields not already shown
    shown_keys = set(priority) | {"TargetUserName", "TargetDomainName", "SubjectUserName", "SubjectDomainName"}
    for key, val in ed.items():
        if key in shown_keys:
            continue
        if val and str(val) not in ("-", "??", "0x0", ""):
            parts.append(f"{key}={val}")
        if len(parts) >= 8:
            break

    return "  " + "  ".join(parts) if parts else ""
