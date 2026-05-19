"""Format Chainsaw hunt results into analyst reports."""

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


def _format_hit(hit: dict) -> str:
    doc = hit.get("document", hit)
    system = doc.get("System", {})
    ts = system.get("TimeCreated", {}).get("@SystemTime", hit.get("timestamp", "?"))
    eid = system.get("EventID", {})
    if isinstance(eid, dict):
        eid = eid.get("#text", "?")
    computer = system.get("Computer", "?")
    user = system.get("Security", {}).get("@UserID", "?")
    return f"[{ts}] EventID={eid} Computer={computer} User={user}"
