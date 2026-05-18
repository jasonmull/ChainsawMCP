"""Format Chainsaw hunt results into a structured analyst report."""

from datetime import datetime, timezone
from typing import Any


def format_report(hits: list[dict[str, Any]], evtx_path: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    grouped = _group_by_rule(hits)

    lines: list[str] = []
    lines += [
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


def _group_by_rule(hits: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for hit in hits:
        key = str(
            hit.get("name")
            or hit.get("rule_name")
            or hit.get("document", {}).get("name", "Unknown Rule")
        )
        groups.setdefault(key, []).append(hit)
    return groups


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
