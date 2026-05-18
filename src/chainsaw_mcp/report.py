"""Format enriched results into a structured analyst report."""

from datetime import datetime, timezone
from typing import Any

from .enrichment import EnrichmentResult


def format_report(
    result: EnrichmentResult,
    evtx_path: str,
    total_hits: int,
    metadata: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = []

    lines += [
        "=" * 72,
        "  CHAINSAW MCP — ANALYST REPORT",
        "=" * 72,
        f"Generated : {now}",
        f"Evidence  : {evtx_path}",
        f"Total hits: {total_hits}",
    ]

    if metadata:
        for k, v in metadata.items():
            lines.append(f"{k:<10}: {v}")

    lines += ["", "-" * 72, "EXECUTIVE SUMMARY", "-" * 72, result.rollup, ""]

    # Confidence breakdown
    high = [b for b in result.batches if b.confidence == "HIGH"]
    med  = [b for b in result.batches if b.confidence == "MEDIUM"]
    low  = [b for b in result.batches if b.confidence == "LOW"]

    lines += [
        "-" * 72,
        "FINDINGS BY CONFIDENCE",
        "-" * 72,
        f"  HIGH   : {len(high)} rule(s)",
        f"  MEDIUM : {len(med)} rule(s)",
        f"  LOW    : {len(low)} rule(s)",
        "",
    ]

    for section_label, section_batches in [("HIGH", high), ("MEDIUM", med), ("LOW", low)]:
        if not section_batches:
            continue
        lines += [f"{'=' * 20} {section_label} CONFIDENCE {'=' * 20}"]
        for batch in section_batches:
            lines += [
                "",
                f"Rule   : {batch.rule_key}",
                f"Hits   : {len(batch.hits)}",
                f"Analysis:",
                _indent(batch.narrative, "  "),
                "",
                "  Sample events:",
            ]
            for hit in batch.hits[:3]:
                lines.append(_indent(_format_hit(hit), "    "))
            if len(batch.hits) > 3:
                lines.append(f"    ... and {len(batch.hits) - 3} more event(s)")
            lines.append("")

    lines += ["=" * 72, "END OF REPORT", "=" * 72]
    return "\n".join(lines)


def _format_hit(hit: dict) -> str:
    doc = hit.get("document", hit)
    system = doc.get("System", {})
    ts = system.get("TimeCreated", {}).get("@SystemTime", hit.get("timestamp", "?"))
    eid = system.get("EventID", {})
    if isinstance(eid, dict):
        eid = eid.get("#text", "?")
    computer = system.get("Computer", "?")
    return f"[{ts}] EventID={eid} Computer={computer}"


def _indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + line for line in text.splitlines())
