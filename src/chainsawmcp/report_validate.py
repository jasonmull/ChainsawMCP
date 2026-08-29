"""Deterministic conformance checking for the incident report.

This is the enforcement half of the consistent-format design. A specification only
constrains a model that chooses to follow it; this module checks the produced document
mechanically, so a report that drifts is caught the same way regardless of which model
wrote it.

Nothing here is a judgement about analytical quality — every check is a structural or
citation fact that can be decided from the text and the hunt output alone.
"""

import re
from typing import Any

from .report import resolve_hit_ids
from .report_spec import (
    MODEL_SECTIONS,
    SECTIONS,
    SPEC_VERSION,
    Section,
    slot_begin,
    slot_end,
    slot_placeholder,
)

#: Citations as written in the report, e.g. "ref=8f7cba50-000123" or "`ref=...`".
_REF_RE = re.compile(r"ref=\s*`?([A-Za-z0-9][\w.-]*)`?")

#: A full ISO-8601 date-time. The canonical form the project mandates ends in Z; this
#: matches the broader shape so non-UTC variants can be reported rather than missed.
_TIMESTAMP_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?)(Z|[+-]\d{2}:?\d{2})?"
)

#: Minimum characters of prose before a model section counts as written. Low enough not
#: to penalise a genuinely short section, high enough to catch "TODO" and "N/A".
_MIN_SECTION_CHARS = 80


def _violation(code: str, message: str, section_id: str = "") -> dict[str, str]:
    return {"code": code, "section": section_id, "message": message}


def _split_sections(text: str) -> dict[str, str]:
    """Return {section_id: body} for every canonical heading present in *text*."""
    positions: list[tuple[int, Section]] = []
    for section in SECTIONS:
        # Anchor to line start so a heading quoted mid-paragraph is not mistaken for
        # the real one.
        match = re.search(
            rf"^{re.escape(section.heading)}\s*$", text, re.MULTILINE
        )
        if match:
            positions.append((match.start(), section))

    positions.sort(key=lambda p: p[0])
    bodies: dict[str, str] = {}
    for index, (start, section) in enumerate(positions):
        end = positions[index + 1][0] if index + 1 < len(positions) else len(text)
        heading_end = text.find("\n", start)
        body_start = heading_end + 1 if heading_end != -1 else end
        bodies[section.id] = text[body_start:end].strip()
    return bodies


def _check_structure(text: str) -> list[dict[str, str]]:
    violations: list[dict[str, str]] = []
    found_order: list[str] = []

    for section in SECTIONS:
        match = re.search(rf"^{re.escape(section.heading)}\s*$", text, re.MULTILINE)
        if match:
            found_order.append(section.id)
        elif section.required:
            violations.append(
                _violation(
                    "missing_section",
                    f"Required section heading is missing: '{section.heading}'.",
                    section.id,
                )
            )

    expected_order = [s.id for s in SECTIONS if s.id in found_order]
    if found_order != expected_order:
        violations.append(
            _violation(
                "section_order",
                "Sections appear out of specification order. Expected: "
                + " -> ".join(expected_order)
                + "; found: "
                + " -> ".join(found_order)
                + ".",
            )
        )
    return violations


def _check_model_sections(text: str, bodies: dict[str, str]) -> list[dict[str, str]]:
    violations: list[dict[str, str]] = []

    for section in MODEL_SECTIONS:
        body = bodies.get(section.id)
        if body is None:
            continue  # already reported as a missing section

        if slot_placeholder(section) in body:
            violations.append(
                _violation(
                    "unfilled_slot",
                    f"Section {section.number} still contains its placeholder line — "
                    "the model has not written this section.",
                    section.id,
                )
            )
            continue

        # Strip the slot markers to measure the prose the model actually contributed.
        prose = body.replace(slot_begin(section), "").replace(slot_end(section), "").strip()

        if len(prose) < _MIN_SECTION_CHARS:
            violations.append(
                _violation(
                    "empty_section",
                    f"Section {section.number} has {len(prose)} characters of content; "
                    f"at least {_MIN_SECTION_CHARS} expected. Write the section or state "
                    "explicitly why the evidence does not support it.",
                    section.id,
                )
            )
            continue

        if not _REF_RE.search(prose):
            violations.append(
                _violation(
                    "uncited_section",
                    f"Section {section.number} contains no ref=<hit_id> citation. Every "
                    "factual claim must cite the detection it rests on.",
                    section.id,
                )
            )
    return violations


def _check_timestamps(text: str) -> list[dict[str, str]]:
    violations: list[dict[str, str]] = []
    offenders: list[str] = []

    for match in _TIMESTAMP_RE.finditer(text):
        stamp, suffix = match.group(1), match.group(2)
        if suffix == "Z":
            continue
        rendered = stamp + (suffix or "")
        if rendered not in offenders:
            offenders.append(rendered)

    if offenders:
        shown = ", ".join(offenders[:5])
        more = f" (+{len(offenders) - 5} more)" if len(offenders) > 5 else ""
        violations.append(
            _violation(
                "non_utc_timestamp",
                "Timestamps must be UTC ISO-8601 ending in Z (e.g. 2026-06-07T14:30:00Z). "
                f"Found: {shown}{more}.",
            )
        )
    return violations


def _check_citations(
    text: str, hits: list[dict[str, Any]]
) -> tuple[list[dict[str, str]], list[str], list[str]]:
    cited = sorted({m.group(1).rstrip(".,;:)") for m in _REF_RE.finditer(text)})
    if not cited:
        return (
            [
                _violation(
                    "no_citations",
                    "The report cites no hit_ids at all. Every factual claim must be "
                    "traceable to a detection via ref=<hit_id>.",
                )
            ],
            [],
            [],
        )

    _, unresolved = resolve_hit_ids(hits, cited)
    violations: list[dict[str, str]] = []
    if unresolved:
        shown = ", ".join(unresolved[:10])
        more = f" (+{len(unresolved) - 10} more)" if len(unresolved) > 10 else ""
        violations.append(
            _violation(
                "unresolved_citation",
                f"{len(unresolved)} cited hit_id(s) do not exist in the hunt output — "
                f"these are unsupported claims and must be withdrawn or corrected: "
                f"{shown}{more}.",
            )
        )
    return violations, cited, unresolved


def validate_report_text(
    text: str, hits: list[dict[str, Any]]
) -> dict[str, Any]:
    """Check *text* against the canonical spec and the hunt output.

    Returns a result dict with a boolean ``pass``, the list of ``violations``, and the
    citation accounting. Callers render this however suits them; the shape is stable
    enough to drive an automated fix-and-revalidate loop.
    """
    bodies = _split_sections(text)

    violations = _check_structure(text)
    violations += _check_model_sections(text, bodies)
    violations += _check_timestamps(text)
    citation_violations, cited, unresolved = _check_citations(text, hits)
    violations += citation_violations

    return {
        "spec_version": SPEC_VERSION,
        "pass": not violations,
        "violations": violations,
        "sections_found": sorted(bodies.keys()),
        "cited": len(cited),
        "unresolved": unresolved,
    }
