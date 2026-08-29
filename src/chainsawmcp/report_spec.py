"""Canonical incident-report specification.

This module is the single source of truth for the structure of the analyst-facing
incident report. Every client — Claude Code via the skill, the OpenWebUI Filter, the
OpenWebUI Pipe — pulls its report format from here over MCP rather than embedding its
own copy, so the report a local model produces has the same shape as the one a hosted
model produces.

Sections are either:

  server — rendered deterministically in Python from ``hunt_results.json``
           (see ``report_markdown.py``). Byte-identical across providers.
  model  — genuinely narrative; the client's model writes these into marked slots.

The numbering of sections 1-8 matches the template that previously lived inline in
``extras/chainsaw_filter.py`` so existing OpenWebUI users see no change in the report
they already receive. Section 9 carries the chain-of-custody block that the server can
render but no client previously asked for.
"""

from dataclasses import dataclass

SPEC_VERSION = "1.0"

#: Emitted around every model-authored section so the validator can tell a filled
#: section from an untouched one. HTML comments render as nothing in Markdown.
SLOT_BEGIN = "<!-- CHAINSAWMCP:BEGIN section={section_id} -->"
SLOT_END = "<!-- CHAINSAWMCP:END section={section_id} -->"

#: The italic line inside an unfilled slot. Its presence means the model never wrote
#: the section; the validator treats that as a violation.
SLOT_PLACEHOLDER = "_(replace this block: {instruction_summary})_"


@dataclass(frozen=True)
class Section:
    """One section of the canonical report."""

    id: str
    number: int
    title: str
    mode: str  # "server" | "model"
    instruction: str
    required: bool = True

    @property
    def heading(self) -> str:
        """The exact Markdown heading emitted for this section."""
        return f"## {self.number}. {self.title}"

    @property
    def summary(self) -> str:
        """First sentence of the instruction, for the in-slot placeholder line."""
        first = self.instruction.strip().split(". ")[0].strip()
        return first.rstrip(".")


SECTIONS: tuple[Section, ...] = (
    Section(
        id="executive_summary",
        number=1,
        title="Executive Summary",
        mode="model",
        instruction=(
            "One paragraph suitable for non-technical stakeholders. State what happened, "
            "when, and the likely impact. Cite the hit_id(s) supporting each claim."
        ),
    ),
    Section(
        id="mitre_attack",
        number=2,
        title="MITRE ATT&CK Mapping",
        mode="server",
        instruction=(
            "Rendered by the server from the Sigma rule tags carried in the hunt output. "
            "Technique IDs come from the rules that actually fired — do not add, rename, "
            "or infer techniques."
        ),
    ),
    Section(
        id="timeline",
        number=3,
        title="Timeline of Events",
        mode="server",
        instruction=(
            "Rendered by the server from event log timestamps, in chronological order, "
            "filtered to the configured severity floor."
        ),
    ),
    Section(
        id="iocs",
        number=4,
        title="Indicators of Compromise (IOCs)",
        mode="server",
        instruction=(
            "Rendered by the server by extracting indicators from the EventData of every "
            "hit, grouped by type."
        ),
    ),
    Section(
        id="accounts_systems",
        number=5,
        title="Compromised Accounts and Systems",
        mode="server",
        instruction=(
            "Rendered by the server from the accounts and hostnames appearing in the "
            "detections, with first/last seen and hit counts."
        ),
    ),
    Section(
        id="attack_narrative",
        number=6,
        title="Attack Narrative",
        mode="model",
        instruction=(
            "Describe the full attack chain in plain English: initial access -> execution "
            "-> persistence -> privilege escalation -> lateral movement -> collection -> "
            "exfiltration/impact. Cite the hit_id(s) behind every step. Where the evidence "
            "does not support a phase, say so rather than filling the gap."
        ),
    ),
    Section(
        id="recommendations",
        number=7,
        title="Recommendations",
        mode="model",
        instruction=(
            "Prioritised remediation steps — immediate containment first, then hardening, "
            "then monitoring. Tie each recommendation to the finding that motivates it."
        ),
    ),
    Section(
        id="gaps",
        number=8,
        title="Gaps and Limitations",
        mode="model",
        instruction=(
            "Note any log gaps, missing data sources, or caveats that affect confidence in "
            "the findings. State what the evidence cannot show."
        ),
    ),
    Section(
        id="provenance",
        number=9,
        title="Evidence & Provenance",
        mode="server",
        instruction=(
            "Rendered by the server from chainsaw_provenance.json: the exact command, "
            "Chainsaw version, binary and output SHA-256, and UTC completion time."
        ),
    ),
)

MODEL_SECTIONS: tuple[Section, ...] = tuple(s for s in SECTIONS if s.mode == "model")
SERVER_SECTIONS: tuple[Section, ...] = tuple(s for s in SECTIONS if s.mode == "server")


def get_section(section_id: str) -> Section | None:
    """Return the section with *section_id*, or None."""
    for section in SECTIONS:
        if section.id == section_id:
            return section
    return None


def slot_begin(section: Section) -> str:
    return SLOT_BEGIN.format(section_id=section.id)


def slot_end(section: Section) -> str:
    return SLOT_END.format(section_id=section.id)


def slot_placeholder(section: Section) -> str:
    return SLOT_PLACEHOLDER.format(instruction_summary=section.summary)


def render_slot(section: Section) -> str:
    """Return the unfilled slot block for a model-authored *section*."""
    return "\n".join(
        [
            slot_begin(section),
            slot_placeholder(section),
            slot_end(section),
        ]
    )


def render_spec_text() -> str:
    """Return the canonical report specification as Markdown.

    This is what ``get_report_spec`` serves and what every client injects into its
    model prompt. It describes the whole report, marks which sections the server has
    already filled in, and gives per-section instructions for the rest.
    """
    lines = [
        f"# ChainsawMCP Incident Report Specification (v{SPEC_VERSION})",
        "",
        "The incident report has a fixed structure. Sections marked SERVER-RENDERED are",
        "already written into the report skeleton by ChainsawMCP from the hash-verified",
        "hunt output — do not rewrite, reorder, summarise, or extend them. Sections marked",
        "YOU WRITE are yours to fill in, in place, between the slot markers.",
        "",
        "Rules that apply to the whole report:",
        "",
        "- Keep the section headings exactly as given, in the order given.",
        "- Every factual claim you write must cite the hit_id(s) it rests on, as",
        "  `ref=<hit_id>`. A claim with no hit_id is unsupported — withdraw it.",
        "- All timestamps are UTC ISO-8601 with a trailing Z (e.g. 2026-06-07T14:30:00Z).",
        "- Do not invent hosts, accounts, IPs, techniques, or events that Chainsaw did not",
        "  detect. The absence of evidence belongs in section 8, not in a narrative.",
        "",
        "---",
        "",
    ]

    for section in SECTIONS:
        marker = "SERVER-RENDERED" if section.mode == "server" else "YOU WRITE"
        lines += [f"{section.heading}  — {marker}", "", section.instruction, ""]

    lines += [
        "---",
        "",
        "When the report is complete, call `validate_report()`. It checks the structure and",
        "resolves every hit_id you cited against the hunt output. Fix any violations it",
        "reports and validate again.",
    ]
    return "\n".join(lines)
