"""Deterministic Markdown rendering of the canonical incident report.

Everything in this module is pure Python over the hits in ``hunt_results.json`` — no
LLM calls, no inference, no heuristics beyond field extraction. Given the same hunt
output it produces byte-identical text, which is the point: the sections rendered here
do not vary with the client's model or inference provider.

The model-authored sections (see ``report_spec.MODEL_SECTIONS``) are emitted as empty
slots for the client to fill in place.
"""

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .jobs import read_provenance
from .report import (
    _count_by_severity,
    _extract_severity,
    _get_event_data,
    _get_system,
    _group_by_rule,
    _rule_name,
)
from .report_spec import SECTIONS, SPEC_VERSION, Section, render_slot

# Severity ordering, most severe first. Chainsaw/Sigma levels plus the "unknown"
# fallback _extract_severity returns for malformed records.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "unknown")

#: Values that mean "no value" in Windows EventData. Mirrors the suppression list in
#: report._format_event_data.
EMPTY_VALUES: frozenset[str] = frozenset({"-", "??", "0x0", "", "null", "none", "N/A"})

_TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_SOFTWARE_RE = re.compile(r"^attack\.(s\d{4})$", re.IGNORECASE)
_GROUP_RE = re.compile(r"^attack\.(g\d{4})$", re.IGNORECASE)

#: Base64 runs long enough to be an encoded payload rather than an incidental token.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

#: Deliberately bounded with lookarounds rather than \b: these patterns are also run
#: over base64-decoded shellcode, where an indicator is frequently adjacent to a raw
#: byte that happens to be a word character, and \b would silently fail to match.
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>|)]+", re.IGNORECASE)
_PIPE_RE = re.compile(r"\\\\[.\w-]+\\pipe\\[\w.-]+", re.IGNORECASE)

#: EventData fields grouped into the IOC categories we emit.
_IOC_FIELDS: dict[str, tuple[str, ...]] = {
    "network": ("IpAddress", "SourceIp", "DestinationIp", "ClientAddress", "SourceAddress"),
    "hosts": ("Computer", "WorkstationName", "TargetServerName", "SourceWorkstation"),
    "services": ("ServiceName", "ServiceFileName", "ImagePath", "NewProcessName", "ProcessName"),
    "commands": ("CommandLine", "ParentCommandLine", "ScriptBlockText", "Payload"),
    "files": ("ObjectName", "TargetFilename", "RelativeTargetName", "ShareName"),
    "hashes": ("Hashes", "Hash", "MD5", "SHA1", "SHA256"),
}

_IOC_TITLES: dict[str, str] = {
    "network": "Network",
    "accounts": "Accounts",
    "hosts": "Hosts and workstations",
    "services": "Services, processes, and image paths",
    "commands": "Command lines and scripts",
    "files": "Files, shares, and objects",
    "pipes": "Named pipes",
    "hashes": "Hashes",
    "urls": "URLs",
}

#: Order IOC categories are rendered in.
_IOC_ORDER: tuple[str, ...] = (
    "network", "accounts", "hosts", "services", "commands", "files", "pipes", "hashes", "urls",
)

_MAX_IOC_PER_CATEGORY = 50
_MAX_REFS_PER_ROW = 3
_MAX_VALUE_LEN = 300

#: Bounds on the base64 sweep, so a hunt with very large script blocks stays fast.
_MAX_B64_RUNS_PER_FIELD = 8
_MAX_B64_RUN_LEN = 200_000

#: Free-text fields swept with regexes and base64-decoded.
_FREETEXT_FIELDS: tuple[str, ...] = (
    "CommandLine", "ParentCommandLine", "ScriptBlockText", "ImagePath",
    "ServiceFileName", "Payload", "Data",
)

#: Addresses that carry no investigative meaning. Loopback is deliberately NOT here:
#: \\127.0.0.1\ADMIN$ is the PSExec-style service-install pattern and is a real signal.
_IP_DISCARD: frozenset[str] = frozenset({"0.0.0.0", "255.255.255.255"})


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _severity_rank(severity: str) -> int:
    """Lower is more severe. Unknown severities sort last."""
    try:
        return SEVERITY_ORDER.index((severity or "unknown").lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    return not text or text.lower() in {v.lower() for v in EMPTY_VALUES}


def _normalise_timestamp(raw: Any) -> str:
    """Return *raw* as UTC ISO-8601 with a trailing Z, or "" if unparseable.

    Chainsaw emits offset-aware timestamps like 2018-05-04T22:16:46.632649+00:00;
    the report standardises on second-precision Z per the project's UTC rule.
    """
    if not raw:
        return ""
    text = str(raw).strip()
    if not text:
        return ""
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hit_timestamp(hit: dict) -> str:
    ts = hit.get("timestamp")
    if not ts:
        tc = _get_system(hit).get("TimeCreated", {})
        if isinstance(tc, dict):
            ts = (
                tc.get("SystemTime")
                or tc.get("@SystemTime")
                or tc.get("#attributes", {}).get("SystemTime")
            )
    return _normalise_timestamp(ts)


def _event_id(hit: dict) -> str:
    eid = _get_system(hit).get("EventID", "")
    if isinstance(eid, dict):
        eid = eid.get("#text") or eid.get("@text") or ""
    return str(eid) if not _is_empty(eid) else ""


def _tags(hit: dict) -> list[str]:
    tags = hit.get("tags")
    if not isinstance(tags, list):
        return []
    return [str(t) for t in tags if isinstance(t, str)]


def _md_escape(value: Any) -> str:
    """Make *value* safe to place inside a Markdown table cell."""
    text = str(value)
    if len(text) > _MAX_VALUE_LEN:
        text = text[:_MAX_VALUE_LEN] + "…"
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ").strip()


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    lines += ["| " + " | ".join(_md_escape(c) for c in row) + " |" for row in rows]
    return lines


def _refs(hit_ids: list[str]) -> str:
    """Render up to _MAX_REFS_PER_ROW citations for a table row."""
    shown = [h for h in hit_ids if h][:_MAX_REFS_PER_ROW]
    if not shown:
        return "—"
    text = ", ".join(f"ref={h}" for h in shown)
    remaining = len([h for h in hit_ids if h]) - len(shown)
    return f"{text} (+{remaining})" if remaining > 0 else text


# ---------------------------------------------------------------------------
# Section builders — pure, list[dict] -> dict
# ---------------------------------------------------------------------------

def build_mitre_rows(hits: list[dict[str, Any]]) -> dict[str, Any]:
    """Map hits to MITRE ATT&CK techniques via the Sigma rule tags in the hunt output.

    Only tags that actually fired are reported. Technique *names* are deliberately not
    emitted — they are not present in the data, and inventing them is exactly the kind
    of fabrication the citation discipline exists to prevent. Each row carries the Sigma
    rules that supplied the tag so the mapping is auditable.
    """
    techniques: dict[str, dict[str, Any]] = {}
    tactics: dict[str, int] = {}
    software: dict[str, set[str]] = {}
    tagged_hits = 0

    for hit in hits:
        tags = _tags(hit)
        if not tags:
            continue
        tagged_hits += 1
        rule = _rule_name(hit)
        severity = _extract_severity(hit)
        ts = _hit_timestamp(hit)
        hit_id = hit.get("hit_id") or ""

        for tag in tags:
            lowered = tag.lower()
            if not lowered.startswith("attack."):
                continue  # car.*, cve.*, detection.* and friends are not ATT&CK

            match = _TECHNIQUE_RE.match(lowered)
            if match:
                tech = match.group(1).upper()
                entry = techniques.setdefault(
                    tech,
                    {
                        "technique": tech,
                        "rules": set(),
                        "severities": set(),
                        "count": 0,
                        "first_seen": "",
                        "last_seen": "",
                        "hit_ids": [],
                    },
                )
                entry["rules"].add(rule)
                entry["severities"].add(severity)
                entry["count"] += 1
                if ts:
                    if not entry["first_seen"] or ts < entry["first_seen"]:
                        entry["first_seen"] = ts
                    if not entry["last_seen"] or ts > entry["last_seen"]:
                        entry["last_seen"] = ts
                if hit_id and len(entry["hit_ids"]) < _MAX_REFS_PER_ROW:
                    entry["hit_ids"].append(hit_id)
                continue

            sw = _SOFTWARE_RE.match(lowered) or _GROUP_RE.match(lowered)
            if sw:
                software.setdefault(sw.group(1).upper(), set()).add(rule)
                continue

            # Everything else under attack.* is a tactic. SigmaHQ is inconsistent about
            # the separator (attack.lateral-movement and attack.lateral_movement both
            # occur in real output), so normalise before counting.
            tactic = lowered[len("attack."):].replace("_", "-")
            if tactic:
                tactics[tactic] = tactics.get(tactic, 0) + 1

    rows = [
        {
            "technique": entry["technique"],
            "rules": sorted(entry["rules"]),
            "severity": sorted(entry["severities"], key=_severity_rank)[0],
            "count": entry["count"],
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
            "hit_ids": entry["hit_ids"],
        }
        for entry in techniques.values()
    ]
    # Most severe first, then most frequent, then technique ID for a stable order.
    rows.sort(key=lambda r: (_severity_rank(r["severity"]), -r["count"], r["technique"]))

    return {
        "techniques": rows,
        "tactics": [
            {"tactic": name, "count": count}
            for name, count in sorted(tactics.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "software": [
            {"id": sid, "rules": sorted(rules)} for sid, rules in sorted(software.items())
        ],
        "tagged_hits": tagged_hits,
        "untagged_hits": len(hits) - tagged_hits,
    }


def build_timeline(
    hits: list[dict[str, Any]],
    min_severity: str = "high",
    max_rows: int = 200,
) -> dict[str, Any]:
    """Chronological event table, filtered to a severity floor.

    The floor is not optional in practice: a real hunt is dominated by ``info`` hits
    (the FINDEVIL sample is 21,939 of 23,306), so an unfiltered timeline is both
    unreadable and far too large for a model's context.
    """
    floor = _severity_rank(min_severity)
    selected = [h for h in hits if _severity_rank(_extract_severity(h)) <= floor]

    rows = [
        {
            "timestamp": _hit_timestamp(hit),
            "computer": _get_system(hit).get("Computer") or "",
            "event_id": _event_id(hit),
            "rule": _rule_name(hit),
            "severity": _extract_severity(hit),
            "hit_id": hit.get("hit_id") or "",
        }
        for hit in selected
    ]
    # Undated records sort last rather than to the top of the timeline.
    rows.sort(key=lambda r: (not r["timestamp"], r["timestamp"], r["hit_id"]))

    truncated = max(0, len(rows) - max_rows) if max_rows > 0 else 0
    return {
        "min_severity": min_severity,
        "max_rows": max_rows,
        "total_matching": len(rows),
        "truncated": truncated,
        "rows": rows[:max_rows] if max_rows > 0 else rows,
    }


def _is_valid_ipv4(text: str) -> bool:
    """The IPv4 regex is shape-only; reject impossible octets and non-indicators."""
    if text in _IP_DISCARD:
        return False
    parts = text.split(".")
    if len(parts) != 4 or not all(p.isdigit() and int(p) <= 255 for p in parts):
        return False
    # Four-part version strings share IPv4's shape and are common in PowerShell event
    # text (HostVersion=1.0.0.0, EngineVersion=2.0.0.0). An address whose last three
    # octets are all zero is a network number, never a host indicator, so dropping the
    # form costs nothing and removes the whole false-positive class.
    return parts[1:] != ["0", "0", "0"]


def _decode_base64_payloads(text: str) -> list[str]:
    """Return plaintext decoded from base64 runs inside *text*.

    Attacker tooling routinely hides its real indicators inside base64-encoded
    PowerShell payloads — in the reference dataset the Cobalt Strike C2 address and SMB
    pipe name appear *only* inside encoded shellcode, not in any plaintext EventData
    field. Sweeping decoded content is what makes those indicators reachable without
    asking the model to decode payloads by hand.

    Both latin-1 and UTF-16LE are tried: PowerShell's -EncodedCommand is UTF-16LE, while
    embedded shellcode strings are usually single-byte.
    """
    decoded: list[str] = []
    for run in _B64_RE.findall(text)[:_MAX_B64_RUNS_PER_FIELD]:
        if len(run) > _MAX_B64_RUN_LEN:
            continue
        try:
            raw = base64.b64decode(run + "=" * (-len(run) % 4), validate=False)
        except (ValueError, binascii.Error):
            continue
        if not raw:
            continue
        for encoding in ("latin-1", "utf-16-le"):
            try:
                decoded.append(raw.decode(encoding, errors="ignore"))
            except (UnicodeDecodeError, LookupError):
                continue
    return decoded


def _add_ioc(
    buckets: dict[str, dict[str, dict[str, Any]]],
    category: str,
    value: Any,
    hit: dict,
    decoded: bool = False,
) -> None:
    if _is_empty(value):
        return
    text = str(value).strip()
    if category == "network" and _IPV4_RE.fullmatch(text) and not _is_valid_ipv4(text):
        return
    if len(text) > _MAX_VALUE_LEN:
        text = text[:_MAX_VALUE_LEN]
    bucket = buckets.setdefault(category, {})
    entry = bucket.setdefault(
        text,
        {"value": text, "count": 0, "hit_ids": [], "rules": set(), "decoded": False},
    )
    entry["count"] += 1
    entry["rules"].add(_rule_name(hit))
    # Sticky: an indicator recovered from an encoded payload stays marked as such, so
    # the report is explicit about how it was derived.
    entry["decoded"] = entry["decoded"] or decoded
    hit_id = hit.get("hit_id")
    if hit_id and len(entry["hit_ids"]) < _MAX_REFS_PER_ROW:
        entry["hit_ids"].append(hit_id)


def _sweep_text(
    buckets: dict[str, dict[str, dict[str, Any]]],
    text: str,
    hit: dict,
    decoded: bool,
) -> None:
    """Extract every regex-matchable indicator from a blob of free text."""
    for url in _URL_RE.findall(text):
        _add_ioc(buckets, "urls", url, hit, decoded)
    for pipe in _PIPE_RE.findall(text):
        _add_ioc(buckets, "pipes", pipe, hit, decoded)
    for ip in _IPV4_RE.findall(text):
        _add_ioc(buckets, "network", ip, hit, decoded)
    for digest in _HASH_RE.findall(text):
        _add_ioc(buckets, "hashes", digest, hit, decoded)


def build_iocs(hits: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract indicators from the EventData of every hit, grouped by type.

    Extraction is field-name driven with regex backup for indicators that only appear
    embedded in command lines. Placeholder values ("-", "??", "0x0") and machine
    accounts are dropped — they are noise, not indicators.
    """
    buckets: dict[str, dict[str, dict[str, Any]]] = {}

    for hit in hits:
        data = _get_event_data(hit)
        if not data:
            continue

        for category, fields in _IOC_FIELDS.items():
            for field in fields:
                _add_ioc(buckets, category, data.get(field), hit)

        # Accounts: combine domain and username, and drop machine accounts, which are
        # an artefact of how Windows logs computer authentication rather than an IOC.
        for user_field, domain_field in (
            ("TargetUserName", "TargetDomainName"),
            ("SubjectUserName", "SubjectDomainName"),
        ):
            user = data.get(user_field)
            if _is_empty(user) or str(user).endswith("$"):
                continue
            domain = data.get(domain_field)
            account = f"{domain}\\{user}" if not _is_empty(domain) else str(user)
            _add_ioc(buckets, "accounts", account, hit)

        # Regex sweep over free-text fields for indicators the field names miss, then
        # the same sweep over anything base64-encoded inside them.
        for field in _FREETEXT_FIELDS:
            text = data.get(field)
            if _is_empty(text):
                continue
            text = str(text)
            _sweep_text(buckets, text, hit, decoded=False)
            for payload in _decode_base64_payloads(text):
                _sweep_text(buckets, payload, hit, decoded=True)

    categories: dict[str, Any] = {}
    for category in _IOC_ORDER:
        entries = buckets.get(category)
        if not entries:
            continue
        ranked = sorted(entries.values(), key=lambda e: (-e["count"], e["value"]))
        categories[category] = {
            "title": _IOC_TITLES[category],
            "total": len(ranked),
            "truncated": max(0, len(ranked) - _MAX_IOC_PER_CATEGORY),
            "entries": [
                {
                    "value": e["value"],
                    "count": e["count"],
                    "hit_ids": e["hit_ids"],
                    "rules": sorted(e["rules"])[:3],
                    "decoded": e["decoded"],
                }
                for e in ranked[:_MAX_IOC_PER_CATEGORY]
            ],
        }
    return {"categories": categories}


def _observe(
    registry: dict[str, dict[str, Any]], key: Any, hit: dict, timestamp: str
) -> None:
    """Record one observation of a host or account.

    Grouping is case-insensitive, because Windows logs the same principal with
    inconsistent casing (SHIELDBASE\\spsql and shieldbase\\spsql are one account). It
    is deliberately NOT more aggressive than that: shieldbase\\spsql and
    shieldbase.lan\\spsql stay separate rows, because treating a NetBIOS name and a DNS
    name as the same principal is an inference, not an observation. The rendered
    section says so, and the observed spellings are listed.
    """
    if _is_empty(key):
        return
    name = str(key).strip()
    entry = registry.setdefault(
        name.casefold(),
        {
            "name": name,
            "count": 0,
            "first_seen": "",
            "last_seen": "",
            "max_severity": "unknown",
            "hit_ids": [],
            "variants": set(),
        },
    )
    entry["variants"].add(name)
    entry["count"] += 1
    severity = _extract_severity(hit)
    if _severity_rank(severity) < _severity_rank(entry["max_severity"]):
        entry["max_severity"] = severity
    if timestamp:
        if not entry["first_seen"] or timestamp < entry["first_seen"]:
            entry["first_seen"] = timestamp
        if not entry["last_seen"] or timestamp > entry["last_seen"]:
            entry["last_seen"] = timestamp
    hit_id = hit.get("hit_id")
    if hit_id and len(entry["hit_ids"]) < _MAX_REFS_PER_ROW:
        entry["hit_ids"].append(hit_id)


def build_hosts_accounts(hits: list[dict[str, Any]]) -> dict[str, Any]:
    """Every host and account appearing in the detections, with activity windows.

    "Appears in the detections" is a factual statement about the event logs, not a
    finding of compromise — the rendered section says so, and attributing compromise
    is left to the analyst and the narrative sections.
    """
    hosts: dict[str, dict[str, Any]] = {}
    accounts: dict[str, dict[str, Any]] = {}

    for hit in hits:
        ts = _hit_timestamp(hit)
        _observe(hosts, _get_system(hit).get("Computer"), hit, ts)

        data = _get_event_data(hit)
        if not data:
            continue
        _observe(hosts, data.get("WorkstationName"), hit, ts)
        for user_field, domain_field in (
            ("TargetUserName", "TargetDomainName"),
            ("SubjectUserName", "SubjectDomainName"),
        ):
            user = data.get(user_field)
            if _is_empty(user) or str(user).endswith("$"):
                continue
            domain = data.get(domain_field)
            account = f"{domain}\\{user}" if not _is_empty(domain) else str(user)
            _observe(accounts, account, hit, ts)

    def _rank(entries: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        ranked = sorted(
            entries.values(),
            key=lambda e: (_severity_rank(e["max_severity"]), -e["count"], e["name"]),
        )
        return [{**e, "variants": sorted(e["variants"])} for e in ranked]

    return {"hosts": _rank(hosts), "accounts": _rank(accounts)}


def build_provenance_block(job_id: str, evidence_path: str = "") -> dict[str, Any]:
    """Chain-of-custody facts for the report. Degrades to a note when unavailable."""
    prov = read_provenance(job_id)
    if not prov:
        return {"job_id": job_id, "evidence": evidence_path, "available": False}
    return {
        "job_id": job_id,
        "evidence": evidence_path,
        "available": True,
        "command": " ".join(prov.get("command", []) or []),
        "chainsaw_version": prov.get("chainsaw_version"),
        "chainsaw_sha256": prov.get("chainsaw_sha256") or prov.get("binary_sha256"),
        "output_file": prov.get("output_file"),
        "output_sha256": prov.get("output_sha256"),
        "raw_output_file": prov.get("raw_output_file"),
        "raw_output_sha256": prov.get("raw_output_sha256"),
        "completed_at": prov.get("completed_at") or prov.get("finished_at"),
    }


# ---------------------------------------------------------------------------
# Section rendering
# ---------------------------------------------------------------------------

def _render_mitre(mitre: dict[str, Any]) -> list[str]:
    rows = mitre["techniques"]
    if not rows:
        return [
            "No ATT&CK-tagged rules fired. Chainsaw's built-in rules carry no Sigma tags, "
            "so a hunt run without `--sigma` produces no mapping.",
        ]

    lines = [
        "Derived from the Sigma rule tags carried by the rules that fired. Technique IDs "
        "are reported exactly as tagged; the contributing rule names are given so each "
        "mapping can be audited back to its rule.",
        "",
    ]
    lines += _table(
        ["Technique", "Severity", "Hits", "First seen (UTC)", "Last seen (UTC)", "Contributing rules", "Refs"],
        [
            [
                row["technique"],
                row["severity"],
                str(row["count"]),
                row["first_seen"] or "—",
                row["last_seen"] or "—",
                "; ".join(row["rules"][:3]) + (f" (+{len(row['rules']) - 3})" if len(row["rules"]) > 3 else ""),
                _refs(row["hit_ids"]),
            ]
            for row in rows
        ],
    )

    if mitre["tactics"]:
        lines += ["", "**Tactic coverage**", ""]
        lines += _table(
            ["Tactic", "Hits"],
            [[t["tactic"], str(t["count"])] for t in mitre["tactics"]],
        )

    if mitre["software"]:
        lines += ["", "**Tagged software / groups**", ""]
        lines += _table(
            ["ID", "Contributing rules"],
            [[s["id"], "; ".join(s["rules"][:3])] for s in mitre["software"]],
        )

    lines += [
        "",
        f"_{mitre['tagged_hits']} of {mitre['tagged_hits'] + mitre['untagged_hits']} hits "
        "carry ATT&CK tags; untagged hits are still reported elsewhere in this report._",
    ]
    return lines


def _render_timeline(timeline: dict[str, Any]) -> list[str]:
    if not timeline["rows"]:
        return [
            f"No detections at severity `{timeline['min_severity']}` or above.",
        ]

    lines = [
        f"All detections at severity `{timeline['min_severity']}` or above, in "
        f"chronological order. {timeline['total_matching']} event(s) matched.",
        "",
    ]
    lines += _table(
        ["Timestamp (UTC)", "Computer", "EventID", "Rule", "Severity", "Ref"],
        [
            [
                row["timestamp"] or "—",
                row["computer"] or "—",
                row["event_id"] or "—",
                row["rule"],
                row["severity"],
                f"ref={row['hit_id']}" if row["hit_id"] else "—",
            ]
            for row in timeline["rows"]
        ],
    )
    if timeline["truncated"]:
        lines += [
            "",
            f"_{timeline['truncated']} further event(s) at this severity are not shown. "
            "Use `get_detections` to page through the full set._",
        ]
    return lines


def _render_iocs(iocs: dict[str, Any]) -> list[str]:
    categories = iocs["categories"]
    if not categories:
        return ["No indicators were extractable from the EventData of the hits in this hunt."]

    any_decoded = any(
        entry["decoded"]
        for block in categories.values()
        for entry in block["entries"]
    )

    lines = [
        "Extracted from the EventData of every hit in the hunt, including indicators "
        "recovered by base64-decoding encoded payloads. Presence here means the value "
        "appeared in a detected event — it is not by itself a determination that the "
        "indicator is malicious.",
    ]
    if any_decoded:
        lines += [
            "",
            "Rows marked **decoded** were not present in plaintext: they were recovered "
            "by decoding a base64 payload inside the cited event. Verify them with "
            "`get_hit` against the cited hit_id before acting on them.",
        ]

    for key in _IOC_ORDER:
        block = categories.get(key)
        if not block:
            continue
        lines += ["", f"### {block['title']}", ""]
        lines += _table(
            ["Indicator", "Occurrences", "Source", "Refs"],
            [
                [
                    entry["value"],
                    str(entry["count"]),
                    "decoded" if entry["decoded"] else "plaintext",
                    _refs(entry["hit_ids"]),
                ]
                for entry in block["entries"]
            ],
        )
        if block["truncated"]:
            lines += [
                "",
                f"_{block['truncated']} further distinct value(s) not shown._",
            ]
    return lines


def _render_hosts_accounts(inventory: dict[str, Any]) -> list[str]:
    lines = [
        "Every host and account appearing in the detections, with the window over which "
        "it appears. Appearing here is a statement about the event logs, not a finding "
        "of compromise — attribution belongs in section 6.",
        "",
        "Names are grouped case-insensitively. The same principal may still appear on "
        "more than one row when Windows logged it under different domain qualifiers "
        "(e.g. a NetBIOS name and a DNS name); those are not merged, because treating "
        "them as one identity is an inference rather than an observation.",
    ]
    for title, entries in (("Hosts", inventory["hosts"]), ("Accounts", inventory["accounts"])):
        lines += ["", f"### {title}", ""]
        if not entries:
            lines.append(f"No {title.lower()} were extractable from these detections.")
            continue
        lines += _table(
            ["Name", "Max severity", "Hits", "First seen (UTC)", "Last seen (UTC)", "Observed as", "Refs"],
            [
                [
                    entry["name"],
                    entry["max_severity"],
                    str(entry["count"]),
                    entry["first_seen"] or "—",
                    entry["last_seen"] or "—",
                    "; ".join(entry["variants"]) if len(entry["variants"]) > 1 else "—",
                    _refs(entry["hit_ids"]),
                ]
                for entry in entries
            ],
        )
    return lines


def _render_provenance(prov: dict[str, Any], hits: list[dict[str, Any]]) -> list[str]:
    by_severity = _count_by_severity(hits)
    severity_line = ", ".join(
        f"{count} {sev}"
        for sev, count in sorted(by_severity.items(), key=lambda kv: _severity_rank(kv[0]))
    )

    lines = [
        "Every detection in this report came from the Chainsaw binary run as a subprocess. "
        "ChainsawMCP makes no LLM calls and adds no detection logic of its own.",
        "",
    ]
    rows = [
        ["Job ID", prov.get("job_id") or "—"],
        ["Evidence", prov.get("evidence") or "—"],
        ["Total hits", str(len(hits))],
        ["Rules triggered", str(len(_group_by_rule(hits)))],
        ["Severity breakdown", severity_line or "—"],
    ]
    if prov.get("available"):
        rows += [
            ["Chainsaw version", prov.get("chainsaw_version") or "—"],
            ["Chainsaw SHA-256", prov.get("chainsaw_sha256") or "—"],
            ["Command", prov.get("command") or "—"],
            ["Output file", prov.get("output_file") or "—"],
            ["Output SHA-256", prov.get("output_sha256") or "—"],
        ]
        if prov.get("raw_output_sha256"):
            rows += [
                ["Raw output file", prov.get("raw_output_file") or "—"],
                ["Raw output SHA-256", prov.get("raw_output_sha256") or "—"],
            ]
        rows.append(["Hunt completed (UTC)", prov.get("completed_at") or "—"])

    lines += _table(["Field", "Value"], rows)

    if not prov.get("available"):
        lines += [
            "",
            "> **Provenance record unavailable.** `chainsaw_provenance.json` could not be "
            "read for this job, so the command, tool version, and output hashes are not "
            "recorded here. Findings above remain traceable by `hit_id`, but the "
            "chain-of-custody anchor is incomplete — note this in section 8.",
        ]
    else:
        lines += [
            "",
            "Any `ref=<hit_id>` cited in this report resolves to its full raw record via "
            "`get_hit`, which returns the same output SHA-256 shown above. A hit_id that "
            "does not resolve is an unsupported claim.",
        ]
    return lines


def render_section_body(
    section: Section,
    hits: list[dict[str, Any]],
    context: dict[str, Any],
) -> list[str]:
    """Render one server section, or the empty slot for a model section."""
    if section.mode == "model":
        return render_slot(section).split("\n")
    if section.id == "mitre_attack":
        return _render_mitre(context["mitre"])
    if section.id == "timeline":
        return _render_timeline(context["timeline"])
    if section.id == "iocs":
        return _render_iocs(context["iocs"])
    if section.id == "accounts_systems":
        return _render_hosts_accounts(context["inventory"])
    if section.id == "provenance":
        return _render_provenance(context["provenance"], hits)
    return [f"_(no renderer registered for section `{section.id}`)_"]


def build_context(
    hits: list[dict[str, Any]],
    job_id: str = "",
    evidence_path: str = "",
    min_severity: str = "high",
    timeline_max_rows: int = 200,
) -> dict[str, Any]:
    """Run every deterministic builder once; both renderers consume the result."""
    return {
        "mitre": build_mitre_rows(hits),
        "timeline": build_timeline(hits, min_severity=min_severity, max_rows=timeline_max_rows),
        "iocs": build_iocs(hits),
        "inventory": build_hosts_accounts(hits),
        "provenance": build_provenance_block(job_id, evidence_path),
    }


def render_report_markdown(
    hits: list[dict[str, Any]],
    job_id: str = "",
    evidence_path: str = "",
    context: dict[str, Any] | None = None,
) -> str:
    """Render the incident report skeleton: server sections filled, model sections slotted."""
    ctx = context if context is not None else build_context(hits, job_id, evidence_path)

    lines = [
        "# Incident Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Report generated (UTC) | {_utc_now()} |",
        f"| Evidence | {_md_escape(evidence_path) or '—'} |",
        f"| Hunt job | {_md_escape(job_id) or '—'} |",
        f"| Total detections | {len(hits)} |",
        f"| Report spec | ChainsawMCP v{SPEC_VERSION} |",
        "",
        "> Sections 2, 3, 4, 5, and 9 are rendered deterministically by ChainsawMCP from the "
        "hash-verified hunt output and are identical regardless of which model is used. "
        "Sections 1, 6, 7, and 8 are written by the analysis model into the marked slots.",
        "",
        "---",
        "",
    ]

    for section in SECTIONS:
        lines.append(section.heading)
        lines.append("")
        lines += render_section_body(section, hits, ctx)
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def build_report_json(
    hits: list[dict[str, Any]],
    job_id: str = "",
    evidence_path: str = "",
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Structured sidecar carrying the same facts as the rendered Markdown."""
    ctx = context if context is not None else build_context(hits, job_id, evidence_path)

    cited: set[str] = set()
    for row in ctx["mitre"]["techniques"]:
        cited.update(row["hit_ids"])
    for row in ctx["timeline"]["rows"]:
        if row["hit_id"]:
            cited.add(row["hit_id"])
    for block in ctx["iocs"]["categories"].values():
        for entry in block["entries"]:
            cited.update(entry["hit_ids"])
    for group in ("hosts", "accounts"):
        for entry in ctx["inventory"][group]:
            cited.update(entry["hit_ids"])

    return {
        "spec_version": SPEC_VERSION,
        "generated": _utc_now(),
        "job_id": job_id,
        "evidence": evidence_path,
        "total_hits": len(hits),
        "sections": [
            {"id": s.id, "number": s.number, "title": s.title, "mode": s.mode}
            for s in SECTIONS
        ],
        "mitre": ctx["mitre"],
        "timeline": ctx["timeline"],
        "iocs": ctx["iocs"],
        "inventory": ctx["inventory"],
        "provenance": ctx["provenance"],
        "cited_hit_ids": sorted(cited),
    }


def write_incident_report(
    hits: list[dict[str, Any]],
    output_dir: Path,
    job_id: str = "",
    evidence_path: str = "",
    min_severity: str = "high",
    timeline_max_rows: int = 200,
) -> tuple[Path, Path]:
    """Write incident_report.md and incident_report.json. Returns both paths.

    Both filenames are fixed constants and *output_dir* comes from get_output_dir() —
    operator configuration, the same shape as an --output-dir flag — so no value that
    arrived over MCP participates in either path.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    context = build_context(
        hits,
        job_id=job_id,
        evidence_path=evidence_path,
        min_severity=min_severity,
        timeline_max_rows=timeline_max_rows,
    )

    md_path = output_dir / "incident_report.md"
    md_path.write_text(
        render_report_markdown(hits, job_id, evidence_path, context=context),
        encoding="utf-8",
    )

    json_path = output_dir / "incident_report.json"
    json_path.write_text(
        json.dumps(
            build_report_json(hits, job_id, evidence_path, context=context),
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    return md_path, json_path
