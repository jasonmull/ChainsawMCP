"""LLM enrichment with batching and confidence tiering."""

import json
from typing import Any

import httpx

from .config import get_batch_size, get_ollama_base_url, get_ollama_model

# Hits with fewer corroborating events get lower confidence
_HIGH_HIT_THRESHOLD = 5
_MEDIUM_HIT_THRESHOLD = 2

# Severity values Chainsaw may emit (case-insensitive comparison used below)
_LOW_SEVERITIES = {"low", "informational", "info"}

_LOW_TEMPLATE = (
    "LOW severity finding: {rule_name}. "
    "This rule triggers frequently and may represent expected behaviour. "
    "Review the raw events for confirmation before escalating."
)


class EnrichmentError(Exception):
    pass


class EnrichedBatch:
    def __init__(self, rule_key: str, hits: list[dict], narrative: str, confidence: str):
        self.rule_key = rule_key
        self.hits = hits
        self.narrative = narrative
        self.confidence = confidence


class EnrichmentResult:
    def __init__(self, batches: list[EnrichedBatch], rollup: str):
        self.batches = batches
        self.rollup = rollup


async def enrich_hits(hits: list[dict[str, Any]], batch_size: int | None = None) -> EnrichmentResult:
    """Batch hits by rule/tactic, enrich each batch, then synthesise a rollup."""
    size = batch_size or get_batch_size()
    grouped = _group_by_rule(hits)

    batches: list[EnrichedBatch] = []
    for rule_key, rule_hits in grouped.items():
        severity = _extract_severity(rule_hits[0])
        if severity.lower() in _LOW_SEVERITIES:
            narrative = _LOW_TEMPLATE.format(rule_name=rule_key)
            batches.append(EnrichedBatch(rule_key, rule_hits, narrative, "LOW"))
            continue

        for chunk in _chunks(rule_hits, size):
            confidence = _confidence_tier(len(chunk))
            narrative = await _llm_enrich_batch(rule_key, chunk)
            batches.append(EnrichedBatch(rule_key, chunk, narrative, confidence))

    rollup = await _llm_rollup(batches) if batches else "No findings to analyse."
    return EnrichmentResult(batches=batches, rollup=rollup)


# ---------------------------------------------------------------------------
# Grouping helpers
# ---------------------------------------------------------------------------

def _group_by_rule(hits: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for hit in hits:
        key = _rule_key(hit)
        groups.setdefault(key, []).append(hit)
    return groups


def _rule_key(hit: dict) -> str:
    # Chainsaw JSON structure varies slightly by version; be defensive
    name = (
        hit.get("name")
        or hit.get("rule_name")
        or hit.get("title")
        or hit.get("document", {}).get("name", "Unknown Rule")
    )
    tactic = (
        hit.get("tactic")
        or hit.get("tags", [""])[0]
        or ""
    )
    return f"{name} [{tactic}]" if tactic else str(name)


def _extract_severity(hit: dict) -> str:
    return (
        hit.get("level")
        or hit.get("severity")
        or hit.get("document", {}).get("level", "medium")
    )


def _confidence_tier(hit_count: int) -> str:
    if hit_count >= _HIGH_HIT_THRESHOLD:
        return "HIGH"
    if hit_count >= _MEDIUM_HIT_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def _chunks(lst: list, n: int):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


# ---------------------------------------------------------------------------
# LLM calls
# ---------------------------------------------------------------------------

async def _llm_enrich_batch(rule_key: str, hits: list[dict]) -> str:
    payload = _summarise_hits(hits)
    prompt = (
        f"You are a threat analyst reviewing Windows Event Log findings from Chainsaw.\n\n"
        f"Rule / Tactic: {rule_key}\n"
        f"Hit count: {len(hits)}\n\n"
        f"Event summary:\n{payload}\n\n"
        "Provide:\n"
        "1. A plain-English explanation of what this activity indicates.\n"
        "2. Severity assessment with reasoning.\n"
        "3. Recommended analyst next steps.\n"
        "4. Flag any uncertainty — never invent context not present in the data.\n"
        "Be concise. Output as prose, not bullet points."
    )
    return await _chat(prompt)


async def _llm_rollup(batches: list[EnrichedBatch]) -> str:
    summaries = "\n\n".join(
        f"--- {b.rule_key} (confidence: {b.confidence}) ---\n{b.narrative}"
        for b in batches
    )
    prompt = (
        "You are a senior threat analyst. Below are per-rule enrichments from a Chainsaw hunt.\n\n"
        f"{summaries}\n\n"
        "Synthesise these findings into a coherent overall incident narrative:\n"
        "- What is the most likely attacker goal or technique?\n"
        "- Which findings corroborate each other?\n"
        "- What should the analyst investigate first?\n"
        "- Where is there genuine uncertainty?\n"
        "Keep it under 400 words. Never invent context not in the data."
    )
    return await _chat(prompt)


def _summarise_hits(hits: list[dict]) -> str:
    """Extract key fields from hits into a compact text block for the LLM."""
    lines = []
    for i, hit in enumerate(hits, 1):
        doc = hit.get("document", hit)
        ts = doc.get("System", {}).get("TimeCreated", {}).get("@SystemTime") or hit.get("timestamp", "?")
        event_id = doc.get("System", {}).get("EventID", {})
        if isinstance(event_id, dict):
            event_id = event_id.get("#text", "?")
        user = (
            doc.get("System", {}).get("Security", {}).get("@UserID")
            or doc.get("UserData", {}).get("user", "?")
        )
        computer = doc.get("System", {}).get("Computer", "?")
        data = doc.get("EventData", {})
        lines.append(
            f"[{i}] ts={ts} EventID={event_id} Computer={computer} User={user} data={json.dumps(data, default=str)[:300]}"
        )
    return "\n".join(lines)


async def _chat(prompt: str) -> str:
    url = f"{get_ollama_base_url()}/v1/chat/completions"
    body = {
        "model": get_ollama_model(),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
    }
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()
    except httpx.ConnectError as e:
        raise EnrichmentError(
            f"Cannot reach Ollama at {get_ollama_base_url()}. "
            "Check OLLAMA_BASE_URL and that Ollama is running."
        ) from e
    except httpx.HTTPStatusError as e:
        raise EnrichmentError(f"Ollama API error {e.response.status_code}: {e.response.text}") from e
    except (KeyError, IndexError) as e:
        raise EnrichmentError(f"Unexpected Ollama response structure: {e}") from e
