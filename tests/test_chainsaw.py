"""Tests for Chainsaw MCP components."""

import json
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chainsaw_mcp.chainsaw import ChainsawError, _parse_output, run_hunt
from chainsaw_mcp.config import get_batch_size, get_ollama_base_url, get_ollama_model
from chainsaw_mcp.enrichment import (
    EnrichmentError,
    _chunks,
    _confidence_tier,
    _group_by_rule,
    _rule_key,
    enrich_hits,
)
from chainsaw_mcp.evidence import EvidenceError, PreparedEvidence, _prepare_evtx_dir
from chainsaw_mcp.report import format_report


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def test_defaults(monkeypatch):
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    monkeypatch.delenv("ENRICHMENT_BATCH_SIZE", raising=False)
    assert get_ollama_base_url() == "http://localhost:11434"
    assert get_ollama_model() == "foundationsec:8b"
    assert get_batch_size() == 20


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://gpu-box:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "llama3:8b")
    monkeypatch.setenv("ENRICHMENT_BATCH_SIZE", "5")
    assert get_ollama_base_url() == "http://gpu-box:11434"
    assert get_ollama_model() == "llama3:8b"
    assert get_batch_size() == 5


# ---------------------------------------------------------------------------
# Chainsaw output parsing
# ---------------------------------------------------------------------------

def test_parse_json_array():
    hits = [{"name": "Mimikatz", "timestamp": "2024-01-01T00:00:00Z"}]
    result = _parse_output(json.dumps(hits))
    assert result == hits


def test_parse_ndjson():
    lines = [
        json.dumps({"name": "Rule A"}),
        json.dumps({"name": "Rule B"}),
    ]
    result = _parse_output("\n".join(lines))
    assert len(result) == 2
    assert result[0]["name"] == "Rule A"


def test_parse_empty():
    assert _parse_output("") == []
    assert _parse_output("   ") == []


def test_parse_skips_non_json_lines():
    raw = "Progress: scanning...\n" + json.dumps({"name": "Rule A"})
    result = _parse_output(raw)
    assert len(result) == 1


def test_parse_nested_array_in_ndjson():
    inner = [{"name": "A"}, {"name": "B"}]
    result = _parse_output(json.dumps(inner))
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Evidence preparation
# ---------------------------------------------------------------------------

def test_prepare_evtx_dir_valid(tmp_path):
    evtx_file = tmp_path / "Security.evtx"
    evtx_file.write_bytes(b"\x00" * 8)
    ev = _prepare_evtx_dir(tmp_path)
    assert ev.evtx_dir == tmp_path


def test_prepare_evtx_dir_empty(tmp_path):
    with pytest.raises(EvidenceError, match="No .evtx files"):
        _prepare_evtx_dir(tmp_path)


def test_prepare_evidence_nonexistent():
    from chainsaw_mcp.evidence import prepare_evidence
    with pytest.raises(EvidenceError, match="does not exist"):
        prepare_evidence("/nonexistent/path/evidence")


def test_prepare_evidence_unknown_extension(tmp_path):
    from chainsaw_mcp.evidence import prepare_evidence
    f = tmp_path / "image.vmdk"
    f.write_bytes(b"")
    with pytest.raises(EvidenceError, match="Unrecognised"):
        prepare_evidence(str(f))


def test_prepared_evidence_cleanup_noop():
    ev = PreparedEvidence(evtx_dir=Path("/tmp"))
    ev.cleanup()  # Should not raise


# ---------------------------------------------------------------------------
# Enrichment helpers
# ---------------------------------------------------------------------------

def test_group_by_rule():
    hits = [
        {"name": "Mimikatz", "tactic": "credential-access"},
        {"name": "Mimikatz", "tactic": "credential-access"},
        {"name": "PSExec", "tactic": "lateral-movement"},
    ]
    groups = _group_by_rule(hits)
    assert len(groups) == 2
    assert sum(len(v) for v in groups.values()) == 3


def test_rule_key_fallback():
    assert _rule_key({}) == "Unknown Rule"
    assert _rule_key({"name": "Mimikatz"}) == "Mimikatz"
    assert _rule_key({"name": "X", "tactic": "cred"}) == "X [cred]"


def test_confidence_tier():
    assert _confidence_tier(10) == "HIGH"
    assert _confidence_tier(3) == "MEDIUM"
    assert _confidence_tier(1) == "LOW"


def test_chunks():
    items = list(range(7))
    result = list(_chunks(items, 3))
    assert result == [[0, 1, 2], [3, 4, 5], [6]]


@pytest.mark.asyncio
async def test_enrich_hits_low_severity_no_llm():
    hits = [{"name": "Noisy Rule", "level": "low", "timestamp": "t"}]
    with patch("chainsaw_mcp.enrichment._chat", new_callable=AsyncMock) as mock_chat:
        mock_chat.return_value = "narrative"
        result = await enrich_hits(hits)
    # LOW severity should be templated — LLM should not be called for the batch
    # (only the rollup calls LLM)
    assert len(result.batches) == 1
    assert result.batches[0].confidence == "LOW"
    assert "LOW severity" in result.batches[0].narrative


@pytest.mark.asyncio
async def test_enrich_hits_medium_calls_llm():
    hits = [
        {"name": "Mimikatz", "level": "high", "timestamp": f"t{i}"}
        for i in range(3)
    ]
    with patch("chainsaw_mcp.enrichment._chat", new_callable=AsyncMock) as mock_chat:
        mock_chat.return_value = "LLM narrative"
        result = await enrich_hits(hits, batch_size=20)

    assert len(result.batches) == 1
    assert result.batches[0].confidence == "MEDIUM"
    assert result.batches[0].narrative == "LLM narrative"


@pytest.mark.asyncio
async def test_enrich_empty_hits():
    result = await enrich_hits([])
    assert result.batches == []
    assert "No findings" in result.rollup


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def test_format_report_structure():
    from chainsaw_mcp.enrichment import EnrichedBatch, EnrichmentResult

    batches = [
        EnrichedBatch(
            rule_key="Mimikatz [credential-access]",
            hits=[{"name": "Mimikatz", "document": {}}],
            narrative="Credential dumping detected.",
            confidence="HIGH",
        )
    ]
    result = EnrichmentResult(batches=batches, rollup="Attacker used Mimikatz.")
    report = format_report(result, evtx_path="/evidence/Security.evtx", total_hits=1)

    assert "CHAINSAW MCP" in report
    assert "Attacker used Mimikatz." in report
    assert "Mimikatz" in report
    assert "HIGH" in report
    assert "Credential dumping detected." in report


def test_format_report_empty():
    from chainsaw_mcp.enrichment import EnrichmentResult
    result = EnrichmentResult(batches=[], rollup="No findings.")
    report = format_report(result, evtx_path="/empty", total_hits=0)
    assert "No findings." in report


# ---------------------------------------------------------------------------
# run_hunt integration (mocked subprocess)
# ---------------------------------------------------------------------------

def test_run_hunt_binary_not_found(tmp_path):
    with patch("chainsaw_mcp.chainsaw.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(ChainsawError, match="not found"):
            run_hunt(tmp_path)


def test_run_hunt_nonzero_exit(tmp_path):
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "some error"
    with patch("chainsaw_mcp.chainsaw.subprocess.run", return_value=mock_result):
        with pytest.raises(ChainsawError, match="exited with code 1"):
            run_hunt(tmp_path)


def test_run_hunt_success(tmp_path):
    hits = [{"name": "Test Rule"}]
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps(hits)
    with patch("chainsaw_mcp.chainsaw.subprocess.run", return_value=mock_result):
        result = run_hunt(tmp_path)
    assert result == hits
