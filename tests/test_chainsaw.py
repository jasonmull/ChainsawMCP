"""Tests for ChainsawMCP components."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chainsawmcp.chainsaw import ChainsawError, _parse_output, run_hunt
from chainsawmcp.config import get_batch_size, get_ollama_base_url, get_ollama_model
from chainsawmcp.evidence import EvidenceError, PreparedEvidence, _prepare_evtx_dir
from chainsawmcp.report import format_report, _group_by_rule, _extract_severity


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
    assert _parse_output(json.dumps(hits)) == hits


def test_parse_ndjson():
    lines = [json.dumps({"name": "Rule A"}), json.dumps({"name": "Rule B"})]
    result = _parse_output("\n".join(lines))
    assert len(result) == 2
    assert result[0]["name"] == "Rule A"


def test_parse_empty():
    assert _parse_output("") == []
    assert _parse_output("   ") == []


def test_parse_skips_non_json_lines():
    raw = "Progress: scanning...\n" + json.dumps({"name": "Rule A"})
    assert len(_parse_output(raw)) == 1


def test_parse_nested_array_in_ndjson():
    result = _parse_output(json.dumps([{"name": "A"}, {"name": "B"}]))
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Evidence preparation
# ---------------------------------------------------------------------------

def test_prepare_evtx_dir_valid(tmp_path):
    (tmp_path / "Security.evtx").write_bytes(b"\x00" * 8)
    ev = _prepare_evtx_dir(tmp_path)
    assert ev.evtx_dir == tmp_path


def test_prepare_evtx_dir_empty(tmp_path):
    with pytest.raises(EvidenceError, match="No .evtx files"):
        _prepare_evtx_dir(tmp_path)


def test_prepare_evidence_nonexistent():
    from chainsawmcp.evidence import prepare_evidence
    with pytest.raises(EvidenceError, match="does not exist"):
        prepare_evidence("/nonexistent/path/evidence")


def test_prepare_evidence_unknown_extension(tmp_path):
    from chainsawmcp.evidence import prepare_evidence
    f = tmp_path / "image.vmdk"
    f.write_bytes(b"")
    with pytest.raises(EvidenceError, match="Unrecognised"):
        prepare_evidence(str(f))


def test_prepared_evidence_cleanup_noop():
    PreparedEvidence(evtx_dir=Path("/tmp")).cleanup()


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def test_group_by_rule():
    hits = [
        {"name": "Mimikatz"},
        {"name": "Mimikatz"},
        {"name": "PSExec"},
    ]
    groups = _group_by_rule(hits)
    assert len(groups) == 2
    assert len(groups["Mimikatz"]) == 2


def test_group_by_rule_fallback():
    hits = [{"document": {"name": "Fallback Rule"}}]
    groups = _group_by_rule(hits)
    assert "Fallback Rule" in groups


def test_extract_severity():
    assert _extract_severity({"level": "high"}) == "high"
    assert _extract_severity({"severity": "medium"}) == "medium"
    assert _extract_severity({}) == "unknown"


def test_format_report_structure():
    hits = [
        {"name": "Mimikatz", "level": "high", "timestamp": "2024-01-01T00:00:00Z"},
        {"name": "Mimikatz", "level": "high", "timestamp": "2024-01-01T00:01:00Z"},
        {"name": "PSExec",   "level": "medium", "timestamp": "2024-01-01T00:02:00Z"},
    ]
    report = format_report(hits, evtx_path="/evidence/Security.evtx")
    assert "ChainsawMCP" in report
    assert "Mimikatz" in report
    assert "PSExec" in report
    assert "Total hits: 3" in report
    assert "Rules hit : 2" in report


def test_format_report_empty():
    report = format_report([], evtx_path="/empty")
    assert "No detections found" in report


def test_format_report_caps_sample_events():
    hits = [{"name": "Noisy", "level": "low", "timestamp": f"t{i}"} for i in range(10)]
    report = format_report(hits, evtx_path="/evidence")
    assert "and 5 more event(s)" in report


# ---------------------------------------------------------------------------
# run_hunt (mocked subprocess)
# ---------------------------------------------------------------------------

def test_run_hunt_binary_not_found(tmp_path):
    with patch("chainsawmcp.chainsaw.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(ChainsawError, match="not found"):
            run_hunt(tmp_path)


def test_run_hunt_nonzero_exit(tmp_path):
    mock = MagicMock()
    mock.returncode = 1
    mock.stderr = "some error"
    with patch("chainsawmcp.chainsaw.subprocess.run", return_value=mock):
        with pytest.raises(ChainsawError, match="exited with code 1"):
            run_hunt(tmp_path)


def test_run_hunt_success(tmp_path):
    hits = [{"name": "Test Rule"}]
    mock = MagicMock()
    mock.returncode = 0
    mock.stdout = json.dumps(hits)
    with patch("chainsawmcp.chainsaw.subprocess.run", return_value=mock):
        assert run_hunt(tmp_path) == hits
