"""Tests for ChainsawMCP components."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chainsawmcp.chainsaw import ChainsawError, HuntResult, _parse_output, run_hunt
from chainsawmcp.config import get_batch_size, get_ollama_base_url, get_ollama_model
from chainsawmcp.evidence import (
    EvidenceError,
    PreparedEvidence,
    _extract_e01_rootless,
    _prepare_evtx_dir,
    _prepare_e01_linux,
)
from chainsawmcp.report import (
    format_full_report,
    format_summary,
    get_detections,
    _group_by_rule,
    _extract_severity,
    _format_hit,
    _format_event_data,
    _get_event_data,
)


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


def test_prepared_evidence_cleanup_removes_temp_dir(tmp_path):
    """Cleanup must delete the staging temp directory."""
    stage = tmp_path / "evtx"
    stage.mkdir()
    PreparedEvidence(evtx_dir=stage, _temp_dir=tmp_path).cleanup()
    assert not tmp_path.exists()


# ---------------------------------------------------------------------------
# E01 rootless extraction (_extract_e01_rootless)
# ---------------------------------------------------------------------------

def test_extract_e01_rootless_missing_libraries(tmp_path):
    """Should raise ImportError (not EvidenceError) when pytsk3/pyewf are absent."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in ("pyewf", "pytsk3"):
            raise ImportError(f"No module named '{name}'")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        with pytest.raises(ImportError):
            _extract_e01_rootless(tmp_path / "disk.E01", tmp_path / "out")


def test_extract_e01_rootless_no_evtx_raises(tmp_path):
    """Should raise EvidenceError when the image contains no .evtx files."""
    (tmp_path / "out").mkdir()

    # Build minimal mock pytsk3/pyewf objects that report an empty NTFS partition.
    fake_dir = MagicMock()
    fake_dir.__iter__ = MagicMock(return_value=iter([]))

    fake_fs = MagicMock()
    fake_fs.info.ftype = 0x400000  # TSK_FS_TYPE_NTFS
    fake_fs.open_dir.return_value = fake_dir

    fake_part = MagicMock()
    fake_part.len = 1_000_000
    fake_part.start = 2048

    fake_volume = MagicMock()
    fake_volume.__iter__ = MagicMock(return_value=iter([fake_part]))

    class _FakeImgInfo:
        def __init__(self, url: str = "") -> None:
            pass

    fake_pytsk3 = MagicMock()
    fake_pytsk3.TSK_FS_TYPE_NTFS = 0x400000
    fake_pytsk3.TSK_FS_TYPE_NTFS_DETECT = 0x400000
    fake_pytsk3.TSK_FS_META_TYPE_DIR = 2
    fake_pytsk3.Img_Info = _FakeImgInfo
    fake_pytsk3.Volume_Info.return_value = fake_volume
    fake_pytsk3.FS_Info.return_value = fake_fs

    fake_ewf_handle = MagicMock()
    fake_pyewf = MagicMock()
    fake_pyewf.glob.return_value = [str(tmp_path / "disk.E01")]
    fake_pyewf.open.return_value = fake_ewf_handle

    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "pyewf":
            return fake_pyewf
        if name == "pytsk3":
            return fake_pytsk3
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        with pytest.raises(EvidenceError, match="No .evtx files"):
            _extract_e01_rootless(tmp_path / "disk.E01", tmp_path / "out")


# ---------------------------------------------------------------------------
# _prepare_e01_linux
# ---------------------------------------------------------------------------

def test_prepare_e01_linux_happy_path(tmp_path):
    """Delegates to _extract_e01_rootless and returns PreparedEvidence with temp dir."""
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"")

    with patch("chainsawmcp.evidence._extract_e01_rootless") as mock_rootless:
        result = _prepare_e01_linux(e01)

    mock_rootless.assert_called_once()
    assert result.evtx_dir.name == "evtx"
    assert result._temp_dir is not None


def test_prepare_e01_linux_cleans_up_on_failure(tmp_path):
    """If rootless extraction fails, the temp directory must be removed."""
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"")

    import tempfile as _tempfile

    created_tmp: list[Path] = []
    real_mkdtemp = _tempfile.mkdtemp

    def capturing_mkdtemp(**kwargs):
        p = real_mkdtemp(**kwargs)
        created_tmp.append(Path(p))
        return p

    with patch("chainsawmcp.evidence._extract_e01_rootless", side_effect=EvidenceError("bad image")):
        with patch("chainsawmcp.evidence.tempfile.mkdtemp", side_effect=capturing_mkdtemp):
            with pytest.raises(EvidenceError, match="bad image"):
                _prepare_e01_linux(e01)

    assert created_tmp, "mkdtemp was never called"
    for p in created_tmp:
        assert not p.exists(), f"Stale temp dir not cleaned up: {p}"


def test_prepare_e01_linux_propagates_errors(tmp_path):
    """Any exception from rootless extraction propagates unchanged."""
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"")

    with patch("chainsawmcp.evidence._extract_e01_rootless", side_effect=EvidenceError("corrupt")):
        with pytest.raises(EvidenceError, match="corrupt"):
            _prepare_e01_linux(e01)


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


def test_format_full_report_structure():
    hits = [
        {"name": "Mimikatz", "level": "high", "timestamp": "2024-01-01T00:00:00Z"},
        {"name": "Mimikatz", "level": "high", "timestamp": "2024-01-01T00:01:00Z"},
        {"name": "PSExec",   "level": "medium", "timestamp": "2024-01-01T00:02:00Z"},
    ]
    report = format_full_report(hits, evtx_path="/evidence/Security.evtx")
    assert "ChainsawMCP" in report
    assert "Mimikatz" in report
    assert "PSExec" in report
    assert "Total hits: 3" in report
    assert "Rules hit : 2" in report


def test_format_full_report_empty():
    report = format_full_report([], evtx_path="/empty")
    assert "No detections found" in report


def test_format_full_report_caps_sample_events():
    hits = [{"name": "Noisy", "level": "low", "timestamp": f"t{i}"} for i in range(10)]
    report = format_full_report(hits, evtx_path="/evidence")
    assert "and 5 more event(s)" in report


def test_format_summary_is_compact():
    hits = [
        {"name": "Mimikatz", "level": "critical"},
        {"name": "PSExec", "level": "high"},
    ]
    summary = format_summary(hits, evtx_path="/evidence")
    assert "HUNT SUMMARY" in summary
    assert "Mimikatz" in summary
    assert "critical" in summary
    # should NOT contain full event detail lines
    assert "EventID=" not in summary


def test_get_detections_filter_by_rule():
    hits = [
        {"name": "Mimikatz", "level": "critical"},
        {"name": "PSExec", "level": "high"},
        {"name": "Mimikatz Variant", "level": "high"},
    ]
    result = get_detections(hits, rule="mimikatz")
    assert "Mimikatz" in result
    assert "PSExec" not in result


def test_get_detections_filter_by_severity():
    hits = [
        {"name": "RuleA", "level": "critical"},
        {"name": "RuleB", "level": "high"},
        {"name": "RuleC", "level": "critical"},
    ]
    result = get_detections(hits, severity="critical")
    assert "RuleA" in result
    assert "RuleC" in result
    assert "RuleB" not in result


def test_get_detections_limit():
    hits = [{"name": f"Rule{i}", "level": "high"} for i in range(50)]
    result = get_detections(hits, limit=10)
    assert "40 more hit(s)" in result


def test_get_detections_no_match():
    hits = [{"name": "Mimikatz", "level": "high"}]
    result = get_detections(hits, rule="nonexistent")
    assert "No hits matched" in result


# ---------------------------------------------------------------------------
# Event field extraction (Chainsaw JSON structure)
# ---------------------------------------------------------------------------

# Minimal hit in the shape Chainsaw actually emits: document.data.Event
_RDP_HIT = {
    "name": "Remote Interactive Logon",
    "level": "critical",
    "timestamp": "2018-08-31T12:34:56.000Z",
    "document": {
        "data": {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "Computer": "DC01.corp.local",
                    "TimeCreated": {"SystemTime": "2018-08-31T12:34:56.000Z"},
                },
                "EventData": {
                    "TargetUserName": "Administrator",
                    "TargetDomainName": "CORP",
                    "IpAddress": "10.10.10.50",
                    "WorkstationName": "ATTACKER-PC",
                    "LogonType": 10,
                },
            }
        }
    },
}


def test_format_hit_extracts_eventid_and_computer():
    line = _format_hit(_RDP_HIT)
    assert "EventID=4624" in line
    assert "Computer=DC01.corp.local" in line
    assert "2018-08-31" in line


def test_format_hit_uses_toplevel_timestamp():
    """Top-level timestamp must be preferred over nested TimeCreated."""
    hit = dict(_RDP_HIT)
    hit["timestamp"] = "2018-09-05T08:00:00.000Z"
    line = _format_hit(hit)
    assert "2018-09-05" in line


def test_get_event_data_flat():
    ed = _get_event_data(_RDP_HIT)
    assert ed["TargetUserName"] == "Administrator"
    assert ed["IpAddress"] == "10.10.10.50"
    assert ed["LogonType"] == 10


def test_get_event_data_list_format():
    """EventData.Data as a list of {#attributes: {Name:...}, #text:...} objects."""
    hit = {
        "document": {
            "data": {
                "Event": {
                    "System": {},
                    "EventData": {
                        "Data": [
                            {"#attributes": {"Name": "TargetUserName"}, "#text": "jdoe"},
                            {"#attributes": {"Name": "IpAddress"}, "#text": "192.168.1.1"},
                        ]
                    },
                }
            }
        }
    }
    ed = _get_event_data(hit)
    assert ed["TargetUserName"] == "jdoe"
    assert ed["IpAddress"] == "192.168.1.1"


def test_format_event_data_shows_priority_fields():
    line = _format_event_data(_RDP_HIT)
    assert "User=CORP\\Administrator" in line
    assert "IpAddress=10.10.10.50" in line
    assert "WorkstationName=ATTACKER-PC" in line


def test_format_event_data_suppresses_dashes():
    """Fields with value '-' (Chainsaw's null sentinel) must be omitted."""
    hit = {
        "document": {
            "data": {
                "Event": {
                    "System": {},
                    "EventData": {"IpAddress": "-", "TargetUserName": "jdoe"},
                }
            }
        }
    }
    line = _format_event_data(hit)
    assert "IpAddress" not in line
    assert "User=jdoe" in line


def test_get_detections_shows_event_data():
    result = get_detections([_RDP_HIT])
    assert "User=CORP\\Administrator" in result
    assert "IpAddress=10.10.10.50" in result


# ---------------------------------------------------------------------------
# run_hunt (mocked subprocess)
# ---------------------------------------------------------------------------

def test_run_hunt_sigma_without_mapping_raises(tmp_path):
    with pytest.raises(ChainsawError, match="mapping file is required"):
        run_hunt(tmp_path, sigma_path=Path("/sigma/rules"))


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

    def _fake_run(cmd, stdout, **kwargs):
        stdout.write(json.dumps(hits))
        mock = MagicMock()
        mock.returncode = 0
        mock.stderr = ""
        return mock

    with patch("chainsawmcp.chainsaw.subprocess.run", side_effect=_fake_run):
        with patch("chainsawmcp.chainsaw.get_output_dir", return_value=tmp_path):
            result = run_hunt(tmp_path)

    assert isinstance(result, HuntResult)
    assert result.hits == hits
    assert result.output_file is not None
