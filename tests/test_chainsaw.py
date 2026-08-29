"""Tests for ChainsawMCP components."""

import json
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chainsawmcp import server
from chainsawmcp.chainsaw import ChainsawError, HuntResult, _parse_output, run_hunt
from chainsawmcp.config import (
    get_batch_size,
    get_ollama_base_url,
    get_ollama_model,
)
from chainsawmcp.jobs import (
    create_job,
    log_path,
    provenance_path,
    read_job,
    read_provenance,
    results_path,
)
from chainsawmcp.evidence import (
    EvidenceError,
    PreparedEvidence,
    _extract_e01,
    _extract_e01_rootless,
    _extract_e01_via_tsk_cli,
    _ntfs_offset_via_mmls,
    _prepare_evtx_dir,
    _prepare_e01_linux,
)
from chainsawmcp.report import (
    format_full_report,
    format_summary,
    get_detections,
    get_detections_json,
    resolve_hit_ids,
    write_full_report,
    _group_by_rule,
    _extract_severity,
    _format_hit,
    _format_event_data,
    _get_event_data,
    _hit_to_dict,
)
from chainsawmcp.report_markdown import (
    build_hosts_accounts,
    build_iocs,
    build_mitre_rows,
    build_provenance_block,
    build_report_json,
    build_timeline,
    render_report_markdown,
    write_incident_report,
)
from chainsawmcp.report_spec import (
    MODEL_SECTIONS,
    SECTIONS,
    SERVER_SECTIONS,
    render_spec_text,
    slot_begin,
    slot_end,
    slot_placeholder,
)
from chainsawmcp.report_validate import validate_report_text
from chainsawmcp.monitor import _annotate_results, _extract_record_id, _event_block


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
        if name == "pytsk3":
            raise ImportError("No module named 'pytsk3'")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        with pytest.raises(ImportError):
            _extract_e01_rootless(tmp_path / "disk.E01", tmp_path / "out")


def test_extract_e01_rootless_no_evtx_raises(tmp_path):
    """Should raise EvidenceError when the image contains no .evtx files."""
    (tmp_path / "out").mkdir()

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

    fake_pytsk3 = MagicMock()
    fake_pytsk3.TSK_FS_TYPE_NTFS = 0x400000
    fake_pytsk3.TSK_FS_TYPE_NTFS_DETECT = 0x400000
    fake_pytsk3.TSK_FS_META_TYPE_DIR = 2
    fake_pytsk3.Img_Info.return_value = MagicMock()
    fake_pytsk3.Volume_Info.return_value = fake_volume
    fake_pytsk3.FS_Info.return_value = fake_fs

    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
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
    """If all extraction methods fail, the temp directory must be removed."""
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"")

    import tempfile as _tempfile

    created_tmp: list[Path] = []
    real_mkdtemp = _tempfile.mkdtemp

    def capturing_mkdtemp(**kwargs):
        p = real_mkdtemp(**kwargs)
        created_tmp.append(Path(p))
        return p

    with patch("chainsawmcp.evidence._extract_e01", side_effect=EvidenceError("bad image")):
        with patch("chainsawmcp.evidence.tempfile.mkdtemp", side_effect=capturing_mkdtemp):
            with pytest.raises(EvidenceError, match="bad image"):
                _prepare_e01_linux(e01)

    assert created_tmp, "mkdtemp was never called"
    for p in created_tmp:
        assert not p.exists(), f"Stale temp dir not cleaned up: {p}"


# ---------------------------------------------------------------------------
# _extract_e01 fallback chain
# ---------------------------------------------------------------------------

def test_extract_e01_uses_pytsk3_when_available(tmp_path):
    """Should use pytsk3 path when it succeeds."""
    dest = tmp_path / "out"
    dest.mkdir()
    with patch("chainsawmcp.evidence._extract_e01_rootless") as mock_rootless:
        _extract_e01(tmp_path / "disk.E01", dest)
    mock_rootless.assert_called_once()


def test_extract_e01_falls_back_to_cli_on_import_error(tmp_path):
    """ImportError from pytsk3 should trigger CLI fallback."""
    dest = tmp_path / "out"
    dest.mkdir()
    with patch("chainsawmcp.evidence._extract_e01_rootless", side_effect=ImportError("no pytsk3")):
        with patch("chainsawmcp.evidence.shutil.which", return_value="/usr/bin/fls"):
            with patch("chainsawmcp.evidence._extract_e01_via_tsk_cli") as mock_cli:
                _extract_e01(tmp_path / "disk.E01", dest)
    mock_cli.assert_called_once()


def test_extract_e01_falls_back_to_cli_on_evidence_error(tmp_path):
    """EvidenceError (e.g. EWF not in libtsk) should also trigger CLI fallback."""
    dest = tmp_path / "out"
    dest.mkdir()
    with patch("chainsawmcp.evidence._extract_e01_rootless", side_effect=EvidenceError("EWF not supported")):
        with patch("chainsawmcp.evidence.shutil.which", return_value="/usr/bin/fls"):
            with patch("chainsawmcp.evidence._extract_e01_via_tsk_cli") as mock_cli:
                _extract_e01(tmp_path / "disk.E01", dest)
    mock_cli.assert_called_once()


def test_extract_e01_raises_when_all_methods_unavailable(tmp_path):
    """Should raise EvidenceError with helpful message when pytsk3 and CLI both unavailable."""
    dest = tmp_path / "out"
    dest.mkdir()
    with patch("chainsawmcp.evidence._extract_e01_rootless", side_effect=ImportError("no pytsk3")):
        with patch("chainsawmcp.evidence.shutil.which", return_value=None):
            with pytest.raises(EvidenceError, match="apt install sleuthkit"):
                _extract_e01(tmp_path / "disk.E01", dest)


# ---------------------------------------------------------------------------
# _extract_e01_via_tsk_cli
# ---------------------------------------------------------------------------

def test_tsk_cli_extracts_evtx(tmp_path):
    """fls output referencing .evtx files should be extracted via icat."""
    dest = tmp_path / "out"
    dest.mkdir()
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"")

    fls_output = (
        "r/r 12345-128-1:\tWindows/System32/winevt/Logs/Security.evtx\n"
        "r/r 12346-128-1:\tWindows/System32/winevt/Logs/System.evtx\n"
        "d/d 100:\tWindows\n"
    )

    def fake_run(cmd, **kwargs):
        mock = MagicMock()
        if cmd[0] == "fls":
            mock.returncode = 0
            mock.stdout = fls_output
            mock.stderr = ""
        elif cmd[0] == "icat":
            mock.returncode = 0
            mock.stdout = b"\x00ELF_EVTX_FAKE_CONTENT"
        elif cmd[0] == "mmls":
            mock.returncode = 0
            mock.stdout = "000:  -------   0000000000   0000002047   0000002048   Unallocated\n"
            mock.stdout += "001:  000:000   0000002048   0002099199   0002097152   NTFS / exFAT (0x07)\n"
        return mock

    with patch("chainsawmcp.evidence.subprocess.run", side_effect=fake_run):
        with patch("chainsawmcp.evidence.shutil.which", return_value="/usr/bin/mmls"):
            _extract_e01_via_tsk_cli(e01, dest)

    extracted = list(dest.glob("*.evtx"))
    assert len(extracted) == 2


def test_tsk_cli_raises_on_fls_failure(tmp_path):
    """fls non-zero exit should raise EvidenceError."""
    dest = tmp_path / "out"
    dest.mkdir()

    def fake_run(cmd, **kwargs):
        mock = MagicMock()
        if cmd[0] == "fls":
            mock.returncode = 1
            mock.stdout = ""
            mock.stderr = "unable to open image"
        elif cmd[0] == "mmls":
            mock.returncode = 1
            mock.stdout = ""
        return mock

    with patch("chainsawmcp.evidence.subprocess.run", side_effect=fake_run):
        with patch("chainsawmcp.evidence.shutil.which", return_value=None):
            with pytest.raises(EvidenceError, match="fls failed"):
                _extract_e01_via_tsk_cli(tmp_path / "disk.E01", dest)


def test_ntfs_offset_via_mmls_picks_largest(tmp_path):
    """Should return the start sector of the largest NTFS partition."""
    mmls_out = (
        "001:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)\n"
        "002:  000:001   0000206848   0010485759   0010278912   NTFS / exFAT (0x07)\n"
    )
    mock = MagicMock()
    mock.returncode = 0
    mock.stdout = mmls_out
    with patch("chainsawmcp.evidence.shutil.which", return_value="/usr/bin/mmls"):
        with patch("chainsawmcp.evidence.subprocess.run", return_value=mock):
            offset = _ntfs_offset_via_mmls(tmp_path / "disk.E01")
    assert offset == 206848  # start of the larger partition


def test_ntfs_offset_via_mmls_no_mmls(tmp_path):
    """Returns None when mmls is not installed."""
    with patch("chainsawmcp.evidence.shutil.which", return_value=None):
        assert _ntfs_offset_via_mmls(tmp_path / "disk.E01") is None


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
        "path": "C:/Windows/System32/winevt/Logs/Security.evtx",
        "data": {
            "Event": {
                "System": {
                    "EventID": 4624,
                    "EventRecordID": 6677,
                    "Channel": "Security",
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


# ---------------------------------------------------------------------------
# Hit ID injection (chain-of-custody citations)
# ---------------------------------------------------------------------------

def _write_results(tmp_path: Path, records: list) -> Path:
    rf = tmp_path / "hunt_results.json"
    rf.write_text(json.dumps(records), encoding="utf-8")
    return rf


def test_annotate_results_stamps_unique_ids(tmp_path):
    records = [dict(_RDP_HIT), dict(_RDP_HIT), dict(_RDP_HIT)]
    rf = _write_results(tmp_path, records)

    _annotate_results(rf, "job42")

    out = json.loads(rf.read_text(encoding="utf-8"))
    ids = [r["hit_id"] for r in out]
    assert ids == ["job42-000000", "job42-000001", "job42-000002"]
    assert len(set(ids)) == len(ids)  # unique


def test_annotate_results_stamps_intrinsic_fields(tmp_path):
    rf = _write_results(tmp_path, [dict(_RDP_HIT)])

    _annotate_results(rf, "job42")

    rec = json.loads(rf.read_text(encoding="utf-8"))[0]
    assert rec["event_record_id"] == "6677"
    assert rec["source"] == "C:/Windows/System32/winevt/Logs/Security.evtx"
    assert rec["channel"] == "Security"


def test_annotate_results_is_deterministic(tmp_path):
    # Same input + same job_id must always produce the same IDs.
    rf1 = tmp_path / "first.json"
    rf1.write_text(json.dumps([dict(_RDP_HIT), dict(_RDP_HIT)]), encoding="utf-8")
    _annotate_results(rf1, "job42")

    rf2 = tmp_path / "again.json"
    rf2.write_text(json.dumps([dict(_RDP_HIT), dict(_RDP_HIT)]), encoding="utf-8")
    _annotate_results(rf2, "job42")

    ids1 = [r["hit_id"] for r in json.loads(rf1.read_text(encoding="utf-8"))]
    ids2 = [r["hit_id"] for r in json.loads(rf2.read_text(encoding="utf-8"))]
    assert ids1 == ids2


def test_annotate_results_rewrites_valid_json(tmp_path):
    rf = _write_results(tmp_path, [dict(_RDP_HIT)])
    _annotate_results(rf, "job42")
    # Must remain parseable by Chainsaw's own parser.
    assert _parse_output(rf.read_text(encoding="utf-8"))[0]["hit_id"] == "job42-000000"


def test_annotate_results_empty_file_is_noop(tmp_path):
    rf = tmp_path / "hunt_results.json"
    rf.write_text("[]", encoding="utf-8")
    _annotate_results(rf, "job42")  # must not raise
    assert json.loads(rf.read_text(encoding="utf-8")) == []


def test_extract_record_id_defensive():
    assert _extract_record_id({"EventRecordID": 42}) == "42"
    assert _extract_record_id({"EventRecordID": "42"}) == "42"
    assert _extract_record_id({"EventRecordID": {"#text": "42"}}) == "42"
    assert _extract_record_id({"EventRecordID": {"@text": "42"}}) == "42"
    assert _extract_record_id({}) is None
    assert _extract_record_id({"EventRecordID": ""}) is None


def test_event_block_handles_both_shapes():
    # document.data.Event
    assert _event_block(_RDP_HIT)["System"]["EventID"] == 4624
    # document.Event (alternate)
    alt = {"document": {"Event": {"System": {"EventID": 1}}}}
    assert _event_block(alt)["System"]["EventID"] == 1
    # missing document
    assert _event_block({}) == {}


def test_hit_to_dict_surfaces_ids():
    annotated = dict(_RDP_HIT)
    annotated.update({
        "hit_id": "job42-000007",
        "event_record_id": "6677",
        "source": "C:/Windows/System32/winevt/Logs/Security.evtx",
    })
    d = _hit_to_dict(annotated)
    assert d["hit_id"] == "job42-000007"
    assert d["event_record_id"] == "6677"
    assert d["source"].endswith("Security.evtx")


def test_hit_to_dict_legacy_without_ids():
    d = _hit_to_dict(dict(_RDP_HIT))  # no hit_id injected
    assert d["hit_id"] is None
    assert d["rule"] == "Remote Interactive Logon"


def test_get_detections_shows_ref():
    annotated = dict(_RDP_HIT)
    annotated["hit_id"] = "job42-000007"
    result = get_detections([annotated])
    assert "ref=job42-000007" in result


def test_get_detections_json_includes_hit_id():
    annotated = dict(_RDP_HIT)
    annotated["hit_id"] = "job42-000007"
    out = get_detections_json([annotated])
    assert out["hits"][0]["hit_id"] == "job42-000007"


# ---------------------------------------------------------------------------
# Agent-to-tool execution log (audit)
# ---------------------------------------------------------------------------

import inspect

from chainsawmcp import audit
from chainsawmcp.audit import audited


def _read_log(case_dir: Path) -> list[dict]:
    path = case_dir / "analysis" / "agent_execution.jsonl"
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


async def test_audited_appends_valid_record(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))

    @audited
    async def sample_tool(path: str, limit: int = 5) -> str:
        return "done: " + path

    result = await sample_tool("/cases/x", limit=9)
    assert result == "done: /cases/x"

    records = _read_log(tmp_path)
    assert len(records) == 1
    rec = records[0]
    for field in ("seq", "session_id", "tool", "args", "started_at",
                  "finished_at", "duration_ms", "status", "result_chars",
                  "result_preview"):
        assert field in rec
    assert rec["tool"] == "sample_tool"
    assert rec["status"] == "ok"
    assert rec["args"] == {"path": "/cases/x", "limit": 9}
    assert rec["result_chars"] == len("done: /cases/x")
    assert rec["result_preview"].startswith("done: ")
    assert "error" not in rec


async def test_audited_seq_increments_and_valid_jsonl(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))

    @audited
    async def t(n: int) -> str:
        return str(n)

    await t(1)
    await t(2)
    await t(3)

    records = _read_log(tmp_path)
    assert len(records) == 3
    seqs = [r["seq"] for r in records]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == 3  # monotonic, no duplicates
    # All share one session id.
    assert len({r["session_id"] for r in records}) == 1


async def test_audited_logs_error_and_reraises(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))

    @audited
    async def boom() -> str:
        raise ValueError("kaboom")

    with pytest.raises(ValueError, match="kaboom"):
        await boom()

    records = _read_log(tmp_path)
    assert len(records) == 1
    rec = records[0]
    assert rec["status"] == "error"
    assert rec["error"] == "ValueError: kaboom"
    assert "result_preview" not in rec


async def test_audited_survives_unwritable_log_dir(tmp_path, monkeypatch):
    # Point case dir at a path whose 'analysis' is a file, so mkdir/open fail.
    blocker = tmp_path / "analysis"
    blocker.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))

    @audited
    async def still_works(x: str) -> str:
        return x.upper()

    # The tool must succeed even though logging cannot write.
    assert await still_works("ok") == "OK"


def test_audited_preserves_signature():
    async def original(path: str, limit: int = 25, output_format: str = "text") -> str:
        return ""

    wrapped = audited(original)
    assert inspect.signature(wrapped) == inspect.signature(original)
    assert wrapped.__name__ == original.__name__


async def test_audited_truncates_long_args(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))

    @audited
    async def t(blob: str) -> str:
        return "ok"

    long = "A" * 5000
    await t(long)
    rec = _read_log(tmp_path)[0]
    assert len(rec["args"]["blob"]) < len(long)
    assert rec["args"]["blob"].endswith("…")


# ---------------------------------------------------------------------------
# Canonical report spec
# ---------------------------------------------------------------------------

def test_spec_sections_are_ordered_and_unique():
    numbers = [s.number for s in SECTIONS]
    assert numbers == sorted(numbers) == list(range(1, len(SECTIONS) + 1))
    assert len({s.id for s in SECTIONS}) == len(SECTIONS)


def test_spec_splits_server_and_model_sections():
    assert {s.id for s in MODEL_SECTIONS} == {
        "executive_summary", "attack_narrative", "recommendations", "gaps",
    }
    assert {s.id for s in SERVER_SECTIONS} == {
        "mitre_attack", "timeline", "iocs", "accounts_systems", "provenance",
    }
    assert set(MODEL_SECTIONS) | set(SERVER_SECTIONS) == set(SECTIONS)


def test_spec_text_lists_every_section_and_marks_authorship():
    text = render_spec_text()
    for section in SECTIONS:
        assert section.heading in text
    assert "SERVER-RENDERED" in text
    assert "YOU WRITE" in text
    assert "ref=<hit_id>" in text


# ---------------------------------------------------------------------------
# MITRE mapping
# ---------------------------------------------------------------------------

def _tagged(name, level, tags, hit_id, timestamp="2018-05-04T22:14:29+00:00"):
    return {
        "name": name, "level": level, "tags": tags,
        "hit_id": hit_id, "timestamp": timestamp,
    }


def test_mitre_extracts_techniques_and_subtechniques():
    hits = [
        _tagged("Eventlog Cleared", "high", ["attack.t1685.005", "car.2016-04-002"], "j-000001"),
        _tagged("PowerShell", "critical", ["attack.t1059.001"], "j-000002"),
    ]
    result = build_mitre_rows(hits)
    techniques = {r["technique"] for r in result["techniques"]}
    assert techniques == {"T1685.005", "T1059.001"}
    # Non-ATT&CK namespaces (car.*, cve.*) must not become techniques or tactics.
    assert all("car" not in t["tactic"] for t in result["tactics"])


def test_mitre_normalises_tactic_separator_variants():
    """SigmaHQ emits both attack.lateral-movement and attack.lateral_movement."""
    hits = [
        _tagged("A", "high", ["attack.lateral-movement"], "j-000001"),
        _tagged("B", "high", ["attack.lateral_movement"], "j-000002"),
    ]
    result = build_mitre_rows(hits)
    tactics = {t["tactic"]: t["count"] for t in result["tactics"]}
    assert tactics == {"lateral-movement": 2}


def test_mitre_groups_rules_and_tracks_window():
    hits = [
        _tagged("Rule A", "high", ["attack.t1021.002"], "j-000001", "2018-05-01T00:00:00+00:00"),
        _tagged("Rule B", "critical", ["attack.t1021.002"], "j-000002", "2018-06-01T00:00:00+00:00"),
    ]
    row = build_mitre_rows(hits)["techniques"][0]
    assert row["technique"] == "T1021.002"
    assert row["count"] == 2
    assert row["rules"] == ["Rule A", "Rule B"]
    assert row["severity"] == "critical"          # most severe of the contributors
    assert row["first_seen"] == "2018-05-01T00:00:00Z"
    assert row["last_seen"] == "2018-06-01T00:00:00Z"
    assert row["hit_ids"] == ["j-000001", "j-000002"]


def test_mitre_captures_software_tags():
    hits = [_tagged("CS", "critical", ["attack.s0002"], "j-000001")]
    assert build_mitre_rows(hits)["software"] == [{"id": "S0002", "rules": ["CS"]}]


def test_mitre_counts_untagged_hits_without_inventing_techniques():
    hits = [
        _tagged("Tagged", "high", ["attack.t1059.001"], "j-000001"),
        {"name": "Untagged", "level": "info", "hit_id": "j-000002"},
    ]
    result = build_mitre_rows(hits)
    assert result["tagged_hits"] == 1
    assert result["untagged_hits"] == 1
    assert len(result["techniques"]) == 1


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

def _sev_hit(level, hit_id, timestamp):
    return {"name": f"Rule {level}", "level": level, "hit_id": hit_id, "timestamp": timestamp}


def test_timeline_applies_severity_floor():
    hits = [
        _sev_hit("critical", "j-000001", "2018-01-01T00:00:00+00:00"),
        _sev_hit("high", "j-000002", "2018-01-02T00:00:00+00:00"),
        _sev_hit("medium", "j-000003", "2018-01-03T00:00:00+00:00"),
        _sev_hit("info", "j-000004", "2018-01-04T00:00:00+00:00"),
    ]
    result = build_timeline(hits, min_severity="high")
    assert [r["hit_id"] for r in result["rows"]] == ["j-000001", "j-000002"]
    assert result["total_matching"] == 2


def test_timeline_sorts_chronologically_and_caps_rows():
    hits = [
        _sev_hit("high", "j-000003", "2018-03-01T00:00:00+00:00"),
        _sev_hit("high", "j-000001", "2018-01-01T00:00:00+00:00"),
        _sev_hit("high", "j-000002", "2018-02-01T00:00:00+00:00"),
    ]
    result = build_timeline(hits, min_severity="high", max_rows=2)
    assert [r["hit_id"] for r in result["rows"]] == ["j-000001", "j-000002"]
    assert result["truncated"] == 1
    assert result["total_matching"] == 3


def test_timeline_normalises_timestamps_to_utc_z():
    hits = [_sev_hit("high", "j-000001", "2018-05-04T22:14:29.632649+00:00")]
    assert build_timeline(hits)["rows"][0]["timestamp"] == "2018-05-04T22:14:29Z"


def test_timeline_sorts_undated_rows_last():
    hits = [
        {"name": "No time", "level": "high", "hit_id": "j-000002"},
        _sev_hit("high", "j-000001", "2018-01-01T00:00:00+00:00"),
    ]
    rows = build_timeline(hits, min_severity="high")["rows"]
    assert [r["hit_id"] for r in rows] == ["j-000001", "j-000002"]


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------

def _evt(event_data, hit_id="j-000001", level="high", name="Rule"):
    return {
        "name": name, "level": level, "hit_id": hit_id,
        "timestamp": "2018-05-04T22:14:29+00:00",
        "document": {"data": {"Event": {"EventData": event_data, "System": {}}}},
    }


def test_iocs_extract_and_deduplicate():
    hits = [
        _evt({"IpAddress": "10.0.0.5"}, "j-000001"),
        _evt({"IpAddress": "10.0.0.5"}, "j-000002"),
    ]
    entries = build_iocs(hits)["categories"]["network"]["entries"]
    assert len(entries) == 1
    assert entries[0]["value"] == "10.0.0.5"
    assert entries[0]["count"] == 2
    assert entries[0]["hit_ids"] == ["j-000001", "j-000002"]


def test_iocs_suppress_placeholder_values():
    hits = [_evt({"IpAddress": "-", "ServiceName": "??", "CommandLine": ""})]
    assert build_iocs(hits)["categories"] == {}


def test_iocs_drop_machine_accounts():
    hits = [
        _evt({"TargetUserName": "WORKSTATION$", "TargetDomainName": "CORP"}, "j-000001"),
        _evt({"TargetUserName": "alice", "TargetDomainName": "CORP"}, "j-000002"),
    ]
    values = [e["value"] for e in build_iocs(hits)["categories"]["accounts"]["entries"]]
    assert values == ["CORP\\alice"]


def test_iocs_reject_version_strings_shaped_like_ips():
    """HostVersion=1.0.0.0 is a version, not an indicator."""
    hits = [_evt({"CommandLine": "app.exe HostVersion=1.0.0.0 peer=192.168.1.7"})]
    values = [e["value"] for e in build_iocs(hits)["categories"]["network"]["entries"]]
    assert values == ["192.168.1.7"]


def test_iocs_reject_impossible_octets():
    hits = [_evt({"CommandLine": "build 999.999.999.999 and 10.1.2.3"})]
    values = [e["value"] for e in build_iocs(hits)["categories"]["network"]["entries"]]
    assert values == ["10.1.2.3"]


def test_iocs_keep_loopback():
    """\\\\127.0.0.1\\ADMIN$ is the PSExec service-install pattern — a real signal."""
    hits = [_evt({"CommandLine": r"\\127.0.0.1\ADMIN$"})]
    values = [e["value"] for e in build_iocs(hits)["categories"]["network"]["entries"]]
    assert values == ["127.0.0.1"]


def test_iocs_recover_indicators_from_base64_payloads():
    """Attacker C2 details commonly appear only inside encoded payloads."""
    import base64
    encoded = base64.b64encode(
        b"\x90\x90connect 206.189.69.35 via \\\\.\\pipe\\diagsvc-22 now padding padding"
    ).decode()
    hits = [_evt({"ScriptBlockText": f"IEX ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('{encoded}')))"})]
    categories = build_iocs(hits)["categories"]

    network = categories["network"]["entries"][0]
    assert network["value"] == "206.189.69.35"
    assert network["decoded"] is True

    pipe = categories["pipes"]["entries"][0]
    assert pipe["value"] == r"\\.\pipe\diagsvc-22"
    assert pipe["decoded"] is True


def test_iocs_mark_plaintext_indicators_as_not_decoded():
    hits = [_evt({"CommandLine": "curl http://evil.example/a"})]
    entry = build_iocs(hits)["categories"]["urls"]["entries"][0]
    assert entry["value"] == "http://evil.example/a"
    assert entry["decoded"] is False


# ---------------------------------------------------------------------------
# Hosts and accounts
# ---------------------------------------------------------------------------

def _sys_evt(system, event_data=None, hit_id="j-000001", level="high"):
    return {
        "name": "Rule", "level": level, "hit_id": hit_id,
        "timestamp": "2018-05-04T22:14:29+00:00",
        "document": {"data": {"Event": {"System": system, "EventData": event_data or {}}}},
    }


def test_inventory_groups_case_variants_of_one_principal():
    hits = [
        _sys_evt({}, {"TargetUserName": "spsql", "TargetDomainName": "shieldbase"}, "j-000001"),
        _sys_evt({}, {"TargetUserName": "spsql", "TargetDomainName": "SHIELDBASE"}, "j-000002"),
    ]
    accounts = build_hosts_accounts(hits)["accounts"]
    assert len(accounts) == 1
    assert accounts[0]["count"] == 2
    assert accounts[0]["variants"] == ["SHIELDBASE\\spsql", "shieldbase\\spsql"]


def test_inventory_keeps_distinct_domain_qualifiers_separate():
    """NetBIOS and DNS forms are not merged — that would be an inference."""
    hits = [
        _sys_evt({}, {"TargetUserName": "spsql", "TargetDomainName": "shieldbase"}, "j-000001"),
        _sys_evt({}, {"TargetUserName": "spsql", "TargetDomainName": "shieldbase.lan"}, "j-000002"),
    ]
    assert len(build_hosts_accounts(hits)["accounts"]) == 2


def test_inventory_tracks_window_and_max_severity():
    hits = [
        _sys_evt({"Computer": "HOST1"}, hit_id="j-000001", level="low"),
        {**_sys_evt({"Computer": "HOST1"}, hit_id="j-000002", level="critical"),
         "timestamp": "2018-09-01T00:00:00+00:00"},
    ]
    host = build_hosts_accounts(hits)["hosts"][0]
    assert host["name"] == "HOST1"
    assert host["count"] == 2
    assert host["max_severity"] == "critical"
    assert host["first_seen"] == "2018-05-04T22:14:29Z"
    assert host["last_seen"] == "2018-09-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

def test_provenance_block_reads_record(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    job_dir = tmp_path / "analysis" / "job1"
    job_dir.mkdir(parents=True)
    (job_dir / "chainsaw_provenance.json").write_text(json.dumps({
        "command": ["chainsaw", "hunt", "/evtx"],
        "chainsaw_version": "2.16.0",
        "output_sha256": "abc123",
        "completed_at": "2026-06-13T16:34:23Z",
    }), encoding="utf-8")

    block = build_provenance_block("job1", "/evidence")
    assert block["available"] is True
    assert block["command"] == "chainsaw hunt /evtx"
    assert block["chainsaw_version"] == "2.16.0"
    assert block["output_sha256"] == "abc123"


def test_provenance_block_degrades_when_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    block = build_provenance_block("nope", "/evidence")
    assert block["available"] is False


def test_report_flags_missing_provenance_to_the_reader(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    report = render_report_markdown([_sev_hit("high", "j-000001", "2018-01-01T00:00:00+00:00")])
    assert "Provenance record unavailable" in report


# ---------------------------------------------------------------------------
# Skeleton rendering
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_hits():
    return [
        _tagged("Eventlog Cleared", "high", ["attack.t1685.005"], "j-000001"),
        _tagged("PowerShell", "critical", ["attack.t1059.001"], "j-000002"),
    ]


def test_skeleton_contains_every_heading_in_spec_order(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    report = render_report_markdown(sample_hits, job_id="j", evidence_path="/evidence")
    positions = [report.index(s.heading) for s in SECTIONS]
    assert positions == sorted(positions)


def test_skeleton_slots_exactly_the_model_sections(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    report = render_report_markdown(sample_hits, job_id="j", evidence_path="/evidence")
    for section in MODEL_SECTIONS:
        assert report.count(slot_begin(section)) == 1
        assert report.count(slot_end(section)) == 1
    for section in SERVER_SECTIONS:
        assert slot_begin(section) not in report


def test_skeleton_prefills_server_sections(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    report = render_report_markdown(sample_hits, job_id="j", evidence_path="/evidence")
    assert "T1685.005" in report          # MITRE
    assert "2018-05-04T22:14:29Z" in report   # timeline
    assert "Total hits" in report          # provenance


def test_skeleton_escapes_pipes_so_tables_do_not_break(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    hits = [_evt({"CommandLine": "cmd.exe /c a | b"})]
    report = render_report_markdown(hits)
    assert "a \\| b" in report


def test_report_json_sidecar_shape(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    payload = build_report_json(sample_hits, job_id="j", evidence_path="/evidence")
    assert set(payload) == {
        "spec_version", "generated", "job_id", "evidence", "total_hits",
        "sections", "mitre", "timeline", "iocs", "inventory", "provenance",
        "cited_hit_ids",
    }
    assert payload["total_hits"] == 2
    assert [s["id"] for s in payload["sections"]] == [s.id for s in SECTIONS]
    assert payload["cited_hit_ids"] == ["j-000001", "j-000002"]


def test_write_incident_report_creates_both_files(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    md_path, json_path = write_incident_report(
        sample_hits, tmp_path / "reports", job_id="j", evidence_path="/evidence"
    )
    assert md_path.name == "incident_report.md"
    assert json_path.name == "incident_report.json"
    assert "# Incident Report" in md_path.read_text(encoding="utf-8")
    assert json.loads(json_path.read_text(encoding="utf-8"))["total_hits"] == 2


def test_write_full_report_writes_text_file(tmp_path):
    """hunt_report.txt is unchanged by the Markdown report — pin its behaviour."""
    hits = [{"name": "Mimikatz", "level": "high", "timestamp": "2024-01-01T00:00:00Z"}]
    path = write_full_report(hits, evtx_path="/evidence", output_dir=tmp_path / "reports")
    assert path.name == "hunt_report.txt"
    text = path.read_text(encoding="utf-8")
    assert "ChainsawMCP — ANALYST REPORT" in text
    assert "Mimikatz" in text


# ---------------------------------------------------------------------------
# Report validation
# ---------------------------------------------------------------------------

def _filled_report(hits, tmp_path):
    """Render the skeleton and fill every model slot with a cited paragraph."""
    report = render_report_markdown(hits, job_id="j", evidence_path="/evidence")
    for section in MODEL_SECTIONS:
        report = report.replace(
            slot_placeholder(section),
            f"The {section.title.lower()} content for this engagement, written out at "
            f"sufficient length to be a real section rather than a stub. ref=j-000001",
        )
    return report


def test_validator_passes_a_complete_report(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    result = validate_report_text(_filled_report(sample_hits, tmp_path), sample_hits)
    assert result["pass"] is True, result["violations"]
    assert result["unresolved"] == []


def test_validator_flags_unfilled_slots(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    skeleton = render_report_markdown(sample_hits, job_id="j", evidence_path="/evidence")
    result = validate_report_text(skeleton, sample_hits)
    assert result["pass"] is False
    codes = {v["code"] for v in result["violations"]}
    assert codes == {"unfilled_slot"}
    assert {v["section"] for v in result["violations"]} == {s.id for s in MODEL_SECTIONS}


def test_validator_flags_missing_section(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    report = _filled_report(sample_hits, tmp_path).replace("## 7. Recommendations", "## Extras")
    result = validate_report_text(report, sample_hits)
    assert result["pass"] is False
    assert any(v["code"] == "missing_section" for v in result["violations"])


def test_validator_flags_unresolved_citation(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    report = _filled_report(sample_hits, tmp_path) + "\n\nExtra claim. ref=j-999999\n"
    result = validate_report_text(report, sample_hits)
    assert result["pass"] is False
    assert "j-999999" in result["unresolved"]
    assert any(v["code"] == "unresolved_citation" for v in result["violations"])


def test_validator_flags_non_utc_timestamp(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    report = _filled_report(sample_hits, tmp_path).replace(
        "ref=j-000001", "at 2018-05-04T22:14:29+02:00 ref=j-000001", 1
    )
    result = validate_report_text(report, sample_hits)
    assert result["pass"] is False
    assert any(v["code"] == "non_utc_timestamp" for v in result["violations"])


def test_validator_flags_uncited_narrative_section(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    report = render_report_markdown(sample_hits, job_id="j", evidence_path="/evidence")
    for section in MODEL_SECTIONS:
        cite = "" if section.id == "gaps" else " ref=j-000001"
        report = report.replace(
            slot_placeholder(section),
            "A section of genuine prose long enough to clear the minimum content "
            "threshold applied by the validator." + cite,
        )
    result = validate_report_text(report, sample_hits)
    assert result["pass"] is False
    assert any(
        v["code"] == "uncited_section" and v["section"] == "gaps"
        for v in result["violations"]
    )


def test_validator_flags_stub_section(sample_hits, tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    report = render_report_markdown(sample_hits, job_id="j", evidence_path="/evidence")
    for section in MODEL_SECTIONS:
        report = report.replace(slot_placeholder(section), "N/A ref=j-000001")
    result = validate_report_text(report, sample_hits)
    assert result["pass"] is False
    assert any(v["code"] == "empty_section" for v in result["violations"])


# ---------------------------------------------------------------------------
# Path traversal guards (CWE-22)
#
# The client-supplied value is never joined onto a path: it is matched against the
# on-disk listing and the path comes from the matching entry. These tests pin that
# behaviour rather than the mechanism, so they still hold if the lookup changes.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# job_id traversal — guarded at _job_dir, so every job path is covered
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["../../etc", "..", "a/b", "/etc", ""])
def test_job_paths_reject_traversal(tmp_path, monkeypatch, bad):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    for fn in (results_path, log_path, provenance_path, read_job):
        with pytest.raises(ValueError):
            fn(bad)


def test_job_paths_accept_a_real_job_id(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    job_id = create_job("/evidence/disk.E01")
    assert re.fullmatch(r"[0-9a-f]{8}", job_id)
    assert results_path(job_id).name == "hunt_results.json"
    assert read_job(job_id)["job_id"] == job_id


def test_read_provenance_tolerates_empty_job_id(tmp_path, monkeypatch):
    """state.job_id is "" before any hunt — that must not raise."""
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    assert read_provenance("") is None


def test_read_provenance_returns_none_for_unknown_job(tmp_path, monkeypatch):
    """Only ever called with a server-generated job_id, so None beats raising."""
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    assert read_provenance("../../../etc") is None
    assert read_provenance("nosuchjob") is None


def test_job_lookup_never_joins_the_caller_string(tmp_path, monkeypatch):
    """A directory that exists outside the jobs root stays unreachable by traversal."""
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    outside = tmp_path / "secrets"
    outside.mkdir()
    (outside / "hunt_results.json").write_text("[]", encoding="utf-8")
    (tmp_path / "analysis").mkdir()
    with pytest.raises(ValueError, match="No such job"):
        results_path("../secrets")


def test_job_lookup_rejects_an_id_that_is_not_a_real_job(tmp_path, monkeypatch):
    """Stronger than containment: an id must name a job that actually exists."""
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    create_job("/evidence/disk.E01")
    with pytest.raises(ValueError, match="No such job"):
        read_job("deadbeef")


# ---------------------------------------------------------------------------
# validate_report path confinement
# ---------------------------------------------------------------------------

@pytest.fixture
def loaded_session(tmp_path, monkeypatch):
    """Put the server in a 'hunt done' state pointed at tmp_path, then restore it."""
    monkeypatch.setenv("CHAINSAWMCP_CASE_DIR", str(tmp_path))
    saved = (server.state.hunt_status, server.state.hits, server.state.job_id)
    server.state.hunt_status = "done"
    server.state.hits = [{"name": "R", "level": "high", "hit_id": "j-000001",
                          "timestamp": "2018-01-01T00:00:00+00:00"}]
    server.state.job_id = ""
    yield tmp_path
    (server.state.hunt_status, server.state.hits, server.state.job_id) = saved


async def test_validate_report_reads_the_default_report(loaded_session):
    await server.build_incident_report()
    result = json.loads(await server.validate_report())
    assert result["report_file"].endswith("incident_report.md")
    # Unfilled skeleton — the point is that it read the file, not that it passed.
    assert result["pass"] is False


@pytest.mark.parametrize("attack", [
    "/etc/passwd",
    "../../../../etc/passwd",
    "../../analysis/forensic_audit.log",
])
async def test_validate_report_refuses_paths_outside_reports_dir(loaded_session, attack):
    await server.build_incident_report()
    with pytest.raises(ValueError, match="is not in the reports directory|No report named"):
        await server.validate_report(path=attack)


async def test_validate_report_accepts_a_relative_name_in_reports_dir(loaded_session):
    """A bare filename resolves against the reports dir, not the process cwd."""
    await server.build_incident_report()
    result = json.loads(await server.validate_report(path="incident_report.md"))
    assert result["report_file"].endswith("incident_report.md")


async def test_validate_report_does_not_leak_file_existence_outside_reports(loaded_session):
    """Lookup is by listing, so a path outside the reports dir is never even stat-ed."""
    await server.build_incident_report()
    with pytest.raises(ValueError, match="is not in the reports directory|No report named"):
        await server.validate_report(path="/definitely/does/not/exist/anywhere")


@pytest.mark.parametrize("bad", ["../../../etc", "..", "a/b", "deadbeef"])
async def test_load_hunt_results_rejects_unknown_or_traversing_job_id(loaded_session, bad):
    """Traversal and a merely-nonexistent id fail the same way: neither is a real job."""
    with pytest.raises(ValueError, match="No such job"):
        await server.load_hunt_results(job_id=bad)
