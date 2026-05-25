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
    _find_windows_ntfs_partition,
    _is_ntfs,
    _partition_size_bytes,
    _prepare_evtx_dir,
    _prepare_e01_linux,
    _prepare_e01_linux_fuse,
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


def test_prepared_evidence_cleanup_calls_umount_in_order(tmp_path):
    """Cleanup must unmount NTFS before the loop device before EWF."""
    ntfs_mount = tmp_path / "ntfs"
    ewf_mount = tmp_path / "ewf"
    ntfs_mount.mkdir()
    ewf_mount.mkdir()

    call_log = []

    def fake_run(cmd, **_kwargs):
        call_log.append(cmd[0] if cmd[0] != "losetup" else f"losetup {cmd[1]}")

    with patch("chainsawmcp.evidence.subprocess.run", side_effect=fake_run):
        PreparedEvidence(
            evtx_dir=tmp_path / "evtx",
            _ewf_mount=ewf_mount,
            _ntfs_mount=ntfs_mount,
            _loop_device="/dev/loop9",
            _temp_dir=tmp_path,
        ).cleanup()

    assert call_log[0] == "umount"        # NTFS first
    assert call_log[1] == "losetup -d"    # then loop device
    assert call_log[2] == "umount"        # then EWF


# ---------------------------------------------------------------------------
# E01 partition detection
# ---------------------------------------------------------------------------

def test_find_windows_ntfs_partition_no_losetup():
    with patch("chainsawmcp.evidence.shutil.which", return_value=None):
        loop, part = _find_windows_ntfs_partition(Path("/fake/ewf1"))
    assert loop is None and part is None


def test_find_windows_ntfs_partition_losetup_fails():
    with patch("chainsawmcp.evidence.shutil.which", return_value="/usr/sbin/losetup"):
        with patch("chainsawmcp.evidence.subprocess.run", side_effect=subprocess.CalledProcessError(1, "losetup")):
            loop, part = _find_windows_ntfs_partition(Path("/fake/ewf1"))
    assert loop is None and part is None


def test_find_windows_ntfs_partition_selects_largest(tmp_path):
    """When multiple NTFS partitions exist, the largest is returned."""
    fake_loop = "/dev/loop7"

    def fake_run(cmd, **kwargs):
        mock = MagicMock()
        mock.returncode = 0
        if "losetup" in cmd and "--show" in cmd:
            mock.stdout = fake_loop + "\n"
        elif "blkid" in cmd:
            # All partitions report as ntfs
            mock.stdout = "ntfs\n"
        elif "blockdev" in cmd:
            # p1 = 100 MB, p2 = 50 GB
            mock.stdout = "104857600\n" if "p1" in cmd[-1] else "53687091200\n"
        else:
            mock.stdout = ""
        return mock

    with patch("chainsawmcp.evidence.subprocess.run", side_effect=fake_run):
        with patch("chainsawmcp.evidence.shutil.which", return_value="/usr/sbin/losetup"):
            with patch("chainsawmcp.evidence._glob.glob", return_value=["/dev/loop7p1", "/dev/loop7p2"]):
                loop, part = _find_windows_ntfs_partition(Path("/fake/ewf1"))

    assert loop == fake_loop
    assert part == "/dev/loop7p2"


def test_find_windows_ntfs_partition_no_ntfs_releases_loop():
    """If no NTFS partition is found the loop device must be released."""
    released = []
    fake_loop = "/dev/loop8"

    def fake_run(cmd, **kwargs):
        mock = MagicMock()
        mock.returncode = 0
        if "losetup" in cmd and "--show" in cmd:
            mock.stdout = fake_loop + "\n"
        elif "losetup" in cmd and "-d" in cmd:
            released.append(cmd[-1])
        elif "blkid" in cmd:
            mock.stdout = "ext4\n"  # not NTFS
        else:
            mock.stdout = ""
        return mock

    with patch("chainsawmcp.evidence.subprocess.run", side_effect=fake_run):
        with patch("chainsawmcp.evidence.shutil.which", return_value="/usr/sbin/losetup"):
            with patch("chainsawmcp.evidence._glob.glob", return_value=["/dev/loop8p1"]):
                loop, part = _find_windows_ntfs_partition(Path("/fake/ewf1"))

    assert loop is None and part is None
    assert fake_loop in released


def test_is_ntfs_true():
    mock = MagicMock()
    mock.stdout = "ntfs\n"
    with patch("chainsawmcp.evidence.shutil.which", return_value="/usr/sbin/blkid"):
        with patch("chainsawmcp.evidence.subprocess.run", return_value=mock):
            assert _is_ntfs("/dev/loop0p1") is True


def test_is_ntfs_false_no_blkid():
    with patch("chainsawmcp.evidence.shutil.which", return_value=None):
        assert _is_ntfs("/dev/loop0p1") is False


def test_partition_size_bytes_success():
    mock = MagicMock()
    mock.stdout = "107374182400\n"
    with patch("chainsawmcp.evidence.subprocess.run", return_value=mock):
        assert _partition_size_bytes("/dev/loop0p2") == 107374182400


def test_partition_size_bytes_failure():
    with patch("chainsawmcp.evidence.subprocess.run", side_effect=subprocess.CalledProcessError(1, "blockdev")):
        assert _partition_size_bytes("/dev/loop0p2") == 0


# ---------------------------------------------------------------------------
# _prepare_e01_linux (mocked subprocess)
# ---------------------------------------------------------------------------

def test_prepare_e01_linux_happy_path(tmp_path):
    """Full happy-path: ewfmount → losetup → ntfs-3g → copy evtx."""
    # Create a fake .evtx in the ntfs_mount directory so _copy_evtx_files succeeds.
    # We intercept ntfs-3g and write the file into the mount dir ourselves.
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"")

    run_calls = []

    def fake_run(cmd, **kwargs):
        run_calls.append(cmd[0])
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = ""
        mock.stderr = ""
        return mock

    # Patch _find_windows_ntfs_partition to skip losetup complexity
    with patch("chainsawmcp.evidence._find_windows_ntfs_partition", return_value=(None, None)):
        with patch("chainsawmcp.evidence.shutil.which", return_value="/usr/bin/tool"):
            with patch("chainsawmcp.evidence._run", side_effect=fake_run):
                # _copy_evtx_files will fail because the ntfs mount is empty.
                # Override it to simulate a successful copy.
                with patch("chainsawmcp.evidence._copy_evtx_files"):
                    result = _prepare_e01_linux(e01)

    assert result.evtx_dir.name == "evtx"
    assert result._ewf_mount is not None
    assert result._ntfs_mount is not None
    # loop_device is None because _find_windows_ntfs_partition returned (None, None)
    assert result._loop_device is None


def test_prepare_e01_linux_cleans_up_on_failure(tmp_path):
    """If ntfs-3g fails, ewfmount must also be unmounted and tmp removed."""
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"")

    unmounted = []

    def fake_run(cmd, capture_output=False, **kwargs):
        if cmd[0] == "umount":
            unmounted.append(str(cmd[1]))
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = ""
        return mock

    def fake__run(cmd, check=True):
        if cmd[0] == "ntfs-3g":
            raise EvidenceError("ntfs-3g failed")
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = ""
        mock.stderr = ""
        return mock

    fuse_tmp = tmp_path / "tmp"
    fuse_tmp.mkdir()
    (tmp_path / "evtx").mkdir()

    with patch("chainsawmcp.evidence._find_windows_ntfs_partition", return_value=(None, None)):
        with patch("chainsawmcp.evidence.shutil.which", return_value="/usr/bin/tool"):
            with patch("chainsawmcp.evidence._run", side_effect=fake__run):
                with patch("chainsawmcp.evidence.subprocess.run", side_effect=fake_run):
                    with pytest.raises(EvidenceError, match="ntfs-3g failed"):
                        _prepare_e01_linux_fuse(e01, fuse_tmp, tmp_path / "evtx")

    # Both ntfs_mount and ewf_mount must have been unmounted
    assert len(unmounted) >= 2


# ---------------------------------------------------------------------------
# Rootless extraction (_extract_e01_rootless)
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
        with pytest.raises(ImportError, match="pytsk3 and pyewf"):
            _extract_e01_rootless(tmp_path / "disk.E01", tmp_path / "out")


def test_extract_e01_rootless_no_evtx_raises(tmp_path):
    """Should raise EvidenceError when the image contains no .evtx files."""
    (tmp_path / "out").mkdir()

    # Build minimal mock pytsk3/pyewf objects that report an empty NTFS partition.
    fake_dir = MagicMock()
    fake_dir.__iter__ = MagicMock(return_value=iter([]))  # empty directory

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


def test_prepare_e01_linux_prefers_rootless(tmp_path):
    """_prepare_e01_linux should use rootless extraction when available."""
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"")

    with patch("chainsawmcp.evidence._extract_e01_rootless") as mock_rootless:
        result = _prepare_e01_linux(e01)

    mock_rootless.assert_called_once()
    # No FUSE mount points should be set
    assert result._ewf_mount is None
    assert result._ntfs_mount is None
    assert result._loop_device is None


def test_prepare_e01_linux_falls_back_to_fuse_when_libs_missing(tmp_path):
    """_prepare_e01_linux should fall back to FUSE when pytsk3/pyewf are absent."""
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"")

    fake_result = PreparedEvidence(evtx_dir=tmp_path / "evtx", _temp_dir=tmp_path)

    with patch("chainsawmcp.evidence._extract_e01_rootless", side_effect=ImportError("no pytsk3")):
        with patch("chainsawmcp.evidence._prepare_e01_linux_fuse", return_value=fake_result) as mock_fuse:
            result = _prepare_e01_linux(e01)

    mock_fuse.assert_called_once()
    assert result is fake_result


def test_prepare_e01_linux_propagates_non_import_errors(tmp_path):
    """EvidenceError from rootless extraction should propagate — not fall through to FUSE."""
    e01 = tmp_path / "disk.E01"
    e01.write_bytes(b"")

    with patch("chainsawmcp.evidence._extract_e01_rootless", side_effect=EvidenceError("bad image")):
        with pytest.raises(EvidenceError, match="bad image"):
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
