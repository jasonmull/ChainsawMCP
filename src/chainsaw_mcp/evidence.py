"""Evidence preparation: validate EVTX directories and mount E01 images."""

import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import is_windows


class EvidenceError(Exception):
    pass


class PreparedEvidence:
    """Holds the staged EVTX directory and cleanup state for a session."""

    def __init__(self, evtx_dir: Path, _mount_point: Path | None = None, _temp_dir: Path | None = None):
        self.evtx_dir = evtx_dir
        self._mount_point = _mount_point
        self._temp_dir = _temp_dir

    def cleanup(self) -> None:
        if self._mount_point and self._mount_point.exists():
            _unmount(self._mount_point)
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)


def prepare_evidence(path: str) -> PreparedEvidence:
    """Detect evidence type, mount if needed, return a PreparedEvidence with staged EVTXs."""
    p = Path(path)
    if not p.exists():
        raise EvidenceError(f"Path does not exist: {p}")

    if p.is_dir():
        return _prepare_evtx_dir(p)

    if p.suffix.lower() in {".e01", ".ex01"}:
        return _prepare_e01(p)

    raise EvidenceError(f"Unrecognised evidence type: {p.suffix}. Expected a directory or .E01 image.")


# ---------------------------------------------------------------------------
# EVTX directory
# ---------------------------------------------------------------------------

def _prepare_evtx_dir(path: Path) -> PreparedEvidence:
    evtx_files = list(path.rglob("*.evtx"))
    if not evtx_files:
        raise EvidenceError(f"No .evtx files found under {path}")
    return PreparedEvidence(evtx_dir=path)


# ---------------------------------------------------------------------------
# E01 image
# ---------------------------------------------------------------------------

def _prepare_e01(first_segment: Path) -> PreparedEvidence:
    """Mount the E01 image and copy EVTXs to a temp staging directory."""
    if is_windows():
        return _prepare_e01_windows(first_segment)
    return _prepare_e01_linux(first_segment)


def _prepare_e01_linux(first_segment: Path) -> PreparedEvidence:
    _require_tool("ewfmount", "ewf-tools package")
    _require_tool("ntfs-3g", "ntfs-3g package")

    tmp = Path(tempfile.mkdtemp(prefix="chainsaw_mcp_"))
    ewf_mount = tmp / "ewf"
    ntfs_mount = tmp / "ntfs"
    evtx_stage = tmp / "evtx"
    ewf_mount.mkdir()
    ntfs_mount.mkdir()
    evtx_stage.mkdir()

    try:
        _run(["ewfmount", str(first_segment), str(ewf_mount)])
        raw_image = ewf_mount / "ewf1"
        _run(["ntfs-3g", "-o", "ro,noatime", str(raw_image), str(ntfs_mount)])
        _copy_evtx_files(ntfs_mount, evtx_stage)
    except Exception:
        _unmount(ntfs_mount)
        _unmount(ewf_mount)
        shutil.rmtree(tmp, ignore_errors=True)
        raise

    return PreparedEvidence(evtx_dir=evtx_stage, _mount_point=ntfs_mount, _temp_dir=tmp)


def _prepare_e01_windows(first_segment: Path) -> PreparedEvidence:
    aim = _find_aim_cli()
    if not aim:
        raise EvidenceError("Arsenal Image Mounter (aim_cli.exe) not found. Add it to PATH or set AIM_CLI env var.")

    tmp = Path(tempfile.mkdtemp(prefix="chainsaw_mcp_"))
    evtx_stage = tmp / "evtx"
    evtx_stage.mkdir()

    import string, random
    drive = _pick_free_drive()
    try:
        _run([str(aim), "/mount", f"/filename={first_segment}", f"/drive={drive}", "/readonly"])
        mounted = Path(f"{drive}:\\")
        _copy_evtx_files(mounted, evtx_stage)
    except Exception:
        _run([str(aim), "/unmount", f"/drive={drive}"], check=False)
        shutil.rmtree(tmp, ignore_errors=True)
        raise

    # Store drive letter so cleanup can unmount
    mount_marker = tmp / ".aim_drive"
    mount_marker.write_text(drive)
    return PreparedEvidence(evtx_dir=evtx_stage, _mount_point=tmp / ".aim_mount", _temp_dir=tmp)


def _copy_evtx_files(source_root: Path, dest: Path) -> None:
    copied = 0
    for evtx in source_root.rglob("*.evtx"):
        target = dest / evtx.name
        # Avoid name collisions by appending a counter
        if target.exists():
            target = dest / f"{evtx.stem}_{copied}{evtx.suffix}"
        shutil.copy2(evtx, target)
        copied += 1
    if copied == 0:
        raise EvidenceError(f"No .evtx files found in mounted image under {source_root}")


def _unmount(mount_point: Path) -> None:
    if not mount_point.exists():
        return
    if is_windows():
        _run(["umount", str(mount_point)], check=False)
    else:
        _run(["umount", str(mount_point)], check=False)


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=check)
    except subprocess.CalledProcessError as e:
        raise EvidenceError(f"Command failed: {' '.join(cmd)}\nstderr: {e.stderr}") from e
    except FileNotFoundError as e:
        raise EvidenceError(f"Binary not found: {cmd[0]}") from e


def _require_tool(name: str, package_hint: str) -> None:
    if not shutil.which(name):
        raise EvidenceError(f"Required tool '{name}' not found. Install {package_hint}.")


def _find_aim_cli() -> Path | None:
    override = __import__("os").environ.get("AIM_CLI")
    if override:
        return Path(override)
    found = shutil.which("aim_cli.exe")
    return Path(found) if found else None


def _pick_free_drive() -> str:
    import string
    used = {p.drive.rstrip("\\:").upper() for p in Path(".").parent.glob("*") if p.drive}
    for letter in reversed(string.ascii_uppercase):
        if letter not in used:
            return letter
    raise EvidenceError("No free drive letter available for mounting.")
