"""Evidence preparation: validate EVTX directories and mount E01 images."""

import glob as _glob
import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import is_windows


class EvidenceError(Exception):
    pass


class PreparedEvidence:
    """Holds staged EVTX directory and all cleanup state for one session."""

    def __init__(
        self,
        evtx_dir: Path,
        _ewf_mount: Path | None = None,
        _ntfs_mount: Path | None = None,
        _loop_device: str | None = None,
        _aim_drive: str | None = None,
        _temp_dir: Path | None = None,
    ):
        self.evtx_dir = evtx_dir
        self._ewf_mount = _ewf_mount
        self._ntfs_mount = _ntfs_mount
        self._loop_device = _loop_device
        self._aim_drive = _aim_drive
        self._temp_dir = _temp_dir

    def cleanup(self) -> None:
        # Tear down in reverse mount order: NTFS → loop device → EWF → temp dir
        if self._ntfs_mount and self._ntfs_mount.exists():
            subprocess.run(["umount", str(self._ntfs_mount)], capture_output=True)
        if self._loop_device:
            subprocess.run(["losetup", "-d", self._loop_device], capture_output=True)
        if self._ewf_mount and self._ewf_mount.exists():
            subprocess.run(["umount", str(self._ewf_mount)], capture_output=True)
        if self._aim_drive:
            aim = _find_aim_cli()
            if aim:
                subprocess.run(
                    [str(aim), "/unmount", f"/drive={self._aim_drive}"],
                    capture_output=True,
                )
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

    tmp = Path(tempfile.mkdtemp(prefix="chainsawmcp_"))
    ewf_mount = tmp / "ewf"
    ntfs_mount = tmp / "ntfs"
    evtx_stage = tmp / "evtx"
    ewf_mount.mkdir()
    ntfs_mount.mkdir()
    evtx_stage.mkdir()

    loop_device: str | None = None

    try:
        _run(["ewfmount", str(first_segment), str(ewf_mount)])
        raw_image = ewf_mount / "ewf1"

        # Real disk images have a partition table; expose partitions via losetup
        # and find the Windows NTFS volume. Fall back to direct mount if losetup
        # is unavailable (e.g. raw NTFS image without a partition table).
        loop_device, ntfs_dev = _find_windows_ntfs_partition(raw_image)
        mount_target = ntfs_dev if ntfs_dev else str(raw_image)
        _run(["ntfs-3g", "-o", "ro,noatime", mount_target, str(ntfs_mount)])

        _copy_evtx_files(ntfs_mount, evtx_stage)
    except Exception:
        subprocess.run(["umount", str(ntfs_mount)], capture_output=True)
        if loop_device:
            subprocess.run(["losetup", "-d", loop_device], capture_output=True)
        subprocess.run(["umount", str(ewf_mount)], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)
        raise

    return PreparedEvidence(
        evtx_dir=evtx_stage,
        _ewf_mount=ewf_mount,
        _ntfs_mount=ntfs_mount,
        _loop_device=loop_device,
        _temp_dir=tmp,
    )


def _find_windows_ntfs_partition(raw_image: Path) -> tuple[str | None, str | None]:
    """
    Attach raw_image as a loop device with partition scanning and return the
    most likely Windows NTFS volume: (loop_device_path, partition_device_path).
    Returns (None, None) if losetup is unavailable or no NTFS partition found.
    """
    if not shutil.which("losetup"):
        return None, None

    try:
        result = subprocess.run(
            ["losetup", "--show", "-f", "-P", str(raw_image)],
            capture_output=True, text=True, check=True,
        )
        loop_dev = result.stdout.strip()  # e.g. /dev/loop5
    except subprocess.CalledProcessError:
        return None, None

    partition_devs = sorted(_glob.glob(f"{loop_dev}p*"))

    ntfs_partitions = [p for p in partition_devs if _is_ntfs(p)]

    if not ntfs_partitions:
        subprocess.run(["losetup", "-d", loop_dev], capture_output=True)
        return None, None

    # Prefer the largest NTFS partition — System Reserved is tiny compared to
    # the main Windows volume.
    best = max(ntfs_partitions, key=_partition_size_bytes)
    return loop_dev, best


def _is_ntfs(device: str) -> bool:
    """Return True if blkid identifies the device filesystem as NTFS."""
    if not shutil.which("blkid"):
        return False
    r = subprocess.run(
        ["blkid", "-o", "value", "-s", "TYPE", device],
        capture_output=True, text=True,
    )
    return "ntfs" in r.stdout.lower()


def _partition_size_bytes(device: str) -> int:
    """Return block device size in bytes via blockdev, or 0 on failure."""
    try:
        r = subprocess.run(
            ["blockdev", "--getsize64", device],
            capture_output=True, text=True, check=True,
        )
        return int(r.stdout.strip())
    except (subprocess.CalledProcessError, ValueError):
        return 0


def _prepare_e01_windows(first_segment: Path) -> PreparedEvidence:
    aim = _find_aim_cli()
    if not aim:
        raise EvidenceError(
            "Arsenal Image Mounter (aim_cli.exe) not found. Add it to PATH or set AIM_CLI env var."
        )

    tmp = Path(tempfile.mkdtemp(prefix="chainsawmcp_"))
    evtx_stage = tmp / "evtx"
    evtx_stage.mkdir()

    drive = _pick_free_drive()
    try:
        _run([str(aim), "/mount", f"/filename={first_segment}", f"/drive={drive}", "/readonly"])
        mounted = Path(f"{drive}:\\")
        _copy_evtx_files(mounted, evtx_stage)
    except Exception:
        subprocess.run([str(aim), "/unmount", f"/drive={drive}"], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)
        raise

    return PreparedEvidence(evtx_dir=evtx_stage, _aim_drive=drive, _temp_dir=tmp)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _copy_evtx_files(source_root: Path, dest: Path) -> None:
    copied = 0
    for evtx in source_root.rglob("*.evtx"):
        target = dest / evtx.name
        if target.exists():
            target = dest / f"{evtx.stem}_{copied}{evtx.suffix}"
        shutil.copy2(evtx, target)
        copied += 1
    if copied == 0:
        raise EvidenceError(f"No .evtx files found in mounted image under {source_root}")


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
    import os
    override = os.environ.get("AIM_CLI")
    if override:
        return Path(override)
    found = shutil.which("aim_cli.exe")
    return Path(found) if found else None


def _pick_free_drive() -> str:
    import string
    for letter in reversed(string.ascii_uppercase):
        if not Path(f"{letter}:\\").exists():
            return letter
    raise EvidenceError("No free drive letter available for mounting.")
