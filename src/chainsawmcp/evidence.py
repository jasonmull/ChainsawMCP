"""Evidence preparation: validate EVTX directories and mount E01 images."""

import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import is_windows


class EvidenceError(Exception):
    pass


class PreparedEvidence:
    """Holds staged EVTX directory and cleanup state for one session."""

    def __init__(
        self,
        evtx_dir: Path,
        _aim_drive: str | None = None,
        _temp_dir: Path | None = None,
    ):
        self.evtx_dir = evtx_dir
        self._aim_drive = _aim_drive
        self._temp_dir = _temp_dir

    def cleanup(self) -> None:
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
    if is_windows():
        return _prepare_e01_windows(first_segment)
    return _prepare_e01_linux(first_segment)


def _prepare_e01_linux(first_segment: Path) -> PreparedEvidence:
    tmp = Path(tempfile.mkdtemp(prefix="chainsawmcp_"))
    evtx_stage = tmp / "evtx"
    evtx_stage.mkdir()

    try:
        _extract_e01_rootless(first_segment, evtx_stage)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise

    return PreparedEvidence(evtx_dir=evtx_stage, _temp_dir=tmp)


def _extract_e01_rootless(first_segment: Path, dest: Path) -> None:
    """
    Extract EVTX files from an E01 image entirely in-process.

    Uses pyewf to read the Expert Witness Format image and pytsk3 (The Sleuth
    Kit Python bindings) to parse the NTFS filesystem — no FUSE, no root, no
    kernel-level mounts.
    """
    import pyewf   # type: ignore[import-untyped]
    import pytsk3  # type: ignore[import-untyped]

    class _EwfImgInfo(pytsk3.Img_Info):
        def __init__(self, handle: object) -> None:
            self._handle = handle
            super().__init__(url="")

        def close(self) -> None:
            self._handle.close()

        def read(self, offset: int, size: int) -> bytes:
            self._handle.seek(offset)
            return self._handle.read(size)

        def get_size(self) -> int:
            return self._handle.get_media_size()

    # ---- inner helpers that close over pytsk3 ----

    def _drain_dir(directory: object) -> int:
        copied = 0
        for entry in directory:
            try:
                raw = entry.info.name.name
                name = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                if not name.lower().endswith(".evtx"):
                    continue
                size = entry.info.meta.size
                if not size:
                    continue
                target = dest / name
                if target.exists():
                    target = dest / f"{Path(name).stem}_{copied}.evtx"
                target.write_bytes(entry.read_random(0, size))
                copied += 1
            except Exception:
                continue
        return copied

    def _walk(directory: object, depth: int = 0) -> int:
        if depth > 20:
            return 0
        copied = 0
        for entry in directory:
            try:
                raw = entry.info.name.name
                name = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                if name in (".", ".."):
                    continue
                meta = entry.info.meta
                if meta is None:
                    continue
                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        copied += _walk(entry.as_directory(), depth + 1)
                    except Exception:
                        continue
                elif name.lower().endswith(".evtx") and meta.size:
                    target = dest / name
                    if target.exists():
                        target = dest / f"{Path(name).stem}_{copied}.evtx"
                    target.write_bytes(entry.read_random(0, meta.size))
                    copied += 1
            except Exception:
                continue
        return copied

    def _extract_from_fs(fs: object) -> int:
        try:
            return _drain_dir(fs.open_dir(path="/Windows/System32/winevt/Logs"))
        except OSError:
            return _walk(fs.open_dir(path="/"))

    # ---- main extraction ----

    # pyewf.glob() resolves multi-segment images (.E01, .E02, …) automatically.
    segments = pyewf.glob(str(first_segment))
    ewf_handle = pyewf.open(segments)
    img = _EwfImgInfo(ewf_handle)

    copied = 0
    try:
        volume = pytsk3.Volume_Info(img)
        for part in volume:
            # Skip tiny metadata / unallocated entries (< 2048 sectors ≈ 1 MB)
            if part.len < 2048:
                continue
            try:
                fs = pytsk3.FS_Info(img, offset=part.start * 512)
            except OSError:
                continue
            if fs.info.ftype not in (pytsk3.TSK_FS_TYPE_NTFS, pytsk3.TSK_FS_TYPE_NTFS_DETECT):
                continue
            copied += _extract_from_fs(fs)
            if copied:
                break
    except OSError:
        # No partition table — treat the image as a raw filesystem volume.
        fs = pytsk3.FS_Info(img)
        copied = _extract_from_fs(fs)

    if copied == 0:
        raise EvidenceError("No .evtx files found in E01 image")


# ---------------------------------------------------------------------------
# Windows path
# ---------------------------------------------------------------------------

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
