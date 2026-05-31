"""Evidence preparation: validate EVTX directories and mount E01 images."""

import re
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


def stage_evtx(source: Path, dest: Path) -> None:
    """Extract/copy EVTXs from source directly into dest. No temp dirs created.

    For E01 images this is the preferred path for background jobs — EVTXs land
    in the job's own directory so they persist alongside hunt results and require
    no separate cleanup step.
    """
    if not source.exists():
        raise EvidenceError(f"Path does not exist: {source}")
    dest.mkdir(parents=True, exist_ok=True)

    if source.is_dir():
        _copy_evtx_files(source, dest)
    elif source.suffix.lower() in {".e01", ".ex01"}:
        if is_windows():
            _stage_e01_windows(source, dest)
        else:
            _extract_e01(source, dest)
    else:
        raise EvidenceError(
            f"Unsupported evidence type: {source.suffix}. Expected a directory or .E01 image."
        )


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
        _extract_e01(first_segment, evtx_stage)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise

    return PreparedEvidence(evtx_dir=evtx_stage, _temp_dir=tmp)


def _extract_e01(first_segment: Path, dest: Path) -> None:
    """
    Try pytsk3 Python API first, then fall back to TSK CLI tools (fls/icat).
    Both approaches are rootless — no FUSE or kernel mounts required.
    """
    pytsk3_exc: Exception | None = None

    try:
        _extract_e01_rootless(first_segment, dest)
        return
    except (ImportError, EvidenceError, OSError) as exc:
        # ImportError  → pytsk3 not installed
        # EvidenceError → pytsk3 can't parse the image (EWF not supported, etc.)
        # OSError      → raw TSK error not wrapped above (belt-and-suspenders)
        pytsk3_exc = exc

    if shutil.which("fls") and shutil.which("icat"):
        _extract_e01_via_tsk_cli(first_segment, dest)
        return

    raise EvidenceError(
        f"Cannot extract E01 image — all methods failed.\n"
        f"  pytsk3: {pytsk3_exc}\n"
        "Install TSK CLI tools: apt install sleuthkit\n"
        "Or install pytsk3 with EWF support: apt install python3-pytsk3 libewf-dev"
    )


def _extract_e01_rootless(first_segment: Path, dest: Path) -> None:
    """
    Extract EVTX files from an E01 image entirely in-process.

    Uses pytsk3 (The Sleuth Kit Python bindings) to open and parse the image.
    TSK has native EWF/E01 support — including multi-segment images — when
    built with libewf (the default for most system-packaged distributions).
    No FUSE, no root, no kernel-level mounts required.
    """
    try:
        import pytsk3  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "pytsk3 is required for E01 extraction. "
            "Install with: pip install pytsk3\n"
            "Note: EWF/E01 support requires libtsk to be compiled with libewf. "
            "System packages (e.g. apt install python3-pytsk3) typically include it."
        ) from exc

    # TSK opens EWF/E01 files natively and resolves multi-segment images
    # (.E01, .E02, …) automatically when given the first segment path.
    try:
        img = pytsk3.Img_Info(str(first_segment))
    except OSError as exc:
        raise EvidenceError(
            f"Failed to open E01 image '{first_segment}': {exc}\n"
            "If pytsk3 was not compiled with libewf support, install the system "
            "package instead: apt install python3-pytsk3 libewf-dev"
        ) from exc

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
        # No partition table — image is a raw partition (no MBR/GPT), try offset 0.
        try:
            fs = pytsk3.FS_Info(img)
        except OSError as exc:
            raise EvidenceError(f"pytsk3 cannot parse filesystem: {exc}") from exc
        copied = _extract_from_fs(fs)

    if copied == 0:
        raise EvidenceError("No .evtx files found in E01 image")


# ---------------------------------------------------------------------------
# TSK CLI fallback  (fls + icat from the sleuthkit package)
# ---------------------------------------------------------------------------

# fls output:  "r/r 12345-128-1:\tWindows/System32/winevt/Logs/Security.evtx"
_FLS_RE = re.compile(r"^r/r\s+(\S+):\s+(.*)", re.IGNORECASE)
# mmls NTFS partition line: leading slot, start, end, length, description
_MMLS_NTFS_RE = re.compile(r"^\d+:\s+\S+\s+(\d+)\s+\d+\s+(\d+)\s+.*NTFS", re.IGNORECASE)


def _extract_e01_via_tsk_cli(first_segment: Path, dest: Path) -> None:
    """
    Extract EVTX files using TSK CLI tools (fls + icat).

    Requires the 'sleuthkit' package (apt install sleuthkit), which is
    always compiled with libewf support on standard distros.  No root needed.
    """
    offset = _ntfs_offset_via_mmls(first_segment)

    fls_cmd = ["fls", "-r", "-p"]
    if offset is not None:
        fls_cmd += ["-o", str(offset)]
    fls_cmd.append(str(first_segment))

    fls = subprocess.run(fls_cmd, capture_output=True, text=True)
    if fls.returncode != 0:
        raise EvidenceError(
            f"fls failed on '{first_segment}': {fls.stderr.strip()}\n"
            "Ensure sleuthkit was compiled with libewf: apt install sleuthkit"
        )

    copied = 0
    for line in fls.stdout.splitlines():
        if ".evtx" not in line.lower():
            continue
        m = _FLS_RE.match(line)
        if not m:
            continue
        inode, filepath = m.group(1), m.group(2).strip()

        icat_cmd = ["icat"]
        if offset is not None:
            icat_cmd += ["-o", str(offset)]
        icat_cmd += [str(first_segment), inode]

        data = subprocess.run(icat_cmd, capture_output=True)
        if data.returncode != 0 or not data.stdout:
            continue

        target = dest / Path(filepath).name
        if target.exists():
            target = dest / f"{Path(filepath).stem}_{copied}.evtx"
        target.write_bytes(data.stdout)
        copied += 1

    if copied == 0:
        raise EvidenceError("No .evtx files found in E01 image via fls/icat")


def _ntfs_offset_via_mmls(image: Path) -> int | None:
    """Return the start sector of the largest NTFS partition, or None."""
    if not shutil.which("mmls"):
        return None
    r = subprocess.run(["mmls", str(image)], capture_output=True, text=True)
    if r.returncode != 0:
        return None

    best_start: int | None = None
    best_size = 0
    for line in r.stdout.splitlines():
        m = _MMLS_NTFS_RE.match(line)
        if not m:
            continue
        start, size = int(m.group(1)), int(m.group(2))
        if size > best_size:
            best_size = size
            best_start = start
    return best_start


# ---------------------------------------------------------------------------
# Windows path
# ---------------------------------------------------------------------------

def _stage_e01_windows(first_segment: Path, dest: Path) -> None:
    """Mount with AIM, copy EVTXs to dest, then unmount. No temp dir needed."""
    aim = _find_aim_cli()
    if not aim:
        raise EvidenceError(
            "Arsenal Image Mounter (aim_cli.exe) not found. Add it to PATH or set AIM_CLI env var."
        )
    drive = _pick_free_drive()
    try:
        _run([str(aim), "/mount", f"/filename={first_segment}", f"/drive={drive}", "/readonly"])
        _copy_evtx_files(Path(f"{drive}:\\"), dest)
    finally:
        subprocess.run([str(aim), "/unmount", f"/drive={drive}"], capture_output=True)


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
