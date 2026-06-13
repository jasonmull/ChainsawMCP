"""Setup helpers: install Chainsaw binary and Sigma rules for SIFT environments."""

import io
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

CHAINSAW_REPO_URL = "https://github.com/WithSecureLabs/chainsaw"
CHAINSAW_RELEASES_API = "https://api.github.com/repos/WithSecureLabs/chainsaw/releases/latest"
SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma"

# User-writable XDG paths — no sudo required on a standard Linux install.
DEFAULT_CHAINSAW_DIR = Path.home() / ".local" / "share" / "chainsaw"
DEFAULT_SIGMA_DIR = Path.home() / ".local" / "share" / "sigma"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_environment(
    chainsaw_dir: Path = DEFAULT_CHAINSAW_DIR,
    sigma_dir: Path = DEFAULT_SIGMA_DIR,
) -> dict:
    """Return the current installation status without making any changes."""
    binary = chainsaw_dir / "chainsaw"
    rules = chainsaw_dir / "rules"
    mapping = chainsaw_dir / "mappings" / "sigma-event-logs-all.yml"
    return {
        "chainsaw_binary": {"path": str(binary), "ok": binary.exists() and os.access(binary, os.X_OK)},
        "chainsaw_rules":  {"path": str(rules),  "ok": rules.is_dir() and _nonempty(rules)},
        "chainsaw_mapping":{"path": str(mapping),"ok": mapping.exists()},
        "sigma_rules":     {"path": str(sigma_dir), "ok": sigma_dir.is_dir() and _nonempty(sigma_dir)},
    }


def setup_environment(
    chainsaw_dir: Path = DEFAULT_CHAINSAW_DIR,
    sigma_dir: Path = DEFAULT_SIGMA_DIR,
) -> dict:
    """Install Chainsaw (compiled via cargo) and Sigma rules if not already present.

    Chainsaw is built from source: the repo is cloned to a temp directory,
    `cargo install` compiles it in release mode and installs the binary to
    <chainsaw_dir>/bin/chainsaw, then rules/ and mappings/ are copied from
    the clone.

    When a target directory is not writable, emits exact shell commands for
    the analyst to run manually rather than escalating privileges silently.

    Returns a structured dict describing what was done, any manual steps
    required, and the resolved config paths written to ~/.chainsawmcp/config.json.
    """
    results: dict[str, dict] = {}
    sudo_instructions: list[str] = []
    config_paths: dict[str, str] = {}

    _setup_chainsaw(chainsaw_dir, results, sudo_instructions, config_paths)
    _setup_sigma(sigma_dir, results, sudo_instructions, config_paths)

    saved_config = None
    if config_paths:
        from .config import save_config, get_config_path
        save_config(config_paths)
        saved_config = str(get_config_path())

    ready = all(
        r.get("status") in ("ok", "installed")
        for r in results.values()
        if isinstance(r, dict)
    )

    return {
        "results": results,
        "sudo_instructions": sudo_instructions or None,
        "config_saved": saved_config,
        "ready": ready,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _nonempty(path: Path) -> bool:
    try:
        next(path.iterdir())
        return True
    except (StopIteration, OSError):
        return False


def _can_write(path: Path) -> bool:
    """Check write permission on path or its nearest existing ancestor."""
    check = path
    while not check.exists():
        check = check.parent
    return os.access(check, os.W_OK)


def _cargo_available() -> bool:
    return shutil.which("cargo") is not None


def _cargo_version() -> tuple[int, int, int] | None:
    try:
        result = subprocess.run(["cargo", "--version"], capture_output=True, text=True, timeout=10)
        m = re.search(r"cargo (\d+)\.(\d+)\.(\d+)", result.stdout)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except Exception:
        pass
    return None


def _cargo_supports_edition2024() -> bool:
    ver = _cargo_version()
    return ver is not None and ver >= (1, 85, 0)


def _get_prebuilt_asset_url() -> str:
    """Query the GitHub releases API and return the download URL for the platform binary."""
    import httpx
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        asset_tag = "x86_64-unknown-linux-gnu"
    elif machine in ("aarch64", "arm64"):
        asset_tag = "aarch64-unknown-linux-gnu"
    else:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    resp = httpx.get(CHAINSAW_RELEASES_API, timeout=30, follow_redirects=True)
    resp.raise_for_status()
    release = resp.json()
    for asset in release.get("assets", []):
        name = asset["name"]
        if asset_tag in name and name.endswith(".tar.gz"):
            return asset["browser_download_url"]
    raise RuntimeError(
        f"No pre-built asset matching '{asset_tag}' in release {release.get('tag_name')}"
    )


def _download_prebuilt_chainsaw(chainsaw_dir: Path) -> None:
    """Download the latest pre-built Chainsaw release and extract it to chainsaw_dir.

    The platform-specific tarball contains only the binary and mappings.
    rules/ are fetched via a shallow git clone of the chainsaw repo.
    """
    import httpx

    url = _get_prebuilt_asset_url()
    resp = httpx.get(url, timeout=300, follow_redirects=True)
    resp.raise_for_status()

    chainsaw_dir.mkdir(parents=True, exist_ok=True)

    base = chainsaw_dir.resolve()
    with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
        for member in tar.getmembers():
            parts = Path(member.name).parts
            if len(parts) < 2:
                continue
            rel = Path(*parts[1:])  # strip leading "chainsaw/" directory component
            dest = chainsaw_dir / rel
            # Refuse any member that resolves outside the install dir (path traversal),
            # and skip anything that is not a plain file or directory (symlinks, devices).
            try:
                resolved = dest.resolve()
            except OSError:
                continue
            if resolved != base and base not in resolved.parents:
                raise RuntimeError(
                    f"Refusing to extract archive member outside install dir: {member.name}"
                )
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                dest.parent.mkdir(parents=True, exist_ok=True)
                f = tar.extractfile(member)
                if f is not None:
                    dest.write_bytes(f.read())
                if rel.parts[-1] == "chainsaw":
                    dest.chmod(dest.stat().st_mode | 0o111)
            else:
                continue

    # Clone rules/ from the repo — not included in the platform tarball.
    rules_dest = chainsaw_dir / "rules"
    if not (rules_dest.is_dir() and _nonempty(rules_dest)):
        with tempfile.TemporaryDirectory(prefix="chainsaw_rules_") as tmp:
            src = Path(tmp)
            subprocess.run(
                ["git", "clone", "--depth=1", CHAINSAW_REPO_URL, str(src)],
                check=True,
                capture_output=True,
                timeout=300,
            )
            for subdir in ("rules", "mappings"):
                src_sub = src / subdir
                dst_sub = chainsaw_dir / subdir
                if src_sub.is_dir():
                    if dst_sub.exists():
                        shutil.rmtree(dst_sub)
                    shutil.copytree(src_sub, dst_sub)


def _build_and_install_chainsaw(chainsaw_dir: Path) -> None:
    """Clone the Chainsaw repo, compile with cargo build --release, copy binary and data files."""
    with tempfile.TemporaryDirectory(prefix="chainsaw_src_") as tmp:
        src = Path(tmp)

        subprocess.run(
            ["git", "clone", "--depth=1", CHAINSAW_REPO_URL, str(src)],
            check=True,
            capture_output=True,
            timeout=300,
        )

        subprocess.run(
            ["cargo", "build", "--release"],
            cwd=str(src),
            check=True,
            capture_output=True,
            timeout=1800,
        )

        chainsaw_dir.mkdir(parents=True, exist_ok=True)

        # Copy compiled binary.
        built_binary = src / "target" / "release" / "chainsaw"
        dest_binary = chainsaw_dir / "chainsaw"
        shutil.copy2(str(built_binary), str(dest_binary))
        dest_binary.chmod(dest_binary.stat().st_mode | 0o111)

        # Copy rules/ and mappings/ from the source tree alongside the binary.
        for subdir in ("rules", "mappings"):
            src_subdir = src / subdir
            dst_subdir = chainsaw_dir / subdir
            if src_subdir.is_dir():
                if dst_subdir.exists():
                    shutil.rmtree(dst_subdir)
                shutil.copytree(src_subdir, dst_subdir)


def _setup_chainsaw(
    chainsaw_dir: Path,
    results: dict,
    sudo_instructions: list,
    config_paths: dict,
) -> None:
    binary = chainsaw_dir / "chainsaw"
    rules_dir = chainsaw_dir / "rules"
    mapping_file = chainsaw_dir / "mappings" / "sigma-event-logs-all.yml"
    all_present = (
        binary.exists() and os.access(binary, os.X_OK)
        and rules_dir.is_dir() and _nonempty(rules_dir)
        and mapping_file.exists()
    )

    if all_present:
        results["chainsaw"] = {
            "status": "ok", "path": str(chainsaw_dir), "action": "already installed",
        }
    elif not _can_write(chainsaw_dir):
        sudo_instructions.append(
            f"# Install Chainsaw to {chainsaw_dir} (requires write access)\n"
            f"git clone --depth=1 {CHAINSAW_REPO_URL} /tmp/chainsaw_src\n"
            f"cd /tmp/chainsaw_src && cargo build --release\n"
            f"sudo mkdir -p {chainsaw_dir}\n"
            f"sudo cp /tmp/chainsaw_src/target/release/chainsaw {chainsaw_dir}/chainsaw\n"
            f"sudo chmod +x {chainsaw_dir}/chainsaw\n"
            f"sudo cp -r /tmp/chainsaw_src/rules {chainsaw_dir}/\n"
            f"sudo cp -r /tmp/chainsaw_src/mappings {chainsaw_dir}/\n"
            f"rm -rf /tmp/chainsaw_src"
        )
        results["chainsaw"] = {
            "status": "needs_sudo",
            "path": str(chainsaw_dir),
            "action": "cannot write to install directory — see sudo_instructions",
        }
    elif _cargo_available() and _cargo_supports_edition2024():
        try:
            _build_and_install_chainsaw(chainsaw_dir)
            results["chainsaw"] = {
                "status": "installed",
                "path": str(chainsaw_dir),
                "action": "cloned from GitHub and compiled with cargo",
            }
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode(errors="replace")[:500] if e.stderr else ""
            results["chainsaw"] = {
                "status": "error",
                "path": str(chainsaw_dir),
                "action": f"build failed: {stderr}",
            }
        except Exception as e:
            results["chainsaw"] = {
                "status": "error", "path": str(chainsaw_dir),
                "action": f"install failed: {e}",
            }
    else:
        # cargo missing or too old (edition2024 requires 1.85+) — download pre-built binary.
        cargo_ver = _cargo_version()
        reason = (
            f"cargo {'.'.join(str(x) for x in cargo_ver)} < 1.85 (edition2024)"
            if cargo_ver else "cargo not found"
        )
        try:
            _download_prebuilt_chainsaw(chainsaw_dir)
            results["chainsaw"] = {
                "status": "installed",
                "path": str(chainsaw_dir),
                "action": f"downloaded pre-built binary from GitHub ({reason})",
            }
        except Exception as e:
            results["chainsaw"] = {
                "status": "error", "path": str(chainsaw_dir),
                "action": f"pre-built download failed ({reason}): {e}",
            }

    if results["chainsaw"]["status"] in ("ok", "installed"):
        config_paths["chainsaw_bin"] = str(binary)
        config_paths["rules_path"] = str(rules_dir)
        config_paths["mapping_path"] = str(mapping_file)


def _setup_sigma(
    sigma_dir: Path,
    results: dict,
    sudo_instructions: list,
    config_paths: dict,
) -> None:
    if sigma_dir.is_dir() and _nonempty(sigma_dir):
        results["sigma"] = {
            "status": "ok", "path": str(sigma_dir), "action": "already installed",
        }
    elif not _can_write(sigma_dir):
        sudo_instructions.append(
            f"# Clone Sigma rules to {sigma_dir}\n"
            f"sudo git clone --depth=1 {SIGMA_REPO_URL} {sigma_dir}"
        )
        results["sigma"] = {
            "status": "needs_sudo",
            "path": str(sigma_dir),
            "action": "cannot write to install directory — see sudo_instructions",
        }
    else:
        try:
            sigma_dir.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth=1", SIGMA_REPO_URL, str(sigma_dir)],
                check=True,
                capture_output=True,
                timeout=300,
            )
            results["sigma"] = {
                "status": "installed", "path": str(sigma_dir),
                "action": "cloned from GitHub (depth=1)",
            }
        except subprocess.CalledProcessError as e:
            results["sigma"] = {
                "status": "error", "path": str(sigma_dir),
                "action": f"git clone failed: {e.stderr.decode(errors='replace')[:300]}",
            }
        except Exception as e:
            results["sigma"] = {
                "status": "error", "path": str(sigma_dir),
                "action": f"clone failed: {e}",
            }

    if results["sigma"]["status"] in ("ok", "installed"):
        config_paths["sigma_path"] = str(sigma_dir)
