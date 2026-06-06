"""Setup helpers: install Chainsaw binary and Sigma rules for SIFT environments."""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

CHAINSAW_REPO_URL = "https://github.com/WithSecureLabs/chainsaw"
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
    binary = chainsaw_dir / "bin" / "chainsaw"
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


def _build_and_install_chainsaw(chainsaw_dir: Path) -> None:
    """Clone the Chainsaw repo, compile with cargo, copy rules and mappings."""
    with tempfile.TemporaryDirectory(prefix="chainsaw_src_") as tmp:
        src = Path(tmp)

        subprocess.run(
            ["git", "clone", "--depth=1", CHAINSAW_REPO_URL, str(src)],
            check=True,
            capture_output=True,
            timeout=300,
        )

        # cargo install builds in release mode by default.
        # --root sets the output prefix; binary lands at <root>/bin/chainsaw.
        chainsaw_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["cargo", "install", "--path", str(src), "--root", str(chainsaw_dir)],
            check=True,
            capture_output=True,
            timeout=1800,
        )

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
    binary = chainsaw_dir / "bin" / "chainsaw"
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
            f"sudo mkdir -p {chainsaw_dir}/bin\n"
            f"git clone --depth=1 {CHAINSAW_REPO_URL} /tmp/chainsaw_src\n"
            f"cargo install --path /tmp/chainsaw_src --root {chainsaw_dir}\n"
            f"sudo cp -r /tmp/chainsaw_src/rules {chainsaw_dir}/\n"
            f"sudo cp -r /tmp/chainsaw_src/mappings {chainsaw_dir}/\n"
            f"rm -rf /tmp/chainsaw_src"
        )
        results["chainsaw"] = {
            "status": "needs_sudo",
            "path": str(chainsaw_dir),
            "action": "cannot write to install directory — see sudo_instructions",
        }
    elif not _cargo_available():
        results["chainsaw"] = {
            "status": "error",
            "path": str(chainsaw_dir),
            "action": (
                "cargo not found — install Rust first: "
                "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
            ),
        }
    else:
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
