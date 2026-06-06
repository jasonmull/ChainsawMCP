"""Setup helpers: install Chainsaw binary and Sigma rules for SIFT environments."""

import json
import os
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

CHAINSAW_REPO = "WithSecureLabs/chainsaw"
SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma"
ASSET_NAME = "chainsaw_all_platforms+rules+examples.zip"

DEFAULT_CHAINSAW_DIR = Path("/opt/chainsaw")
DEFAULT_SIGMA_DIR = Path("/opt/sigma")


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
    """Install Chainsaw and Sigma rules if not already present.

    When a target directory is not writable (e.g. /opt requires sudo), emits
    exact shell commands for the analyst to run manually rather than escalating
    privileges silently.

    Returns a structured dict describing what was done, any manual steps
    required, and the resolved config paths written to ~/.chainsawmcp/config.json.
    """
    results: dict[str, dict] = {}
    sudo_instructions: list[str] = []
    config_paths: dict[str, str] = {}

    # --- Chainsaw binary + rules + mappings ---
    _setup_chainsaw(chainsaw_dir, results, sudo_instructions, config_paths)

    # --- Sigma rules ---
    _setup_sigma(sigma_dir, results, sudo_instructions, config_paths)

    # --- Persist resolved paths ---
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


def _latest_asset_url() -> str:
    """Fetch download URL for the all-platforms zip from the latest Chainsaw release."""
    api_url = f"https://api.github.com/repos/{CHAINSAW_REPO}/releases/latest"
    req = Request(
        api_url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "ChainsawMCP"},
    )
    with urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    for asset in data.get("assets", []):
        if asset["name"] == ASSET_NAME:
            return asset["browser_download_url"]
    tag = data.get("tag_name", "unknown")
    raise RuntimeError(
        f"Asset '{ASSET_NAME}' not found in Chainsaw release {tag}. "
        f"Available: {[a['name'] for a in data.get('assets', [])]}"
    )


def _extract_chainsaw(zip_path: Path, dest: Path) -> None:
    """Extract the Linux x86_64 binary, rules/, and mappings/ from the all-platforms zip."""
    dest.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()

        # Locate the Linux x86_64 binary — try most-specific match first
        binary_entry = None
        for candidate in names:
            base = candidate.split("/")[-1]
            if base in ("chainsaw", "chainsaw_x86_64-unknown-linux-gnu"):
                lower = candidate.lower()
                if "linux" in lower and "x86_64" in lower and not candidate.endswith("/"):
                    binary_entry = candidate
                    break
        if binary_entry is None:
            # Fallback: any entry named exactly "chainsaw" (not a dir, not .exe)
            binary_entry = next(
                (n for n in names if n.split("/")[-1] == "chainsaw" and not n.endswith("/")),
                None,
            )
        if binary_entry is None:
            raise RuntimeError(
                f"Could not find chainsaw Linux binary in zip. Entries: {names[:30]}"
            )

        # Write binary and make executable
        binary_dest = dest / "chainsaw"
        binary_dest.write_bytes(zf.read(binary_entry))
        binary_dest.chmod(
            binary_dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
        )

        # Determine path prefix used for rules/ and mappings/ in the zip
        prefix = ""
        for pfx in ("", "chainsaw/"):
            if any(n.startswith(f"{pfx}rules/") for n in names):
                prefix = pfx
                break

        # Extract rules/ and mappings/
        for name in names:
            rel = name[len(prefix):]
            if not rel or rel.endswith("/"):
                continue
            if rel.startswith("rules/") or rel.startswith("mappings/"):
                out = dest / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(zf.read(name))


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
        try:
            url = _latest_asset_url()
        except Exception as e:
            url = f"<fetch failed: {e}> — find the URL at https://github.com/WithSecureLabs/chainsaw/releases"
        sudo_instructions.append(
            f"# Install Chainsaw to {chainsaw_dir}\n"
            f"sudo mkdir -p {chainsaw_dir}\n"
            f"cd /tmp && curl -L -o chainsaw.zip '{url}'\n"
            f"sudo unzip -o chainsaw.zip -d /tmp/chainsaw_extract\n"
            f"sudo find /tmp/chainsaw_extract -name 'chainsaw' -not -name '*.exe' "
            f"! -path '*windows*' ! -path '*darwin*' "
            f"-exec cp {{}} {chainsaw_dir}/chainsaw \\;\n"
            f"sudo chmod +x {chainsaw_dir}/chainsaw\n"
            f"sudo cp -r /tmp/chainsaw_extract/*/rules {chainsaw_dir}/\n"
            f"sudo cp -r /tmp/chainsaw_extract/*/mappings {chainsaw_dir}/\n"
            f"sudo rm -rf /tmp/chainsaw.zip /tmp/chainsaw_extract"
        )
        results["chainsaw"] = {
            "status": "needs_sudo",
            "path": str(chainsaw_dir),
            "action": "cannot write to install directory — see sudo_instructions",
        }
    else:
        try:
            url = _latest_asset_url()
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                tmp_path = Path(tmp.name)
            try:
                req = Request(url, headers={"User-Agent": "ChainsawMCP"})
                with urlopen(req, timeout=120) as resp, tmp_path.open("wb") as f:
                    shutil.copyfileobj(resp, f)
                _extract_chainsaw(tmp_path, chainsaw_dir)
                results["chainsaw"] = {
                    "status": "installed", "path": str(chainsaw_dir),
                    "action": f"downloaded {ASSET_NAME} and extracted",
                }
            finally:
                tmp_path.unlink(missing_ok=True)
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
