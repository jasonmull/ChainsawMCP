"""Configuration and environment handling."""

import json
import os
import platform
from pathlib import Path


def get_config_path() -> Path:
    return Path.home() / ".chainsawmcp" / "config.json"


def load_saved_config() -> dict:
    """Load persisted config written by setup_environment."""
    try:
        return json.loads(get_config_path().read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(updates: dict) -> None:
    """Merge updates into the persisted config file."""
    p = get_config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    existing = load_saved_config()
    existing.update(updates)
    p.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def get_ollama_base_url() -> str:
    return os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")


def get_ollama_model() -> str:
    return os.environ.get("OLLAMA_MODEL", "foundationsec:8b")


def get_chainsaw_binary() -> Path:
    """Return the Chainsaw binary path. Precedence: env var → saved config → PATH."""
    override = os.environ.get("CHAINSAW_BIN")
    if override:
        return Path(override)
    saved = load_saved_config().get("chainsaw_bin")
    if saved:
        return Path(saved)
    name = "chainsaw.exe" if platform.system() == "Windows" else "chainsaw"
    return Path(name)


def get_rules_path() -> Path | None:
    """Precedence: env var → saved config → None."""
    val = os.environ.get("CHAINSAW_RULES")
    if val:
        return Path(val)
    saved = load_saved_config().get("rules_path")
    return Path(saved) if saved else None


def get_sigma_path() -> Path | None:
    """Precedence: env var → saved config → None."""
    val = os.environ.get("CHAINSAW_SIGMA")
    if val:
        return Path(val)
    saved = load_saved_config().get("sigma_path")
    return Path(saved) if saved else None


def get_mapping_path() -> Path | None:
    """Precedence: env var → saved config → None."""
    val = os.environ.get("CHAINSAW_MAPPING")
    if val:
        return Path(val)
    saved = load_saved_config().get("mapping_path")
    return Path(saved) if saved else None


def get_hunt_timeout() -> int:
    """Seconds before giving up on a chainsaw hunt subprocess. Override with CHAINSAW_TIMEOUT."""
    try:
        return int(os.environ.get("CHAINSAW_TIMEOUT", "1800"))
    except ValueError:
        return 1800


def get_output_dir() -> Path:
    """Directory where Chainsaw JSON output is written. Override with CHAINSAW_OUTPUT_DIR."""
    val = os.environ.get("CHAINSAW_OUTPUT_DIR")
    if val:
        return Path(val)
    import tempfile
    return Path(tempfile.gettempdir()) / "chainsawmcp"


def get_jobs_dir() -> Path:
    """Directory where detached hunt job state and results are stored. Override with CHAINSAWMCP_JOBS_DIR."""
    val = os.environ.get("CHAINSAWMCP_JOBS_DIR")
    if val:
        return Path(val)
    import tempfile
    return Path(tempfile.gettempdir()) / "chainsawmcp_jobs"


def get_webhook_url() -> str | None:
    """Webhook URL to POST when a detached hunt completes. Set CHAINSAWMCP_WEBHOOK_URL."""
    return os.environ.get("CHAINSAWMCP_WEBHOOK_URL") or None


def get_batch_size() -> int:
    try:
        return int(os.environ.get("ENRICHMENT_BATCH_SIZE", "20"))
    except ValueError:
        return 20


def get_http_host() -> str:
    return os.environ.get("CHAINSAWMCP_HOST", "127.0.0.1")


def get_http_port() -> int:
    try:
        return int(os.environ.get("CHAINSAWMCP_PORT", "8000"))
    except ValueError:
        return 8000


def is_windows() -> bool:
    return platform.system() == "Windows"
