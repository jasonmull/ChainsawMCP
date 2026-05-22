"""Configuration and environment handling."""

import os
import platform
from pathlib import Path


def get_ollama_base_url() -> str:
    return os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")


def get_ollama_model() -> str:
    return os.environ.get("OLLAMA_MODEL", "foundationsec:8b")


def get_chainsaw_binary() -> Path:
    """Return the platform-appropriate Chainsaw binary name."""
    name = "chainsaw.exe" if platform.system() == "Windows" else "chainsaw"
    # Allow override via env var; otherwise expect it on PATH
    override = os.environ.get("CHAINSAW_BIN")
    if override:
        return Path(override)
    return Path(name)


def get_rules_path() -> Path | None:
    val = os.environ.get("CHAINSAW_RULES")
    return Path(val) if val else None


def get_sigma_path() -> Path | None:
    val = os.environ.get("CHAINSAW_SIGMA")
    return Path(val) if val else None


def get_mapping_path() -> Path | None:
    val = os.environ.get("CHAINSAW_MAPPING")
    return Path(val) if val else None


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
