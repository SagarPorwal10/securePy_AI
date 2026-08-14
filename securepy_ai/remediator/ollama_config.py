"""
ollama_config.py
----------------
Centralised configuration for the Ollama LLM connection.

Resolution priority (highest → lowest):
  1. Explicit kwargs passed to OllamaConfig(...)
  2. Environment variables  (OLLAMA_HOST, OLLAMA_PORT, OLLAMA_MODEL, OLLAMA_TIMEOUT)
  3. Values in a .env file  (looked up next to the project root)
  4. Built-in defaults      (localhost:11434)

Usage — load from environment / .env:
    config = OllamaConfig.from_env()

Usage — override individual fields (e.g. from CLI flags):
    config = OllamaConfig.from_env(host="192.168.1.50", model="qwen2.5-coder:7b")

Usage — build base_url:
    config.base_url   # -> "http://192.168.1.50:11434"
"""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 11434
_DEFAULT_MODEL = "codellama:13b"
_DEFAULT_TIMEOUT = 180


# ---------------------------------------------------------------------------
# .env loader  (stdlib-only, no python-dotenv dependency)
# ---------------------------------------------------------------------------

def _load_dotenv(dotenv_path: pathlib.Path) -> dict:
    """
    Parses a .env file and returns a dict of key→value pairs.

    Supports:
      - KEY=VALUE
      - KEY="VALUE"  /  KEY='VALUE'
      - # comment lines
      - blank lines
    """
    env: dict = {}

    if not dotenv_path.is_file():
        return env

    with dotenv_path.open(encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()

            # skip blanks and comments
            if not line or line.startswith("#"):
                continue

            if "=" not in line:
                continue

            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if key:
                env[key] = value

    return env


def _find_dotenv() -> pathlib.Path:
    """
    Searches upward from this file for a .env file, stopping at the
    filesystem root.  Returns the first one found, or a non-existent
    path if none is found.
    """
    start = pathlib.Path(__file__).resolve().parent

    for parent in [start, *start.parents]:
        candidate = parent / ".env"
        if candidate.is_file():
            return candidate

    # fall back to CWD/.env (common convention)
    return pathlib.Path.cwd() / ".env"


# ---------------------------------------------------------------------------
# OllamaConfig
# ---------------------------------------------------------------------------

@dataclass
class OllamaConfig:
    """
    Holds all settings needed to connect to an Ollama server.

    Attributes:
        host     : IP address or hostname of the Ollama machine.
        port     : TCP port Ollama is listening on.
        model    : Model tag to use (e.g. "codellama:13b").
        timeout  : Request timeout in seconds.
        scheme   : "http" or "https" (almost always "http" for local/LAN).
    """

    host: str = _DEFAULT_HOST
    port: int = _DEFAULT_PORT
    model: str = _DEFAULT_MODEL
    timeout: int = _DEFAULT_TIMEOUT
    scheme: str = "http"

    # Path to the .env file that was loaded (informational only).
    _dotenv_path: Optional[pathlib.Path] = field(default=None, repr=False, compare=False)

    # -----------------------------------------------------------------------
    # Derived properties
    # -----------------------------------------------------------------------

    @property
    def base_url(self) -> str:
        """Returns the full Ollama API base URL, e.g. http://192.168.1.50:11434"""
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def is_remote(self) -> bool:
        """True when the configured host is not the local machine."""
        return self.host not in ("127.0.0.1", "localhost", "::1")

    # -----------------------------------------------------------------------
    # Factory
    # -----------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
        scheme: Optional[str] = None,
        dotenv_path: Optional[pathlib.Path] = None,
    ) -> "OllamaConfig":
        """
        Build an OllamaConfig by merging (in priority order):
          1. Explicit kwargs
          2. OS environment variables
          3. .env file values
          4. Built-in defaults

        Parameters
        ----------
        host, port, model, timeout, scheme
            Optional overrides (e.g. from CLI flags).  Any value that is
            not None takes precedence over env vars / .env / defaults.
        dotenv_path
            Explicit path to a .env file.  If omitted, the file is
            discovered automatically by walking up from the package root.
        """
        # --- load .env ---
        env_file = dotenv_path or _find_dotenv()
        dotenv_values = _load_dotenv(env_file)

        def _resolve_str(kwarg: Optional[str], env_key: str, default: str) -> str:
            if kwarg is not None:
                return kwarg
            return os.environ.get(env_key) or dotenv_values.get(env_key) or default

        def _resolve_int(kwarg: Optional[int], env_key: str, default: int) -> int:
            if kwarg is not None:
                return kwarg
            raw = os.environ.get(env_key) or dotenv_values.get(env_key)
            if raw is not None:
                try:
                    return int(raw)
                except ValueError:
                    pass
            return default

        resolved_host    = _resolve_str(host,    "OLLAMA_HOST",    _DEFAULT_HOST)
        resolved_port    = _resolve_int(port,    "OLLAMA_PORT",    _DEFAULT_PORT)
        resolved_model   = _resolve_str(model,   "OLLAMA_MODEL",   _DEFAULT_MODEL)
        resolved_timeout = _resolve_int(timeout, "OLLAMA_TIMEOUT", _DEFAULT_TIMEOUT)
        resolved_scheme  = _resolve_str(scheme,  "OLLAMA_SCHEME",  "http")

        return cls(
            host=resolved_host,
            port=resolved_port,
            model=resolved_model,
            timeout=resolved_timeout,
            scheme=resolved_scheme,
            _dotenv_path=env_file if env_file.is_file() else None,
        )

    # -----------------------------------------------------------------------
    # Display
    # -----------------------------------------------------------------------

    def describe(self) -> str:
        """Returns a human-readable summary of the active config."""
        location = "remote" if self.is_remote else "local"
        source = f"  .env: {self._dotenv_path}" if self._dotenv_path else "  .env: not found (using env vars / defaults)"

        return (
            f"Ollama connection ({location})\n"
            f"  URL    : {self.base_url}\n"
            f"  Model  : {self.model}\n"
            f"  Timeout: {self.timeout}s\n"
            f"{source}"
        )
