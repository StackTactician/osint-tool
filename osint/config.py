"""
osint/config.py

Configuration management for the OSINT CLI tool.

Priority order (highest wins):
  1. Environment variables (prefixed OSINT_, nested with __)
  2. TOML config file at ~/.osint/config.toml (or CLI-supplied path)
  3. Hardcoded defaults
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------------------------
# Nested config models
# ---------------------------------------------------------------------------


class KeysConfig(BaseSettings):
    """API keys and tokens for third-party services."""

    model_config = SettingsConfigDict(extra="ignore")

    hibp_api_key: str | None = None
    ipinfo_token: str | None = None
    numverify_key: str | None = None
    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    securitytrails_api_key: str | None = None
    hunter_api_key: str | None = None
    anthropic_api_key: str | None = None


class ScanConfig(BaseSettings):
    """Parameters governing how scans execute."""

    model_config = SettingsConfigDict(extra="ignore")

    default_timeout: int = 10
    default_workers: int = 20
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    passive_only: bool = True


class OutputConfig(BaseSettings):
    """Display and formatting preferences."""

    model_config = SettingsConfigDict(extra="ignore")

    color: bool = True
    date_format: str = "%Y-%m-%d %H:%M:%S UTC"


class ProxyConfig(BaseSettings):
    """Proxy and anonymisation settings."""

    model_config = SettingsConfigDict(extra="ignore")

    enabled: bool = False
    url: str = ""
    tor_socks: str = "socks5://127.0.0.1:9050"


class ServerConfig(BaseSettings):
    """REST API server settings."""

    model_config = SettingsConfigDict(extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8080
    # When non-empty, every request must supply a matching X-API-Key header.
    api_key: str = ""


# ---------------------------------------------------------------------------
# Runtime flags (non-persisted, set by CLI at startup)
# ---------------------------------------------------------------------------


@dataclass
class RuntimeConfig:
    """
    Ephemeral flags set from CLI arguments at process startup.

    These are never written to disk or read from env vars — they exist only
    for the lifetime of a single CLI invocation.
    """

    active: bool = False          # run active (non-passive) modules
    stealth: bool = False         # add random delays, rotate UA, limit rate
    tor: bool = False             # route traffic through Tor
    session: str = ""             # current session name
    verbose: bool = False         # debug-level output

    # Extra ad-hoc flags modules may register at startup
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Main Settings class
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_DIR = Path.home() / ".osint"
_DEFAULT_CONFIG_FILE = _DEFAULT_CONFIG_DIR / "config.toml"


class Settings(BaseSettings):
    """
    Root settings object.

    Loaded via Settings.load() rather than direct instantiation so that TOML
    file values can be merged before pydantic-settings processes env vars.
    """

    model_config = SettingsConfigDict(
        env_prefix="OSINT_",
        env_nested_delimiter="__",
        extra="ignore",
        # Do not attempt to read .env files automatically — TOML is the file
        # source and is handled manually in load().
        env_file=None,
    )

    keys: KeysConfig = Field(default_factory=KeysConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)

    # Stored for reference only; not read from env.
    config_file: Path = Field(default=_DEFAULT_CONFIG_FILE, exclude=True)

    # Set after construction by init_settings(); not a pydantic field.
    # Declared here so type checkers know it exists on Settings instances.
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig, exclude=True)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, config_path: Path | None = None) -> "Settings":
        """
        Build a Settings instance by merging three sources.

        Order of application (first = lowest priority):
          1. Hardcoded pydantic defaults
          2. TOML file values (silently skipped if file is absent)
          3. OSINT_* environment variables (handled by pydantic-settings)
        """
        resolved_path = config_path or _DEFAULT_CONFIG_FILE
        toml_data: dict[str, Any] = {}

        if resolved_path.exists():
            try:
                with open(resolved_path, "rb") as fh:
                    toml_data = tomllib.load(fh)
            except (OSError, tomllib.TOMLDecodeError):
                # Non-fatal: fall back to defaults + env vars.
                toml_data = {}

        # Build nested override dicts from TOML for each section.
        # pydantic-settings will still apply env vars on top of these.
        init_kwargs: dict[str, Any] = {"config_file": resolved_path}

        section_map = {
            "keys":   KeysConfig,
            "scan":   ScanConfig,
            "output": OutputConfig,
            "proxy":  ProxyConfig,
            "server": ServerConfig,
        }

        for section_name, model_cls in section_map.items():
            if section_name in toml_data:
                # Instantiate the nested model from TOML values so that
                # pydantic validates types before we pass them upward.
                try:
                    init_kwargs[section_name] = model_cls(**toml_data[section_name])
                except Exception:
                    # Malformed TOML section — skip it, env vars still apply.
                    pass

        instance = cls(**init_kwargs)
        # Attach a default RuntimeConfig; overwritten by init_settings().
        object.__setattr__(instance, "runtime", RuntimeConfig())
        return instance

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def has_hibp(self) -> bool:
        return bool(self.keys.hibp_api_key)

    @property
    def has_shodan(self) -> bool:
        return bool(self.keys.shodan_api_key)

    @property
    def has_anthropic(self) -> bool:
        return bool(self.keys.anthropic_api_key)

    @property
    def effective_proxy(self) -> str | None:
        """
        Return the proxy URL to use for outbound HTTP, or None if proxying is
        disabled.

        - If tor mode is active (runtime.tor), return tor_socks regardless of
          proxy.enabled so callers don't need to know about the distinction.
        - If proxy.enabled and a URL is configured, return that URL.
        - Otherwise return None.
        """
        if self.runtime.tor:
            return self.proxy.tor_socks
        if self.proxy.enabled and self.proxy.url:
            return self.proxy.url
        return None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_settings: Settings | None = None


def get_settings() -> Settings:
    """
    Return the cached Settings singleton.

    If init_settings() has not been called yet, initialises with defaults
    (no config file, no overrides).  Modules that want to read settings
    during import should use this rather than caching their own reference.
    """
    global _settings
    if _settings is None:
        _settings = Settings.load()
    return _settings


def init_settings(
    config_path: Path | None = None,
    *,
    active: bool = False,
    stealth: bool = False,
    tor: bool = False,
    session: str = "",
    verbose: bool = False,
    **extra_runtime: Any,
) -> Settings:
    """
    Initialise (or reinitialise) the Settings singleton.

    Called once at CLI startup after argument parsing.  All subsequent calls
    to get_settings() return this instance.

    Args:
        config_path:    Path to a TOML config file.  Defaults to
                        ~/.osint/config.toml.
        active:         Enable active (non-passive) scan modules.
        stealth:        Apply rate limiting, UA rotation, and random delays.
        tor:            Route traffic through the local Tor SOCKS proxy.
        session:        Session name for the current run.
        verbose:        Enable debug-level console output.
        **extra_runtime: Additional runtime flags stored in RuntimeConfig.extra.

    Returns:
        The newly constructed Settings singleton.
    """
    global _settings

    settings = Settings.load(config_path)
    runtime = RuntimeConfig(
        active=active,
        stealth=stealth,
        tor=tor,
        session=session,
        verbose=verbose,
        extra=dict(extra_runtime),
    )
    object.__setattr__(settings, "runtime", runtime)
    _settings = settings
    return _settings
