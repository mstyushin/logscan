"""Configuration handling for logscan.

Settings are resolved with the following precedence (highest first):
1. CLI arguments
2. Environment variables
3. Defaults
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

# Default Kaspersky OpenTIP API v1 base endpoint.
DEFAULT_OPENTIP_ENDPOINT = "https://opentip.kaspersky.com/api/v1/"

# Default report output directory.
DEFAULT_REPORT_DIR = "./reports"

# Supported report formats.
SUPPORTED_FORMATS = ("csv", "json")


def _as_bool(value: str) -> bool:
    """Convert a string environment value to a boolean."""
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _as_int(value: str, default: int) -> int:
    """Convert a string environment value to an int, falling back to default."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class Settings:
    """Runtime settings for logscan."""

    opentip_api_key: str = ""
    telegram_token: str = ""
    telegram_allowed_chats: list[int] = field(default_factory=list)
    opentip_endpoint: str = DEFAULT_OPENTIP_ENDPOINT
    report_format: str = "csv"
    report_dir: str = DEFAULT_REPORT_DIR
    opentip_backoff_interval: int = 15
    opentip_max_retries: int = 5
    # When True, private/reserved IP ranges are included in analysis.
    include_private_ips: bool = False

    def is_analysis_configured(self) -> bool:
        """Return True when an OpenTIP API key is present."""
        return bool(self.opentip_api_key)

    def is_bot_configured(self) -> bool:
        """Return True when a Telegram token is present."""
        return bool(self.telegram_token)


def _parse_allowed_chats(value: Optional[str]) -> list[int]:
    """Parse a comma-separated list of Telegram chat IDs into integers."""
    if not value:
        return []
    chats: list[int] = []
    for part in str(value).split(","):
        part = part.strip()
        if part.lstrip("-").isdigit():
            chats.append(int(part))
    return chats


def load_settings(cli_args: Optional[Any] = None) -> Settings:
    """Build a Settings instance from env vars and optional CLI args.

    ``cli_args`` is expected to expose attributes named after the CLI options
    (e.g. ``api_key``, ``endpoint``, ``format``, ``report_dir``). Values that
    are ``None`` or empty are ignored so env/defaults take over.
    """
    env = os.environ

    # Start from environment variables.
    settings = Settings(
        opentip_api_key=env.get("OPENTIP_API_KEY", ""),
        telegram_token=env.get("TELEGRAM_TOKEN", ""),
        telegram_allowed_chats=_parse_allowed_chats(env.get("TELEGRAM_ALLOWED_CHATS")),
        opentip_endpoint=env.get("OPENTIP_ENDPOINT", DEFAULT_OPENTIP_ENDPOINT),
        report_format=env.get("LOGSCAN_REPORT_FORMAT", "csv"),
        report_dir=env.get("LOGSCAN_REPORT_DIR", DEFAULT_REPORT_DIR),
        opentip_backoff_interval=_as_int(env.get("OPENTIP_BACKOFF_INTERVAL"), 15),
        opentip_max_retries=_as_int(env.get("OPENTIP_MAX_RETRIES"), 5),
        include_private_ips=_as_bool(env.get("LOGSCAN_INCLUDE_PRIVATE_IPS", "false")),
    )

    # Normalize report format.
    settings.report_format = normalize_format(settings.report_format)

    if cli_args is None:
        return settings

    # CLI overrides take highest precedence.
    cli_overrides = {
        "opentip_api_key": getattr(cli_args, "api_key", None),
        "opentip_endpoint": getattr(cli_args, "endpoint", None),
        "report_format": getattr(cli_args, "format", None),
        "report_dir": getattr(cli_args, "report_dir", None),
        "include_private_ips": getattr(cli_args, "include_private_ips", None),
    }
    for attr, value in cli_overrides.items():
        if value not in (None, ""):
            setattr(settings, attr, value)

    if settings.report_format:
        settings.report_format = normalize_format(settings.report_format)

    return settings


def normalize_format(fmt: str) -> str:
    """Normalize and validate a report format string."""
    value = str(fmt).strip().lower()
    if value not in SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported report format: {fmt!r}. "
            f"Supported formats: {', '.join(SUPPORTED_FORMATS)}"
        )
    return value


def settings_summary(settings: Settings) -> str:
    """Return a human-readable summary of the settings, hiding secrets."""
    lines = [
        "logscan configuration:",
        f"  endpoint           : {settings.opentip_endpoint}",
        f"  report format      : {settings.report_format}",
        f"  report directory   : {settings.report_dir}",
        f"  backoff interval (s): {settings.opentip_backoff_interval}",
        f"  max retries        : {settings.opentip_max_retries}",
        f"  include private IPs: {settings.include_private_ips}",
        f"  analysis configured: {settings.is_analysis_configured()}",
        f"  bot configured     : {settings.is_bot_configured()}",
        f"  allowed chats      : {settings.telegram_allowed_chats or 'all'}",
    ]
    return "\n".join(lines)
