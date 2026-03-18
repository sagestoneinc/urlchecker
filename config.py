"""Configuration loaded from environment variables or a .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _require_env(name: str) -> str:
    """Return environment variable value; raise if missing."""
    value = os.getenv(name, "").strip()
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set. "
            "Please add it to your GitHub Actions secrets or .env file."
        )
    return value


def _optional_env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


@dataclass
class Config:
    """Central configuration for the URL checker."""

    # VirusTotal
    vt_api_key: str = field(default_factory=lambda: _require_env("VT_API_KEY"))

    # Telegram (optional – alerts are skipped when not configured)
    telegram_bot_token: str = field(
        default_factory=lambda: _optional_env("TELEGRAM_BOT_TOKEN")
    )
    telegram_chat_id: str = field(
        default_factory=lambda: _optional_env("TELEGRAM_CHAT_ID")
    )

    # Input
    urls_file: Path = field(
        default_factory=lambda: Path(
            _optional_env("URLS_FILE", "urls.txt")
        )
    )

    # Storage
    results_dir: Path = field(
        default_factory=lambda: Path(
            _optional_env("RESULTS_DIR", "results")
        )
    )

    # VirusTotal polling
    poll_interval_seconds: int = field(
        default_factory=lambda: int(_optional_env("VT_POLL_INTERVAL", "15"))
    )
    poll_max_attempts: int = field(
        default_factory=lambda: int(_optional_env("VT_POLL_MAX_ATTEMPTS", "10"))
    )
    request_timeout_seconds: int = field(
        default_factory=lambda: int(_optional_env("VT_REQUEST_TIMEOUT", "30"))
    )
    max_retries: int = field(
        default_factory=lambda: int(_optional_env("VT_MAX_RETRIES", "3"))
    )

    # Rate limiting – free tier allows 4 req/min
    rate_limit_requests_per_minute: int = field(
        default_factory=lambda: int(_optional_env("VT_RATE_LIMIT_RPM", "4"))
    )

    # Alert behaviour
    alert_on_clean: bool = field(
        default_factory=lambda: _optional_env("ALERT_ON_CLEAN", "false").lower()
        == "true"
    )
    send_summary: bool = field(
        default_factory=lambda: _optional_env("SEND_SUMMARY", "true").lower() == "true"
    )

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)

    @classmethod
    def from_env(cls) -> "Config":
        """Factory method – load all config from the environment."""
        return cls()
