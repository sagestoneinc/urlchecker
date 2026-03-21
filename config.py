"""Configuration loaded from environment variables or a .env file."""

from __future__ import annotations

import os
import json
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


def _optional_bool(name: str, default: str = "false") -> bool:
    return _optional_env(name, default).lower() == "true"


def _optional_int(name: str, default: str) -> int:
    return int(_optional_env(name, default))


def _optional_json_map(name: str) -> dict[str, str]:
    raw = _optional_env(name, "{}")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    return {}


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
        default_factory=lambda: _optional_int("VT_POLL_INTERVAL", "15")
    )
    poll_max_attempts: int = field(
        default_factory=lambda: _optional_int("VT_POLL_MAX_ATTEMPTS", "10")
    )
    request_timeout_seconds: int = field(
        default_factory=lambda: _optional_int("VT_REQUEST_TIMEOUT", "30")
    )
    max_retries: int = field(
        default_factory=lambda: _optional_int("VT_MAX_RETRIES", "3")
    )

    # Rate limiting – free tier allows 4 req/min
    rate_limit_requests_per_minute: int = field(
        default_factory=lambda: _optional_int("VT_RATE_LIMIT_RPM", "4")
    )

    # Alert behaviour
    alert_on_clean: bool = field(
        default_factory=lambda: _optional_bool("ALERT_ON_CLEAN", "false")
    )
    send_summary: bool = field(
        default_factory=lambda: _optional_bool("SEND_SUMMARY", "true")
    )
    report_sources_checked: str = field(
        default_factory=lambda: _optional_env(
            "REPORT_SOURCES_CHECKED",
            "VirusTotal",
        )
    )

    # Optional Hubstaff task-bot subsystem (off by default)
    enable_hubstaff_tasks_bot: bool = field(
        default_factory=lambda: _optional_bool("ENABLE_HUBSTAFF_TASKS_BOT", "false")
    )
    hubstaff_api_base_url: str = field(
        default_factory=lambda: _optional_env(
            "HUBSTAFF_API_BASE_URL",
            "https://api.hubstaff.com",
        )
    )
    hubstaff_token: str = field(default_factory=lambda: _optional_env("HUBSTAFF_TOKEN"))
    hubstaff_timeout_seconds: int = field(
        default_factory=lambda: _optional_int("HUBSTAFF_TIMEOUT_SECONDS", "30")
    )
    hubstaff_max_retries: int = field(
        default_factory=lambda: _optional_int("HUBSTAFF_MAX_RETRIES", "3")
    )
    hubstaff_done_status_ids: str = field(
        default_factory=lambda: _optional_env("HUBSTAFF_DONE_STATUS_IDS", "")
    )
    taskbot_poll_timeout_seconds: int = field(
        default_factory=lambda: _optional_int("TASKBOT_POLL_TIMEOUT_SECONDS", "30")
    )
    taskbot_poll_interval_seconds: int = field(
        default_factory=lambda: _optional_int("TASKBOT_POLL_INTERVAL_SECONDS", "2")
    )
    taskbot_state_file: Path = field(
        default_factory=lambda: Path(
            _optional_env("TASKBOT_STATE_FILE", "results/taskbot_state.json")
        )
    )
    taskbot_default_timezone: str = field(
        default_factory=lambda: _optional_env("TASKBOT_DEFAULT_TIMEZONE", "UTC")
    )
    taskbot_user_mapping_json: dict[str, str] = field(
        default_factory=lambda: _optional_json_map("TASKBOT_USER_MAPPING_JSON")
    )

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)

    @classmethod
    def from_env(cls) -> "Config":
        """Factory method – load all config from the environment."""
        return cls()
