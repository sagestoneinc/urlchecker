"""Separate entrypoint for optional Hubstaff Telegram task bot."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from config import Config
from hubstaff_auth import HubstaffAuth
from hubstaff_client import HubstaffClient
from task_reminders import TaskReminderEngine
from task_state_store import TaskStateStore
from telegram_task_bot import TelegramTaskBot
from telegram_task_handlers import TelegramTaskHandlers
from utils import setup_logging


logger = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hubstaff Telegram task bot (optional subsystem)"
    )
    parser.add_argument("--run-once", action="store_true", help="Process updates once")
    parser.add_argument(
        "--run-reminders-once",
        action="store_true",
        help="Dispatch reminders once and exit",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logs")
    return parser.parse_args()


def _build_task_stack(config: Config) -> tuple[TelegramTaskBot, TaskReminderEngine]:
    if not config.enable_hubstaff_tasks_bot:
        raise EnvironmentError(
            "ENABLE_HUBSTAFF_TASKS_BOT is false. Set it to true to run the task bot."
        )
    if not config.telegram_bot_token:
        raise EnvironmentError("TELEGRAM_BOT_TOKEN is required for task bot runtime")
    if not config.hubstaff_token:
        raise EnvironmentError("HUBSTAFF_TOKEN is required for Hubstaff task bot runtime")

    state = TaskStateStore(config.taskbot_state_file)
    if config.taskbot_user_mapping_json:
        state.merge_user_mapping(config.taskbot_user_mapping_json)

    auth = HubstaffAuth(access_token=config.hubstaff_token)
    done_ids = [item.strip() for item in config.hubstaff_done_status_ids.split(",") if item.strip()]
    hubstaff = HubstaffClient(
        auth=auth,
        base_url=config.hubstaff_api_base_url,
        timeout_seconds=config.hubstaff_timeout_seconds,
        max_retries=config.hubstaff_max_retries,
        done_status_ids=done_ids,
    )

    handlers = TelegramTaskHandlers(
        hubstaff_client=hubstaff,
        state_store=state,
        default_timezone=config.taskbot_default_timezone,
    )
    bot = TelegramTaskBot(
        bot_token=config.telegram_bot_token,
        handlers=handlers,
        state_store=state,
        poll_timeout_seconds=config.taskbot_poll_timeout_seconds,
        poll_interval_seconds=config.taskbot_poll_interval_seconds,
    )

    def send_message(chat_id: str, text: str) -> None:
        bot.send_text(chat_id=chat_id, text=text)

    reminders = TaskReminderEngine(
        hubstaff_client=hubstaff,
        state_store=state,
        send_message=send_message,
    )
    return bot, reminders


def main() -> int:
    args = _parse_args()
    setup_logging(debug=args.debug)

    try:
        try:
            from dotenv import load_dotenv

            load_dotenv(override=False)
        except ImportError:
            pass
        # Config currently requires VT_API_KEY for legacy scanner mode.
        # Task bot runtime does not use VT, so provide a safe placeholder.
        os.environ.setdefault("VT_API_KEY", "__TASKBOT_UNUSED__")
        config = Config.from_env()
        bot, reminders = _build_task_stack(config)
    except EnvironmentError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    if args.run_reminders_once:
        dispatched = reminders.run_once()
        logger.info("Reminder dispatch complete: sent=%d", dispatched.sent_count)
        return 0

    if args.run_once:
        return bot.run_once()

    bot.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
