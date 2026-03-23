"""Telegram long-polling runtime for optional Hubstaff task assistant."""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from task_state_store import TaskStateStore
from telegram_task_handlers import HandlerResponse, TelegramTaskHandlers

logger = logging.getLogger(__name__)


class TelegramTaskBot:
    def __init__(
        self,
        *,
        bot_token: str,
        handlers: TelegramTaskHandlers,
        state_store: TaskStateStore,
        poll_timeout_seconds: int = 30,
        poll_interval_seconds: int = 2,
    ) -> None:
        self._token = bot_token
        self._handlers = handlers
        self._state = state_store
        self._poll_timeout = poll_timeout_seconds
        self._poll_interval = poll_interval_seconds
        last_update_id = self._state.last_update_id()
        self._offset = last_update_id + 1 if last_update_id > 0 else 0
        self._base_url = f"https://api.telegram.org/bot{bot_token}"
        self._next_conflict_recovery_at = 0.0
        self._conflict_recovery_cooldown_seconds = max(30, self._poll_timeout)

    def run_forever(self) -> None:
        logger.info("Starting Hubstaff Telegram task bot (polling mode)")
        while True:
            try:
                updates = self._get_updates_with_conflict_recovery()
                if updates is None:
                    time.sleep(max(self._poll_interval, 1))
                    continue
                self._process_updates(updates)
            except Exception as exc:
                logger.error("Task bot loop error: %s", exc)
                time.sleep(max(self._poll_interval, 1))

    def run_once(self) -> int:
        try:
            updates = self._get_updates_with_conflict_recovery()
        except requests.HTTPError as exc:
            logger.error("Task bot run_once failed during getUpdates: %s", exc)
            return 1
        except Exception as exc:
            logger.error("Task bot run_once failed before update processing: %s", exc)
            return 1

        if updates is None:
            return 0

        try:
            self._process_updates(updates)
            return 0
        except Exception as exc:
            logger.error("Task bot run_once failed while processing updates: %s", exc)
            return 1

    def _get_updates(self) -> list[dict[str, Any]]:
        response = requests.get(
            f"{self._base_url}/getUpdates",
            params={"timeout": self._poll_timeout, "offset": self._offset},
            timeout=self._poll_timeout + 5,
        )
        response.raise_for_status()
        payload = response.json()
        if not payload.get("ok"):
            return []
        result = payload.get("result")
        if isinstance(result, list):
            return [item for item in result if isinstance(item, dict)]
        return []

    def _handle_update(self, update: dict[str, Any]) -> None:
        if "callback_query" in update:
            self._handle_callback(update["callback_query"])
            return
        message = update.get("message")
        if not isinstance(message, dict):
            return
        text = message.get("text")
        if not isinstance(text, str):
            return
        from_user = message.get("from") or {}
        chat = message.get("chat") or {}
        response = self._handlers.handle_command(
            telegram_user_id=str(from_user.get("id", "")),
            chat_id=str(chat.get("id", "")),
            text=text,
        )
        self._send_message(chat_id=str(chat.get("id", "")), response=response)

    def _handle_callback(self, callback: dict[str, Any]) -> None:
        data = callback.get("data")
        if not isinstance(data, str):
            return
        message = callback.get("message") or {}
        chat = message.get("chat") or {}
        from_user = callback.get("from") or {}
        response = self._handlers.handle_callback_query(
            telegram_user_id=str(from_user.get("id", "")),
            chat_id=str(chat.get("id", "")),
            data=data,
        )
        self._answer_callback_query(callback.get("id", ""))
        self._send_message(chat_id=str(chat.get("id", "")), response=response)

    def _send_message(self, *, chat_id: str, response: HandlerResponse) -> None:
        if not chat_id:
            return
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": response.text,
            "disable_web_page_preview": True,
        }
        if response.reply_markup:
            payload["reply_markup"] = response.reply_markup

        resp = requests.post(
            f"{self._base_url}/sendMessage",
            json=payload,
            timeout=20,
        )
        resp.raise_for_status()

    def send_text(self, chat_id: str, text: str) -> None:
        self._send_message(chat_id=chat_id, response=HandlerResponse(text=text))

    def _answer_callback_query(self, callback_query_id: str) -> None:
        if not callback_query_id:
            return
        requests.post(
            f"{self._base_url}/answerCallbackQuery",
            json={"callback_query_id": callback_query_id},
            timeout=10,
        )

    def _process_updates(self, updates: list[dict[str, Any]]) -> None:
        for update in updates:
            update_id = int(update.get("update_id", 0))
            self._offset = max(self._offset, update_id + 1)
            self._state.set_last_update_id(update_id)
            self._handle_update(update)

    def _get_updates_with_conflict_recovery(self) -> list[dict[str, Any]] | None:
        try:
            updates = self._get_updates()
            self._next_conflict_recovery_at = 0.0
            return updates
        except requests.HTTPError as exc:
            if exc.response is None or exc.response.status_code != 409:
                raise
            if time.monotonic() < self._next_conflict_recovery_at:
                return None
            return self._recover_updates_after_conflict()

    def _recover_updates_after_conflict(self) -> list[dict[str, Any]] | None:
        logger.warning(
            "Task bot getUpdates conflict (409). "
            "Attempting webhook reset fallback."
        )
        if not self._delete_webhook():
            logger.warning(
                "Task bot fallback failed: webhook reset did not succeed. "
                "Another poller may already be running."
            )
            self._activate_conflict_recovery_cooldown()
            return None
        try:
            updates = self._get_updates()
            self._next_conflict_recovery_at = 0.0
            logger.info("Task bot recovered from Telegram conflict via deleteWebhook fallback.")
            return updates
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 409:
                logger.warning(
                    "Task bot getUpdates conflict (409) "
                    "after webhook reset fallback. Another poller may already be running."
                )
                self._activate_conflict_recovery_cooldown()
                return None
            raise

    def _activate_conflict_recovery_cooldown(self) -> None:
        self._next_conflict_recovery_at = (
            time.monotonic() + self._conflict_recovery_cooldown_seconds
        )

    def _delete_webhook(self) -> bool:
        response = requests.post(
            f"{self._base_url}/deleteWebhook",
            json={"drop_pending_updates": False},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
        return bool(payload.get("ok"))
