"""Persistent state for task-bot reminders and user mapping."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ReminderSubscription:
    telegram_user_id: str
    chat_id: str
    reminder_type: str
    timezone: str = "UTC"
    project_id: str = ""
    assignee_id: str = ""
    last_sent_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "telegram_user_id": self.telegram_user_id,
            "chat_id": self.chat_id,
            "reminder_type": self.reminder_type,
            "timezone": self.timezone,
            "project_id": self.project_id,
            "assignee_id": self.assignee_id,
            "last_sent_at": self.last_sent_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ReminderSubscription":
        return cls(
            telegram_user_id=str(payload.get("telegram_user_id", "")),
            chat_id=str(payload.get("chat_id", "")),
            reminder_type=str(payload.get("reminder_type", "open_tasks")),
            timezone=str(payload.get("timezone", "UTC")),
            project_id=str(payload.get("project_id", "")),
            assignee_id=str(payload.get("assignee_id", "")),
            last_sent_at=str(payload.get("last_sent_at", "")),
        )


@dataclass
class TaskBotState:
    user_mapping: dict[str, str] = field(default_factory=dict)
    reminders: list[ReminderSubscription] = field(default_factory=list)
    pending_actions: dict[str, dict[str, Any]] = field(default_factory=dict)


class TaskStateStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._state = TaskBotState()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.load()

    def load(self) -> TaskBotState:
        if not self._path.exists():
            return self._state
        payload = json.loads(self._path.read_text(encoding="utf-8"))
        mapping = payload.get("user_mapping") if isinstance(payload, dict) else {}
        reminders_payload = payload.get("reminders") if isinstance(payload, dict) else []
        pending_actions = payload.get("pending_actions") if isinstance(payload, dict) else {}
        reminders = []
        if isinstance(reminders_payload, list):
            reminders = [
                ReminderSubscription.from_dict(item)
                for item in reminders_payload
                if isinstance(item, dict)
            ]
        self._state = TaskBotState(
            user_mapping={str(k): str(v) for k, v in (mapping or {}).items()},
            reminders=reminders,
            pending_actions={str(k): v for k, v in (pending_actions or {}).items()},
        )
        return self._state

    def save(self) -> None:
        payload = {
            "user_mapping": self._state.user_mapping,
            "reminders": [item.to_dict() for item in self._state.reminders],
            "pending_actions": self._state.pending_actions,
        }
        self._path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def merge_user_mapping(self, mapping: dict[str, str]) -> None:
        for tg_user, hubstaff_user in mapping.items():
            self._state.user_mapping[str(tg_user)] = str(hubstaff_user)
        self.save()

    def hubstaff_user_id_for(self, telegram_user_id: str) -> str:
        return self._state.user_mapping.get(str(telegram_user_id), "")

    def put_pending_action(self, telegram_user_id: str, action: dict[str, Any]) -> None:
        self._state.pending_actions[str(telegram_user_id)] = action
        self.save()

    def pop_pending_action(self, telegram_user_id: str) -> dict[str, Any]:
        key = str(telegram_user_id)
        action = self._state.pending_actions.pop(key, {})
        self.save()
        return action

    def add_reminder(self, subscription: ReminderSubscription) -> None:
        self._state.reminders.append(subscription)
        self.save()

    def remove_reminder(self, telegram_user_id: str, reminder_type: str) -> bool:
        key = str(telegram_user_id)
        before = len(self._state.reminders)
        self._state.reminders = [
            item
            for item in self._state.reminders
            if not (item.telegram_user_id == key and item.reminder_type == reminder_type)
        ]
        changed = len(self._state.reminders) != before
        if changed:
            self.save()
        return changed

    def list_reminders(self) -> list[ReminderSubscription]:
        return list(self._state.reminders)
