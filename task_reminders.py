"""Reminder delivery engine for optional Hubstaff task bot."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Callable
from zoneinfo import ZoneInfo

from hubstaff_client import HubstaffClient
from hubstaff_models import HubstaffTask
from task_state_store import ReminderSubscription, TaskStateStore

SendMessageFn = Callable[[str, str], None]


@dataclass
class ReminderDispatchResult:
    sent_count: int = 0


class TaskReminderEngine:
    def __init__(
        self,
        *,
        hubstaff_client: HubstaffClient,
        state_store: TaskStateStore,
        send_message: SendMessageFn,
    ) -> None:
        self._hubstaff = hubstaff_client
        self._state = state_store
        self._send_message = send_message

    def run_once(self, now_utc: datetime | None = None) -> ReminderDispatchResult:
        now = self._normalize_utc_naive(now_utc)
        result = ReminderDispatchResult()
        for sub in self._state.list_reminders():
            if not self._should_send(sub, now):
                continue
            message = self._build_message(sub, now)
            if not message:
                continue
            self._send_message(sub.chat_id, message)
            result.sent_count += 1
            sub.last_sent_at = now.isoformat()
        if result.sent_count:
            self._state.save()
        return result

    def _should_send(self, subscription: ReminderSubscription, now_utc: datetime) -> bool:
        local_now = self._as_local(now_utc, subscription.timezone)
        if subscription.reminder_type in {"daily_digest", "weekday_morning_digest"}:
            if subscription.reminder_type == "weekday_morning_digest" and local_now.weekday() >= 5:
                return False
            if local_now.hour != 9:
                return False
            if subscription.last_sent_at:
                last = self._parse_iso(subscription.last_sent_at)
                if last and self._as_local(last, subscription.timezone).date() == local_now.date():
                    return False
            return True

        # Other reminder types: send at most every 4 hours
        if not subscription.last_sent_at:
            return True
        last = self._parse_iso(subscription.last_sent_at)
        if not last:
            return True
        return (now_utc - last) >= timedelta(hours=4)

    def _build_message(self, subscription: ReminderSubscription, now_utc: datetime) -> str:
        filters = {"state": "open"}
        if subscription.project_id:
            filters["project_id"] = subscription.project_id
        if subscription.assignee_id:
            filters["assignee_id"] = subscription.assignee_id

        tasks = self._hubstaff.list_tasks(filters=filters)
        selected = self._filter_tasks(subscription.reminder_type, tasks, now_utc)
        if not selected:
            return ""

        header = {
            "open_tasks": "Open tasks reminder",
            "overdue": "Overdue tasks reminder",
            "due_today": "Tasks due today",
            "due_tomorrow": "Tasks due tomorrow",
            "daily_digest": "Daily task digest",
            "weekday_morning_digest": "Weekday morning task digest",
        }.get(subscription.reminder_type, "Task reminder")

        lines = [header]
        for task in selected[:20]:
            due = task.due_at or "no due"
            lines.append(f"• #{task.id} {task.title} (due: {due})")
        if len(selected) > 20:
            lines.append(f"… and {len(selected) - 20} more")
        return "\n".join(lines)

    def _filter_tasks(
        self,
        reminder_type: str,
        tasks: list[HubstaffTask],
        now_utc: datetime,
    ) -> list[HubstaffTask]:
        if reminder_type in {"open_tasks", "daily_digest", "weekday_morning_digest"}:
            return tasks
        today = now_utc.date()
        tomorrow = today + timedelta(days=1)
        output: list[HubstaffTask] = []
        for task in tasks:
            due_day = self._task_due_date(task)
            if reminder_type == "overdue" and due_day and due_day < today:
                output.append(task)
            elif reminder_type == "due_today" and due_day == today:
                output.append(task)
            elif reminder_type == "due_tomorrow" and due_day == tomorrow:
                output.append(task)
        return output

    @staticmethod
    def _normalize_utc_naive(value: datetime | None) -> datetime:
        if value is None:
            return datetime.now(timezone.utc).replace(tzinfo=None)
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    @staticmethod
    def _task_due_date(task: HubstaffTask) -> date | None:
        if not task.due_at:
            return None
        parsed = TaskReminderEngine._parse_iso(task.due_at)
        if not parsed:
            return None
        return parsed.date()

    @staticmethod
    def _parse_iso(value: str) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo:
            return parsed.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        return parsed

    @staticmethod
    def _as_local(value: datetime, timezone_name: str) -> datetime:
        tz_name = timezone_name or "UTC"
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = ZoneInfo("UTC")
        if value.tzinfo is None:
            value = value.replace(tzinfo=ZoneInfo("UTC"))
        return value.astimezone(tz)
