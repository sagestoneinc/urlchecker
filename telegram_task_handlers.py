"""Telegram task command handlers for the optional Hubstaff bot."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from hubstaff_client import HubstaffClient
from hubstaff_models import HubstaffTask
from task_state_store import ReminderSubscription, TaskStateStore

logger = logging.getLogger(__name__)


@dataclass
class HandlerResponse:
    text: str
    reply_markup: Optional[dict[str, Any]] = None


class TelegramTaskHandlers:
    def __init__(
        self,
        *,
        hubstaff_client: HubstaffClient,
        state_store: TaskStateStore,
    ) -> None:
        self._hubstaff = hubstaff_client
        self._state = state_store

    def handle_command(
        self,
        *,
        telegram_user_id: str,
        chat_id: str,
        text: str,
    ) -> HandlerResponse:
        message = text.strip()
        if not message:
            return HandlerResponse(text="Empty command.")

        pending = self._state.pop_pending_action(telegram_user_id)
        if pending and not message.startswith("/"):
            return self._handle_pending_action(telegram_user_id=telegram_user_id, pending=pending, value=message)

        command, _, args = message.partition(" ")
        command = command.lower()

        if command in {"/start", "/help"}:
            return HandlerResponse(text=self._help_text())
        if command == "/tasks":
            return self._handle_list_tasks(telegram_user_id=telegram_user_id, args=args)
        if command == "/task":
            return self._handle_task_detail(args)
        if command == "/assign":
            return self._handle_assign(args)
        if command == "/complete":
            return self._handle_complete(args)
        if command == "/edit":
            return self._handle_edit_start(telegram_user_id=telegram_user_id, args=args)
        if command == "/remind":
            return self._handle_remind(telegram_user_id=telegram_user_id, chat_id=chat_id, args=args)
        if command == "/reminders":
            return self._handle_list_reminders(telegram_user_id)
        return HandlerResponse(text="Unknown command. Use /help.")

    def handle_callback_query(self, *, telegram_user_id: str, data: str) -> HandlerResponse:
        if data.startswith("task:"):
            task_id = data.split(":", 1)[1]
            return self._handle_task_detail(task_id)
        if data.startswith("complete:"):
            task_id = data.split(":", 1)[1]
            return self._handle_complete(task_id)
        if data.startswith("remind:"):
            reminder_type = data.split(":", 1)[1]
            return self._handle_remind(
                telegram_user_id=telegram_user_id,
                chat_id="",
                args=f"subscribe {reminder_type}",
            )
        return HandlerResponse(text="Unsupported action.")

    def _help_text(self) -> str:
        return (
            "Hubstaff Task Bot commands:\n"
            "/tasks [mine|open|overdue|today|week] [project=<id>] [assignee=<id>] [label=<text>] [status=<id>] [q=<text>]\n"
            "/task <task_id>\n"
            "/assign <task_id> <user query or user_id>\n"
            "/edit <task_id> <title|description|due|labels|status>\n"
            "/complete <task_id>\n"
            "/remind subscribe <open_tasks|overdue|due_today|due_tomorrow|daily_digest|weekday_morning_digest> [timezone=UTC] [project=<id>] [assignee=<id>]\n"
            "/remind unsubscribe <type>\n"
            "/reminders"
        )

    def _handle_list_tasks(self, *, telegram_user_id: str, args: str) -> HandlerResponse:
        filters = self._parse_task_filters(args)
        if filters.pop("mine", False):
            mapped = self._state.hubstaff_user_id_for(telegram_user_id)
            if mapped:
                filters["assignee_id"] = mapped
        tasks = self._hubstaff.list_tasks(filters=filters)
        if not tasks:
            return HandlerResponse(text="No tasks found for the selected filters.")

        lines = ["Tasks:"]
        keyboard_rows = []
        for task in tasks[:15]:
            due = task.due_at or "no due"
            status = task.status_name or task.status_id or "unknown"
            lines.append(f"• #{task.id} {task.title} [{status}] due={due}")
            keyboard_rows.append([
                {"text": f"#{task.id}", "callback_data": f"task:{task.id}"},
                {"text": "Complete", "callback_data": f"complete:{task.id}"},
            ])
        markup = {"inline_keyboard": keyboard_rows} if keyboard_rows else None
        return HandlerResponse(text="\n".join(lines), reply_markup=markup)

    def _handle_task_detail(self, args: str) -> HandlerResponse:
        task_id = args.strip()
        if not task_id:
            return HandlerResponse(text="Usage: /task <task_id>")
        task = self._hubstaff.get_task(task_id)
        return HandlerResponse(text=self._format_task_detail(task))

    def _handle_assign(self, args: str) -> HandlerResponse:
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            return HandlerResponse(text="Usage: /assign <task_id> <user query or user_id>")
        task_id, query = parts[0], parts[1].strip()
        users = self._hubstaff.search_users(query)
        if not users:
            return HandlerResponse(text=f"No users matched '{query}'.")

        exact = [u for u in users if u.id == query]
        selected = exact[0] if exact else users[0]
        task = self._hubstaff.assign_task(task_id, [selected.id])
        return HandlerResponse(text=f"Task #{task.id} assigned to {selected.name}.")

    def _handle_complete(self, args: str) -> HandlerResponse:
        task_id = args.strip()
        if not task_id:
            return HandlerResponse(text="Usage: /complete <task_id>")
        task = self._hubstaff.complete_task(task_id)
        return HandlerResponse(text=f"Task #{task.id} moved to done status '{task.status_name or task.status_id}'.")

    def _handle_edit_start(self, *, telegram_user_id: str, args: str) -> HandlerResponse:
        parts = args.split(maxsplit=2)
        if len(parts) < 2:
            return HandlerResponse(text="Usage: /edit <task_id> <title|description|due|labels|status>")
        task_id = parts[0]
        field = parts[1].lower()
        if field not in {"title", "description", "due", "labels", "status"}:
            return HandlerResponse(text="Editable fields: title, description, due, labels, status")
        self._state.put_pending_action(
            telegram_user_id,
            {"action": "edit", "task_id": task_id, "field": field},
        )
        return HandlerResponse(text=f"Send the new value for {field} on task #{task_id}.")

    def _handle_pending_action(self, *, telegram_user_id: str, pending: dict[str, Any], value: str) -> HandlerResponse:
        if pending.get("action") != "edit":
            return HandlerResponse(text="Unsupported pending action.")
        task_id = str(pending.get("task_id", ""))
        field = str(pending.get("field", ""))
        if not task_id or not field:
            return HandlerResponse(text="Pending edit action was invalid.")

        update_fields: dict[str, Any]
        if field == "due":
            parsed = self._validate_due_date(value)
            if not parsed:
                self._state.put_pending_action(telegram_user_id, pending)
                return HandlerResponse(text="Invalid due date format. Use YYYY-MM-DD.")
            update_fields = {"due_at": parsed}
        elif field == "labels":
            labels = [item.strip() for item in value.split(",") if item.strip()]
            update_fields = {"labels": labels}
        elif field == "status":
            update_fields = {"status_id": value.strip()}
        else:
            key = "title" if field == "title" else "description"
            update_fields = {key: value}

        task = self._hubstaff.update_task(task_id, update_fields)
        return HandlerResponse(text=f"Task #{task.id} updated: {field} changed.")

    def _handle_remind(self, *, telegram_user_id: str, chat_id: str, args: str) -> HandlerResponse:
        parts = args.split()
        if len(parts) < 2:
            return HandlerResponse(text="Usage: /remind subscribe <type> [timezone=UTC] [project=<id>] [assignee=<id>] OR /remind unsubscribe <type>")

        action = parts[0].lower()
        reminder_type = parts[1].lower()
        if action == "unsubscribe":
            removed = self._state.remove_reminder(telegram_user_id, reminder_type)
            if removed:
                return HandlerResponse(text=f"Unsubscribed from {reminder_type} reminders.")
            return HandlerResponse(text=f"No existing {reminder_type} reminder subscription.")

        if action != "subscribe":
            return HandlerResponse(text="Use subscribe or unsubscribe.")

        options = self._parse_options(parts[2:])
        subscription = ReminderSubscription(
            telegram_user_id=str(telegram_user_id),
            chat_id=str(chat_id),
            reminder_type=reminder_type,
            timezone=options.get("timezone", "UTC"),
            project_id=options.get("project", ""),
            assignee_id=options.get("assignee", ""),
        )
        self._state.add_reminder(subscription)
        return HandlerResponse(
            text=(
                f"Subscribed to {reminder_type} reminders "
                f"(timezone={subscription.timezone}, project={subscription.project_id or 'any'}, "
                f"assignee={subscription.assignee_id or 'any'})."
            )
        )

    def _handle_list_reminders(self, telegram_user_id: str) -> HandlerResponse:
        entries = [
            item
            for item in self._state.list_reminders()
            if item.telegram_user_id == str(telegram_user_id)
        ]
        if not entries:
            return HandlerResponse(text="No reminder subscriptions configured.")

        lines = ["Your reminders:"]
        for item in entries:
            lines.append(
                f"• {item.reminder_type} timezone={item.timezone} project={item.project_id or 'any'} assignee={item.assignee_id or 'any'}"
            )
        return HandlerResponse(text="\n".join(lines))

    def _parse_task_filters(self, args: str) -> dict[str, Any]:
        filters: dict[str, Any] = {}
        parts = [item for item in args.split() if item]
        presets = {"mine", "open", "overdue", "today", "week"}
        for part in parts:
            lower = part.lower()
            if lower in presets:
                if lower == "mine":
                    filters["mine"] = True
                elif lower == "overdue":
                    filters["due_before"] = self._utc_today().date().isoformat()
                elif lower == "today":
                    today = self._utc_today().date().isoformat()
                    filters["due_on"] = today
                elif lower == "week":
                    end = self._utc_today().date() + timedelta(days=7)
                    filters["due_before"] = end.isoformat()
                elif lower == "open":
                    filters["state"] = "open"
                continue
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip().lower()
                value = value.strip()
                if key == "project":
                    filters["project_id"] = value
                elif key == "assignee":
                    filters["assignee_id"] = value
                elif key == "label":
                    filters["label"] = value
                elif key == "status":
                    filters["status_id"] = value
                elif key in {"q", "query", "search"}:
                    filters["search"] = value
        return filters

    @staticmethod
    def _parse_options(tokens: list[str]) -> dict[str, str]:
        options: dict[str, str] = {}
        for token in tokens:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            options[key.strip().lower()] = value.strip()
        return options

    @staticmethod
    def _validate_due_date(value: str) -> str:
        raw = value.strip()
        try:
            day = datetime.strptime(raw, "%Y-%m-%d")
        except ValueError:
            return ""
        return day.date().isoformat()

    @staticmethod
    def _format_task_detail(task: HubstaffTask) -> str:
        return (
            f"Task #{task.id}: {task.title}\n"
            f"Project: {task.project_name or task.project_id or 'N/A'}\n"
            f"Status: {task.status_name or task.status_id or 'N/A'}\n"
            f"Assignees: {task.assignee_names}\n"
            f"Labels: {', '.join(task.labels) if task.labels else 'None'}\n"
            f"Due: {task.due_at or 'N/A'}\n"
            f"Created: {task.created_at or 'N/A'}\n"
            f"Updated: {task.updated_at or 'N/A'}\n"
            f"URL: {task.web_url or 'N/A'}\n\n"
            f"Description:\n{task.description or 'N/A'}"
        )

    @staticmethod
    def _utc_today() -> datetime:
        return datetime.now(timezone.utc)
