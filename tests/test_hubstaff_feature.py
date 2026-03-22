import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import requests
from hubstaff_auth import HubstaffAuth
from hubstaff_client import HubstaffClient
from hubstaff_models import HubstaffTask
from task_reminders import TaskReminderEngine
from task_state_store import ReminderSubscription, TaskStateStore
from telegram_task_bot import TelegramTaskBot
from telegram_task_handlers import TelegramTaskHandlers


class HubstaffFeatureTests(unittest.TestCase):
    class FakeHandlers:
        def handle_command(self, telegram_user_id: str, chat_id: str, text: str):
            from telegram_task_handlers import HandlerResponse

            return HandlerResponse(text="ok")

        def handle_callback_query(self, telegram_user_id: str, chat_id: str, data: str):
            from telegram_task_handlers import HandlerResponse

            return HandlerResponse(text="ok")

    def test_auth_header_uses_bearer_token(self) -> None:
        auth = HubstaffAuth(access_token="abc123")
        self.assertEqual(auth.authorization_header()["Authorization"], "Bearer abc123")

    def test_list_tasks_paginates(self) -> None:
        auth = HubstaffAuth(access_token="abc")
        client = HubstaffClient(auth=auth, base_url="https://api.example.test")

        def fake_request(method, path, params=None, json=None):
            page = params.get("page", 1)
            if page == 1:
                return {
                    "tasks": [{"id": "1", "title": "First"}],
                    "pagination": {"total_pages": 2},
                }
            return {
                "tasks": [{"id": "2", "title": "Second"}],
                "pagination": {"total_pages": 2},
            }

        client._request = fake_request  # type: ignore[assignment]
        tasks = client.list_tasks()
        self.assertEqual([task.id for task in tasks], ["1", "2"])

    def test_complete_task_uses_done_status(self) -> None:
        auth = HubstaffAuth(access_token="abc")
        client = HubstaffClient(auth=auth, base_url="https://api.example.test")

        calls = []

        def fake_request(method, path, params=None, json=None):
            calls.append((method, path, params, json))
            if method == "GET" and path == "/v2/tasks/10":
                return {"task": {"id": "10", "title": "A", "project_id": "p1"}}
            if method == "GET" and path == "/v2/task_statuses":
                return {"statuses": [{"id": "done-1", "name": "Done", "is_done": True}]}
            if method == "PATCH" and path == "/v2/tasks/10":
                return {
                    "task": {
                        "id": "10",
                        "title": "A",
                        "status": {"id": "done-1", "name": "Done"},
                    }
                }
            raise AssertionError(f"Unexpected request: {method} {path}")

        client._request = fake_request  # type: ignore[assignment]
        task = client.complete_task("10")
        self.assertEqual(task.status_id, "done-1")

    def test_complete_task_prefers_first_configured_done_status_id(self) -> None:
        auth = HubstaffAuth(access_token="abc")
        client = HubstaffClient(
            auth=auth,
            base_url="https://api.example.test",
            done_status_ids=["done-a", "done-b"],
        )

        def fake_request(method, path, params=None, json=None):
            if method == "GET" and path == "/v2/tasks/10":
                return {"task": {"id": "10", "title": "A", "project_id": "p1"}}
            if method == "PATCH" and path == "/v2/tasks/10":
                return {
                    "task": {
                        "id": "10",
                        "title": "A",
                        "status": {"id": json["task"]["status_id"], "name": "Done"},
                    }
                }
            raise AssertionError(f"Unexpected request: {method} {path}")

        client._request = fake_request  # type: ignore[assignment]
        task = client.complete_task("10")
        self.assertEqual(task.status_id, "done-a")

    def test_handlers_support_listing_detail_assign_complete_edit_and_callback(self) -> None:
        class FakeHubstaff:
            def __init__(self):
                self.updated = []

            def list_tasks(self, filters=None, per_page=50):
                return [
                    HubstaffTask(id="1", title="Task 1", status_name="Open", due_at="2026-03-22"),
                ]

            def get_task(self, task_id):
                return HubstaffTask(id=task_id, title="Task 1", status_name="Open")

            def search_users(self, query=""):
                from hubstaff_models import HubstaffUser

                return [HubstaffUser(id="u1", name="Alice")]

            def assign_task(self, task_id, assignee_ids):
                return HubstaffTask(id=task_id, title="Task 1", assignees=[])

            def complete_task(self, task_id):
                return HubstaffTask(id=task_id, title="Task 1", status_name="Done", status_id="done")

            def update_task(self, task_id, fields):
                self.updated.append((task_id, fields))
                return HubstaffTask(id=task_id, title=fields.get("title", "Task 1"))

        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStateStore(Path(tmp) / "state.json")
            store.merge_user_mapping({"100": "u1"})
            handlers = TelegramTaskHandlers(
                hubstaff_client=FakeHubstaff(),
                state_store=store,
                default_timezone="America/New_York",
            )

            listed = handlers.handle_command(telegram_user_id="100", chat_id="200", text="/tasks mine")
            self.assertIn("Tasks:", listed.text)
            self.assertIsNotNone(listed.reply_markup)

            detail = handlers.handle_command(telegram_user_id="100", chat_id="200", text="/task 1")
            self.assertIn("Task #1", detail.text)

            assign = handlers.handle_command(telegram_user_id="100", chat_id="200", text="/assign 1 alice")
            self.assertIn("assigned", assign.text.lower())

            complete = handlers.handle_command(telegram_user_id="100", chat_id="200", text="/complete 1")
            self.assertIn("done status", complete.text.lower())

            start_edit = handlers.handle_command(telegram_user_id="100", chat_id="200", text="/edit 1 title")
            self.assertIn("Send the new value", start_edit.text)

            help_text = handlers.handle_command(telegram_user_id="100", chat_id="200", text="/help")
            self.assertIn("timezone=America/New_York", help_text.text)
            self.assertIsNotNone(help_text.reply_markup)

            menu = handlers.handle_command(telegram_user_id="100", chat_id="200", text="/hubspot")
            self.assertIn("Quick actions", menu.text)
            self.assertIsNotNone(menu.reply_markup)

            # Pending edit should be preserved when issuing slash command
            still_editing = handlers.handle_command(telegram_user_id="100", chat_id="200", text="/task 1")
            self.assertIn("Task #1", still_editing.text)
            finish_edit = handlers.handle_command(telegram_user_id="100", chat_id="200", text="Updated title")
            self.assertIn("updated", finish_edit.text.lower())

            callback = handlers.handle_callback_query(telegram_user_id="100", chat_id="200", data="task:1")
            self.assertIn("Task #1", callback.text)

            quick_list_callback = handlers.handle_callback_query(
                telegram_user_id="100",
                chat_id="200",
                data="cmd:tasks:mine",
            )
            self.assertIn("Tasks:", quick_list_callback.text)

            subscribe_callback = handlers.handle_callback_query(
                telegram_user_id="100",
                chat_id="200",
                data="remind:due_today",
            )
            self.assertIn("Subscribed to due_today reminders", subscribe_callback.text)

            quick_subscribe_callback = handlers.handle_callback_query(
                telegram_user_id="100",
                chat_id="200",
                data="cmd:remind_due_today",
            )
            self.assertIn("Subscribed to due_today reminders", quick_subscribe_callback.text)
            reminders = store.list_reminders()
            self.assertEqual(reminders[-1].chat_id, "200")
            self.assertEqual(reminders[-1].timezone, "America/New_York")

    def test_handlers_mine_preset_requires_user_mapping(self) -> None:
        class FakeHubstaff:
            def list_tasks(self, filters=None, per_page=50):
                raise AssertionError("list_tasks should not run without mapping for mine preset")

        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStateStore(Path(tmp) / "state.json")
            handlers = TelegramTaskHandlers(
                hubstaff_client=FakeHubstaff(),
                state_store=store,
            )

            from_command = handlers.handle_command(
                telegram_user_id="100",
                chat_id="200",
                text="/tasks mine",
            )
            self.assertIn("TASKBOT_USER_MAPPING_JSON", from_command.text)
            self.assertIn("/tasks assignee=<hubstaff_user_id>", from_command.text)

            from_callback = handlers.handle_callback_query(
                telegram_user_id="100",
                chat_id="200",
                data="cmd:tasks:mine",
            )
            self.assertIn("TASKBOT_USER_MAPPING_JSON", from_callback.text)
            self.assertIn("/tasks assignee=<hubstaff_user_id>", from_callback.text)

    def test_reminder_engine_sends_due_today(self) -> None:
        class FakeHubstaff:
            def list_tasks(self, filters=None, per_page=50):
                return [
                    HubstaffTask(id="1", title="Today", due_at="2026-03-21"),
                    HubstaffTask(id="2", title="Tomorrow", due_at="2026-03-22"),
                ]

        sent = []

        def send_message(chat_id: str, text: str) -> None:
            sent.append((chat_id, text))

        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStateStore(Path(tmp) / "state.json")
            store.add_reminder(
                ReminderSubscription(
                    telegram_user_id="100",
                    chat_id="200",
                    reminder_type="due_today",
                    timezone="UTC",
                )
            )
            engine = TaskReminderEngine(
                hubstaff_client=FakeHubstaff(),
                state_store=store,
                send_message=send_message,
            )
            result = engine.run_once(now_utc=datetime(2026, 3, 21, 9, 0, 0))
            self.assertEqual(result.sent_count, 1)
            self.assertEqual(len(sent), 1)
            self.assertIn("Tasks due today", sent[0][1])

    def test_reminder_engine_accepts_aware_now_argument(self) -> None:
        class FakeHubstaff:
            def list_tasks(self, filters=None, per_page=50):
                return [HubstaffTask(id="1", title="Open", due_at="2026-03-21")]

        sent = []

        def send_message(chat_id: str, text: str) -> None:
            sent.append((chat_id, text))

        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStateStore(Path(tmp) / "state.json")
            store.add_reminder(
                ReminderSubscription(
                    telegram_user_id="100",
                    chat_id="200",
                    reminder_type="open_tasks",
                    timezone="UTC",
                    last_sent_at="2026-03-21T04:00:00",
                )
            )
            engine = TaskReminderEngine(
                hubstaff_client=FakeHubstaff(),
                state_store=store,
                send_message=send_message,
            )
            aware_now = datetime(2026, 3, 21, 9, 0, tzinfo=timezone.utc)
            result = engine.run_once(now_utc=aware_now)
            self.assertEqual(result.sent_count, 1)
            self.assertEqual(len(sent), 1)

    def test_state_store_deduplicates_reminders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStateStore(Path(tmp) / "state.json")
            first = ReminderSubscription(
                telegram_user_id="100",
                chat_id="200",
                reminder_type="due_today",
                timezone="UTC",
                project_id="p1",
                assignee_id="u1",
                last_sent_at="2026-03-20T09:00:00",
            )
            second = ReminderSubscription(
                telegram_user_id="100",
                chat_id="300",
                reminder_type="due_today",
                timezone="America/New_York",
                project_id="p1",
                assignee_id="u1",
            )
            store.add_reminder(first)
            store.add_reminder(second)
            reminders = store.list_reminders()
            self.assertEqual(len(reminders), 1)
            self.assertEqual(reminders[0].chat_id, "300")
            self.assertEqual(reminders[0].timezone, "America/New_York")
            self.assertEqual(reminders[0].last_sent_at, "2026-03-20T09:00:00")

    def test_state_store_persists_last_update_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            store = TaskStateStore(state_path)
            store.set_last_update_id(123)

            reloaded = TaskStateStore(state_path)
            self.assertEqual(reloaded.last_update_id(), 123)

    def test_task_bot_run_once_persists_processed_update_offset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStateStore(Path(tmp) / "state.json")
            bot = TelegramTaskBot(
                bot_token="token",
                handlers=self.FakeHandlers(),  # type: ignore[arg-type]
                state_store=store,
                poll_timeout_seconds=1,
                poll_interval_seconds=1,
            )

            bot._get_updates = lambda: [  # type: ignore[assignment]
                {
                    "update_id": 42,
                    "message": {
                        "text": "/help",
                        "from": {"id": 100},
                        "chat": {"id": 200},
                    },
                }
            ]
            bot._send_message = lambda **kwargs: None  # type: ignore[assignment]

            exit_code = bot.run_once()
            self.assertEqual(exit_code, 0)
            self.assertEqual(store.last_update_id(), 42)

            reloaded = TaskStateStore(Path(tmp) / "state.json")
            self.assertEqual(reloaded.last_update_id(), 42)

    def test_task_bot_run_once_returns_success_on_telegram_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStateStore(Path(tmp) / "state.json")
            bot = TelegramTaskBot(
                bot_token="token",
                handlers=self.FakeHandlers(),  # type: ignore[arg-type]
                state_store=store,
                poll_timeout_seconds=1,
                poll_interval_seconds=1,
            )

            response = Mock()
            response.status_code = 409
            bot._get_updates = Mock(  # type: ignore[assignment]
                side_effect=requests.HTTPError("Conflict", response=response)
            )
            bot._delete_webhook = Mock(return_value=False)  # type: ignore[assignment]

            exit_code = bot.run_once()
            self.assertEqual(exit_code, 0)
            bot._delete_webhook.assert_called_once()
            bot._get_updates.assert_called_once()

    def test_task_bot_run_once_recovers_conflict_via_delete_webhook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStateStore(Path(tmp) / "state.json")
            bot = TelegramTaskBot(
                bot_token="token",
                handlers=self.FakeHandlers(),  # type: ignore[arg-type]
                state_store=store,
                poll_timeout_seconds=1,
                poll_interval_seconds=1,
            )

            conflict_response = Mock()
            conflict_response.status_code = 409
            bot._get_updates = Mock(  # type: ignore[assignment]
                side_effect=[
                    requests.HTTPError("Conflict", response=conflict_response),
                    [
                        {
                            "update_id": 42,
                            "message": {
                                "text": "/help",
                                "from": {"id": 100},
                                "chat": {"id": 200},
                            },
                        }
                    ],
                ]
            )
            bot._delete_webhook = Mock(return_value=True)  # type: ignore[assignment]
            bot._send_message = lambda **kwargs: None  # type: ignore[assignment]

            exit_code = bot.run_once()
            self.assertEqual(exit_code, 0)
            bot._delete_webhook.assert_called_once()
            self.assertEqual(bot._get_updates.call_count, 2)
            self.assertEqual(store.last_update_id(), 42)

    def test_task_bot_run_once_logs_processing_http_error_separately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TaskStateStore(Path(tmp) / "state.json")
            bot = TelegramTaskBot(
                bot_token="token",
                handlers=self.FakeHandlers(),  # type: ignore[arg-type]
                state_store=store,
                poll_timeout_seconds=1,
                poll_interval_seconds=1,
            )

            bot._get_updates = Mock(return_value=[])  # type: ignore[assignment]
            bot._process_updates = Mock(side_effect=requests.HTTPError("send failed"))  # type: ignore[assignment]

            with self.assertLogs("telegram_task_bot", level="ERROR") as captured:
                exit_code = bot.run_once()

            self.assertEqual(exit_code, 1)
            self.assertTrue(
                any("failed while processing updates" in line for line in captured.output)
            )


if __name__ == "__main__":
    unittest.main()
