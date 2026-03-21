import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from hubstaff_auth import HubstaffAuth
from hubstaff_client import HubstaffClient
from hubstaff_models import HubstaffTask
from task_reminders import TaskReminderEngine
from task_state_store import ReminderSubscription, TaskStateStore
from telegram_task_handlers import TelegramTaskHandlers


class HubstaffFeatureTests(unittest.TestCase):
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
            handlers = TelegramTaskHandlers(hubstaff_client=FakeHubstaff(), state_store=store)

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

            finish_edit = handlers.handle_command(telegram_user_id="100", chat_id="200", text="Updated title")
            self.assertIn("updated", finish_edit.text.lower())

            callback = handlers.handle_callback_query(telegram_user_id="100", data="task:1")
            self.assertIn("Task #1", callback.text)

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


if __name__ == "__main__":
    unittest.main()
