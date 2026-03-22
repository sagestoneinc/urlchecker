import unittest
from pathlib import Path

import yaml


class HubstaffWorkflowActivationTests(unittest.TestCase):
    _REPO_ROOT = Path(__file__).resolve().parents[1]

    def test_workflow_file_contains_required_configuration(self) -> None:
        workflow_path = self._REPO_ROOT / ".github/workflows/hubstaff-task-bot.yml"
        self.assertTrue(
            workflow_path.is_file(),
            f"Expected workflow file to exist at {workflow_path!s}",
        )
        workflow = yaml.load(workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

        jobs = workflow.get("jobs", {}) or {}
        task_bot = jobs.get("task-bot", {}) or {}
        self.assertEqual(
            task_bot.get("if"),
            "${{ secrets.HUBSTAFF_TOKEN != '' && secrets.TELEGRAM_BOT_TOKEN != '' }}",
        )

        steps = task_bot.get("steps", []) or []
        step_with_run = next(
            (
                step
                for step in steps
                if isinstance(step, dict) and step.get("run") == "python bot_entrypoint.py --run-once"
            ),
            None,
        )
        self.assertIsNotNone(step_with_run)

        env = step_with_run.get("env", {}) if isinstance(step_with_run, dict) else {}
        self.assertEqual(env.get("ENABLE_HUBSTAFF_TASKS_BOT"), "true")
        self.assertEqual(env.get("HUBSTAFF_TOKEN"), "${{ secrets.HUBSTAFF_TOKEN }}")
        self.assertEqual(env.get("TELEGRAM_BOT_TOKEN"), "${{ secrets.TELEGRAM_BOT_TOKEN }}")
        self.assertEqual(
            env.get("TASKBOT_USER_MAPPING_JSON"),
            "${{ secrets.TASKBOT_USER_MAPPING_JSON }}",
        )

    def test_workflow_yaml_structure_is_valid(self) -> None:
        workflow_path = self._REPO_ROOT / ".github/workflows/hubstaff-task-bot.yml"
        workflow = yaml.load(workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

        self.assertIsInstance(workflow, dict)
        self.assertEqual(workflow.get("name"), "Hubstaff Tasks Bot")

        on_block = workflow.get("on")
        self.assertIsInstance(on_block, dict)
        self.assertIn("schedule", on_block)
        self.assertIn("workflow_dispatch", on_block)

        jobs = workflow.get("jobs")
        self.assertIsInstance(jobs, dict)
        self.assertIn("task-bot", jobs)

        task_bot = jobs["task-bot"]
        self.assertEqual(task_bot.get("runs-on"), "ubuntu-latest")
        self.assertEqual(workflow.get("concurrency", {}).get("group"), "hubstaff-task-bot")
        self.assertEqual(workflow.get("concurrency", {}).get("cancel-in-progress"), "true")

        steps = task_bot.get("steps", [])
        self.assertTrue(any(step.get("run") == "python bot_entrypoint.py --run-once" for step in steps))


if __name__ == "__main__":
    unittest.main()
