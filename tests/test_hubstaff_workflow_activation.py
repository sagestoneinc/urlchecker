import unittest
from pathlib import Path

import yaml


class HubstaffWorkflowActivationTests(unittest.TestCase):
    _REPO_ROOT = Path(__file__).resolve().parents[1]

    def test_workflow_file_contains_required_configuration(self) -> None:
        workflow = (
            self._REPO_ROOT / ".github/workflows/hubstaff-task-bot.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("python bot_entrypoint.py --run-once", workflow)
        self.assertIn('ENABLE_HUBSTAFF_TASKS_BOT: "true"', workflow)
        self.assertIn("HUBSTAFF_TOKEN: ${{ secrets.HUBSTAFF_TOKEN }}", workflow)
        self.assertIn("TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}", workflow)

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

        steps = task_bot.get("steps", [])
        self.assertTrue(any(step.get("run") == "python bot_entrypoint.py --run-once" for step in steps))


if __name__ == "__main__":
    unittest.main()
