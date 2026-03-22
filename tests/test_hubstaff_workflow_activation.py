import unittest
from pathlib import Path


class HubstaffWorkflowActivationTests(unittest.TestCase):
    _REPO_ROOT = Path(__file__).resolve().parents[1]

    def test_hubstaff_task_bot_workflow_exists_with_activation_env(self) -> None:
        workflow = (
            self._REPO_ROOT / ".github/workflows/hubstaff-task-bot.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("python bot_entrypoint.py --run-once", workflow)
        self.assertIn('ENABLE_HUBSTAFF_TASKS_BOT: "true"', workflow)
        self.assertIn("HUBSTAFF_TOKEN: ${{ secrets.HUBSTAFF_TOKEN }}", workflow)
        self.assertIn("TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}", workflow)


if __name__ == "__main__":
    unittest.main()
