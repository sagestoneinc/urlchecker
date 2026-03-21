import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import Config
from main import _parse_args, run_scan
from models import RunSummary, ScanResult, Verdict
from storage import Storage
from telegram_client import TelegramClient


class RegressionCompatibilityTests(unittest.TestCase):
    _REPO_ROOT = Path(__file__).resolve().parents[1]

    def test_cli_flags_parse(self) -> None:
        with patch("sys.argv", ["main.py", "--run-once", "--dry-run", "--alert-summary", "--debug", "--input", "my_urls.txt"]):
            args = _parse_args()
        self.assertTrue(args.run_once)
        self.assertTrue(args.dry_run)
        self.assertTrue(args.alert_summary)
        self.assertTrue(args.debug)
        self.assertEqual(args.input, "my_urls.txt")

    def test_storage_persists_expected_result_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp))
            result = ScanResult(
                url="https://example.com",
                normalized_url="https://example.com",
                domain="example.com",
                verdict=Verdict.CLEAN,
                harmless_count=10,
                total_engines=10,
            )
            summary = RunSummary(total=1, clean=1)
            storage.save_results([result], summary)

            self.assertTrue(storage.latest_path.exists())
            self.assertTrue(storage.history_path.exists())
            self.assertTrue(storage.csv_path.exists())
            self.assertTrue(storage.summary_path.exists())

    def test_telegram_summary_format_preserved(self) -> None:
        client = TelegramClient("token", "chat")
        summary = RunSummary(total=10, malicious=2, suspicious=1)
        text = client._build_summary_text(
            summary,
            "VirusTotal",
            include_scan_date=True,
            include_flag_removal=True,
        )
        self.assertIn("Malicious URL Checks", text)
        self.assertIn("Sources Checked", text)
        self.assertIn("Request Flag Removal", text)

    def test_issue_comment_commands_workflow_contains_expected_commands(self) -> None:
        workflow = (self._REPO_ROOT / ".github/workflows/url-bot-commands.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("/add-link ", workflow)
        self.assertIn("/rescan ", workflow)

    def test_old_scan_flow_works_when_hubstaff_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            urls_file = Path(tmp) / "urls.txt"
            urls_file.write_text("https://example.com\n", encoding="utf-8")
            results_dir = Path(tmp) / "results"
            with patch.dict(
                os.environ,
                {
                    "VT_API_KEY": "dummy",
                    "URLS_FILE": str(urls_file),
                    "RESULTS_DIR": str(results_dir),
                    "ENABLE_HUBSTAFF_TASKS_BOT": "false",
                },
                clear=False,
            ):
                config = Config.from_env()
                exit_code = run_scan(
                    config=config,
                    input_file=config.urls_file,
                    dry_run=True,
                    send_summary=False,
                )
            self.assertEqual(exit_code, 0)
            self.assertFalse((results_dir / "latest_results.json").exists())


if __name__ == "__main__":
    unittest.main()
