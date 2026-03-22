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

    def test_telegram_summary_flagged_details_are_truncated_to_fit_limit(self) -> None:
        client = TelegramClient("token", "chat")
        summary = RunSummary(total=200, malicious=200, suspicious=0)
        flagged_url_details = [
            (
                f"https://example{i:03d}.very-long-domain-name-for-telegram-summary-limit-test.example/path/segment/extra",
                "VirusTotal, URLScan.io, Sucuri SiteCheck, Cloudflare Radar URL Scanner",
            )
            for i in range(1, 200)
        ]
        text = client._build_summary_text(
            summary,
            "VirusTotal, URLScan.io, Sucuri SiteCheck, Cloudflare Radar URL Scanner",
            flagged_url_details=flagged_url_details,
            include_scan_date=False,
            include_flag_removal=False,
        )
        self.assertLessEqual(len(text), 4096)
        self.assertIn("Flagged URL Details", text)
        self.assertIn("…and", text)

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

    def test_config_supports_multiple_telegram_chat_ids(self) -> None:
        with patch.dict(
            os.environ,
            {
                "VT_API_KEY": "dummy",
                "TELEGRAM_BOT_TOKEN": "token",
                "TELEGRAM_CHAT_ID": "1001, 1002 ,1003",
            },
            clear=False,
        ):
            config = Config.from_env()
        self.assertEqual(config.telegram_chat_ids, ["1001", "1002", "1003"])
        self.assertTrue(config.telegram_enabled)

    def test_telegram_client_sends_message_to_all_chat_ids(self) -> None:
        client = TelegramClient("token", "1001, 1002")
        with patch("telegram_client.requests.post") as post:
            post.return_value.raise_for_status.return_value = None
            sent = client.send_summary(RunSummary(total=1), "VirusTotal", [])
        self.assertTrue(sent)
        self.assertEqual(post.call_count, 2)
        first_payload = post.call_args_list[0].kwargs["json"]
        second_payload = post.call_args_list[1].kwargs["json"]
        self.assertEqual(first_payload["chat_id"], "1001")
        self.assertEqual(second_payload["chat_id"], "1002")

    def test_telegram_client_accepts_chat_id_list(self) -> None:
        client = TelegramClient("token", ["1001", " 1002 "])
        with patch("telegram_client.requests.post") as post:
            post.return_value.raise_for_status.return_value = None
            sent = client.send_summary(RunSummary(total=1), "VirusTotal", [])
        self.assertTrue(sent)
        self.assertEqual(post.call_count, 2)

    def test_telegram_client_returns_false_on_partial_multi_chat_failure(self) -> None:
        client = TelegramClient("token", "1001,1002")
        with patch("telegram_client.requests.post") as post:
            post.side_effect = [Exception("boom"), post.return_value]
            post.return_value.raise_for_status.return_value = None
            sent = client.send_summary(RunSummary(total=1), "VirusTotal", [])
        self.assertFalse(sent)
        self.assertEqual(post.call_count, 2)


if __name__ == "__main__":
    unittest.main()
