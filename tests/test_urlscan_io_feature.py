import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import Config
from main import run_scan
from models import ScanResult, Verdict


class URLScanIOFeatureTests(unittest.TestCase):
    def test_config_reads_urlscan_settings(self) -> None:
        with patch.dict(
            os.environ,
            {
                "VT_API_KEY": "dummy",
                "URLSCAN_IO_API_KEY": "urlscan-key",
                "ENABLE_URLSCAN_IO": "true",
                "URLSCAN_IO_RPS": "3",
                "URLSCAN_IO_VISIBILITY": "public",
                "ENABLE_SUCURI_SITECHECK": "true",
                "ENABLE_CLOUDFLARE_RADAR_URL_SCANNER": "true",
            },
            clear=False,
        ):
            config = Config.from_env()
        self.assertEqual(config.urlscan_io_api_key, "urlscan-key")
        self.assertTrue(config.enable_urlscan_io)
        self.assertEqual(config.urlscan_io_requests_per_second, 3)
        self.assertEqual(config.urlscan_io_visibility, "public")
        self.assertTrue(config.enable_sucuri_sitecheck)
        self.assertTrue(config.enable_cloudflare_radar_url_scanner)

    def test_run_scan_merges_urlscan_result_and_promotes_verdict(self) -> None:
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
                    "ENABLE_URLSCAN_IO": "true",
                    "URLSCAN_IO_API_KEY": "urlscan-key",
                    "SEND_SUMMARY": "false",
                },
                clear=False,
            ):
                config = Config.from_env()
                vt_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    verdict=Verdict.CLEAN,
                    harmless_count=1,
                    total_engines=1,
                )
                urlscan_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    urlscan_io_uuid="abc-uuid",
                    urlscan_io_verdict=Verdict.MALICIOUS,
                    urlscan_io_malicious=1,
                )
                with patch("main.VirusTotalClient") as vt_cls, patch(
                    "main.URLScanIOClient"
                ) as us_cls:
                    vt_result_second = ScanResult(
                        url="https://example.org",
                        normalized_url="https://example.org",
                        domain="example.org",
                        verdict=Verdict.CLEAN,
                        harmless_count=1,
                        total_engines=1,
                    )
                    urlscan_result_second = ScanResult(
                        url="https://example.org",
                        normalized_url="https://example.org",
                        domain="example.org",
                        urlscan_io_uuid="def-uuid",
                        urlscan_io_verdict=Verdict.CLEAN,
                    )
                    vt_cls.return_value.scan_url.side_effect = [
                        vt_result,
                        vt_result_second,
                    ]
                    us_cls.return_value.scan_url.side_effect = [
                        urlscan_result,
                        urlscan_result_second,
                    ]
                    exit_code = run_scan(
                        config=config,
                        input_file=config.urls_file,
                        dry_run=False,
                        send_summary=False,
                    )

            self.assertEqual(exit_code, 0)
            latest = (results_dir / "latest_results.json").read_text(encoding="utf-8")
            self.assertIn('"urlscan_io_uuid": "abc-uuid"', latest)
            self.assertIn('"urlscan_io_verdict": "malicious"', latest)
            self.assertIn('"malicious_count": 1', latest)
            self.assertIn('"verdict": "malicious"', latest)

    def test_summary_sources_include_urlscan_when_enabled(self) -> None:
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
                    "ENABLE_URLSCAN_IO": "true",
                    "URLSCAN_IO_API_KEY": "urlscan-key",
                    "TELEGRAM_BOT_TOKEN": "token",
                    "TELEGRAM_CHAT_ID": "chat",
                    "SEND_SUMMARY": "true",
                    "REPORT_SOURCES_CHECKED": "Browser logs, spam reports, customer tickets",
                },
                clear=False,
            ):
                config = Config.from_env()
                vt_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    verdict=Verdict.CLEAN,
                    harmless_count=1,
                    total_engines=1,
                )
                urlscan_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    urlscan_io_uuid="abc-uuid",
                    urlscan_io_verdict=Verdict.MALICIOUS,
                    urlscan_io_malicious=1,
                )
                with patch("main.VirusTotalClient") as vt_cls, patch(
                    "main.URLScanIOClient"
                ) as us_cls, patch("main.TelegramClient") as tg_cls:
                    vt_cls.return_value.scan_url.return_value = vt_result
                    us_cls.return_value.scan_url.return_value = urlscan_result
                    exit_code = run_scan(
                        config=config,
                        input_file=config.urls_file,
                        dry_run=False,
                        send_summary=True,
                    )

            self.assertEqual(exit_code, 0)
            tg_cls.return_value.send_summary.assert_called_once()
            args, _ = tg_cls.return_value.send_summary.call_args
            self.assertEqual(args[1], "Browser logs, spam reports, customer tickets")
            self.assertEqual(
                args[2],
                [("https://example.com", "URLScan.io")],
            )

    def test_summary_sources_not_duplicated_when_case_differs(self) -> None:
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
                    "ENABLE_URLSCAN_IO": "true",
                    "URLSCAN_IO_API_KEY": "urlscan-key",
                    "TELEGRAM_BOT_TOKEN": "token",
                    "TELEGRAM_CHAT_ID": "chat",
                    "SEND_SUMMARY": "true",
                    "REPORT_SOURCES_CHECKED": "VirusTotal, URLScan.io",
                },
                clear=False,
            ):
                config = Config.from_env()
                vt_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    verdict=Verdict.CLEAN,
                    harmless_count=1,
                    total_engines=1,
                )
                urlscan_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    urlscan_io_uuid="abc-uuid",
                    urlscan_io_verdict=Verdict.CLEAN,
                )
                with patch("main.VirusTotalClient") as vt_cls, patch(
                    "main.URLScanIOClient"
                ) as us_cls, patch("main.TelegramClient") as tg_cls:
                    vt_cls.return_value.scan_url.return_value = vt_result
                    us_cls.return_value.scan_url.return_value = urlscan_result
                    exit_code = run_scan(
                        config=config,
                        input_file=config.urls_file,
                        dry_run=False,
                        send_summary=True,
                    )

            self.assertEqual(exit_code, 0)
            tg_cls.return_value.send_summary.assert_called_once()
            args, _ = tg_cls.return_value.send_summary.call_args
            self.assertEqual(args[1], "VirusTotal, URLScan.io")
            self.assertEqual(args[2], [])

    def test_summary_flagged_url_details_include_all_scanners_that_flagged(self) -> None:
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
                    "ENABLE_URLSCAN_IO": "true",
                    "URLSCAN_IO_API_KEY": "urlscan-key",
                    "TELEGRAM_BOT_TOKEN": "token",
                    "TELEGRAM_CHAT_ID": "chat",
                    "SEND_SUMMARY": "true",
                    "REPORT_SOURCES_CHECKED": "Browser logs, spam reports, customer tickets",
                },
                clear=False,
            ):
                config = Config.from_env()
                vt_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    verdict=Verdict.MALICIOUS,
                    malicious_count=1,
                    total_engines=1,
                )
                urlscan_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    urlscan_io_uuid="abc-uuid",
                    urlscan_io_verdict=Verdict.MALICIOUS,
                    urlscan_io_malicious=1,
                )
                with patch("main.VirusTotalClient") as vt_cls, patch(
                    "main.URLScanIOClient"
                ) as us_cls, patch("main.TelegramClient") as tg_cls:
                    vt_cls.return_value.scan_url.return_value = vt_result
                    us_cls.return_value.scan_url.return_value = urlscan_result
                    exit_code = run_scan(
                        config=config,
                        input_file=config.urls_file,
                        dry_run=False,
                        send_summary=True,
                    )

            self.assertEqual(exit_code, 0)
            tg_cls.return_value.send_summary.assert_called_once()
            args, _ = tg_cls.return_value.send_summary.call_args
            self.assertEqual(
                args[2],
                [("https://example.com", "VirusTotal, URLScan.io")],
            )

    def test_both_scanners_scan_all_urls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            urls_file = Path(tmp) / "urls.txt"
            urls_file.write_text(
                "https://example.com\nhttps://example.org\n",
                encoding="utf-8",
            )
            results_dir = Path(tmp) / "results"

            with patch.dict(
                os.environ,
                {
                    "VT_API_KEY": "dummy",
                    "URLS_FILE": str(urls_file),
                    "RESULTS_DIR": str(results_dir),
                    "ENABLE_URLSCAN_IO": "true",
                    "URLSCAN_IO_API_KEY": "urlscan-key",
                    "SEND_SUMMARY": "false",
                },
                clear=False,
            ):
                config = Config.from_env()
                vt_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    verdict=Verdict.CLEAN,
                    harmless_count=1,
                    total_engines=1,
                )
                urlscan_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    urlscan_io_uuid="abc-uuid",
                    urlscan_io_verdict=Verdict.CLEAN,
                )
                with patch("main.VirusTotalClient") as vt_cls, patch(
                    "main.URLScanIOClient"
                ) as us_cls:
                    vt_result_second = ScanResult(
                        url="https://example.org",
                        normalized_url="https://example.org",
                        domain="example.org",
                        verdict=Verdict.CLEAN,
                        harmless_count=1,
                        total_engines=1,
                    )
                    urlscan_result_second = ScanResult(
                        url="https://example.org",
                        normalized_url="https://example.org",
                        domain="example.org",
                        urlscan_io_uuid="def-uuid",
                        urlscan_io_verdict=Verdict.CLEAN,
                    )
                    vt_cls.return_value.scan_url.side_effect = [
                        vt_result,
                        vt_result_second,
                    ]
                    us_cls.return_value.scan_url.side_effect = [
                        urlscan_result,
                        urlscan_result_second,
                    ]
                    exit_code = run_scan(
                        config=config,
                        input_file=config.urls_file,
                        dry_run=False,
                        send_summary=False,
                    )

            self.assertEqual(exit_code, 0)
            self.assertEqual(vt_cls.return_value.scan_url.call_count, 2)
            self.assertEqual(us_cls.return_value.scan_url.call_count, 2)

    def test_all_scanners_scan_all_urls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            urls_file = Path(tmp) / "urls.txt"
            urls_file.write_text(
                "https://example.com\nhttps://example.org\n",
                encoding="utf-8",
            )
            results_dir = Path(tmp) / "results"

            with patch.dict(
                os.environ,
                {
                    "VT_API_KEY": "dummy",
                    "URLS_FILE": str(urls_file),
                    "RESULTS_DIR": str(results_dir),
                    "ENABLE_URLSCAN_IO": "true",
                    "URLSCAN_IO_API_KEY": "urlscan-key",
                    "ENABLE_SUCURI_SITECHECK": "true",
                    "ENABLE_CLOUDFLARE_RADAR_URL_SCANNER": "true",
                    "SEND_SUMMARY": "false",
                },
                clear=False,
            ):
                config = Config.from_env()
                vt_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    verdict=Verdict.CLEAN,
                    harmless_count=1,
                    total_engines=1,
                )
                vt_result_second = ScanResult(
                    url="https://example.org",
                    normalized_url="https://example.org",
                    domain="example.org",
                    verdict=Verdict.CLEAN,
                    harmless_count=1,
                    total_engines=1,
                )
                urlscan_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    urlscan_io_uuid="abc-uuid",
                    urlscan_io_verdict=Verdict.CLEAN,
                )
                urlscan_result_second = ScanResult(
                    url="https://example.org",
                    normalized_url="https://example.org",
                    domain="example.org",
                    urlscan_io_uuid="def-uuid",
                    urlscan_io_verdict=Verdict.CLEAN,
                )
                sucuri_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    sucuri_sitecheck_verdict=Verdict.CLEAN,
                )
                sucuri_result_second = ScanResult(
                    url="https://example.org",
                    normalized_url="https://example.org",
                    domain="example.org",
                    sucuri_sitecheck_verdict=Verdict.CLEAN,
                )
                cloudflare_result = ScanResult(
                    url="https://example.com",
                    normalized_url="https://example.com",
                    domain="example.com",
                    cloudflare_radar_verdict=Verdict.CLEAN,
                )
                cloudflare_result_second = ScanResult(
                    url="https://example.org",
                    normalized_url="https://example.org",
                    domain="example.org",
                    cloudflare_radar_verdict=Verdict.CLEAN,
                )
                with patch("main.VirusTotalClient") as vt_cls, patch(
                    "main.URLScanIOClient"
                ) as us_cls, patch("main.SucuriSiteCheckClient") as su_cls, patch(
                    "main.CloudflareRadarURLScannerClient"
                ) as cf_cls:
                    vt_cls.return_value.scan_url.side_effect = [vt_result, vt_result_second]
                    us_cls.return_value.scan_url.side_effect = [urlscan_result, urlscan_result_second]
                    su_cls.return_value.scan_url.side_effect = [sucuri_result, sucuri_result_second]
                    cf_cls.return_value.scan_url.side_effect = [cloudflare_result, cloudflare_result_second]
                    exit_code = run_scan(
                        config=config,
                        input_file=config.urls_file,
                        dry_run=False,
                        send_summary=False,
                    )

            self.assertEqual(exit_code, 0)
            self.assertEqual(vt_cls.return_value.scan_url.call_count, 2)
            self.assertEqual(us_cls.return_value.scan_url.call_count, 2)
            self.assertEqual(su_cls.return_value.scan_url.call_count, 2)
            self.assertEqual(cf_cls.return_value.scan_url.call_count, 2)


if __name__ == "__main__":
    unittest.main()
