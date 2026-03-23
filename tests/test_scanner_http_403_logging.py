import os
import unittest
from unittest.mock import Mock, patch

import requests

from cloudflare_radar_client import CloudflareRadarURLScannerClient
from config import Config
from models import Verdict
from sucuri_sitecheck_client import SucuriSiteCheckClient


class ScannerHttp403LoggingTests(unittest.TestCase):
    def _config(self) -> Config:
        with patch.dict(
            os.environ,
            {
                "VT_API_KEY": "dummy",
            },
            clear=False,
        ):
            return Config.from_env()

    def test_sucuri_403_logs_at_debug_level_and_returns_unknown(self) -> None:
        client = SucuriSiteCheckClient(self._config())
        response = Mock()
        response.status_code = 403
        error = requests.HTTPError("403 Client Error: Forbidden", response=response)
        with patch.object(client, "_get", side_effect=error), patch(
            "sucuri_sitecheck_client.logger"
        ) as logger_mock:
            result = client.scan_url("https://example.com")

        logger_mock.debug.assert_called_once()
        logger_mock.error.assert_not_called()
        self.assertEqual(result.sucuri_sitecheck_verdict, Verdict.UNKNOWN)
        self.assertIn("Sucuri HTTP 403", result.error)

    def test_cloudflare_403_logs_at_debug_level_and_returns_unknown(self) -> None:
        client = CloudflareRadarURLScannerClient(self._config())
        response = Mock()
        response.status_code = 403
        error = requests.HTTPError("403 Client Error: Forbidden", response=response)
        with patch.object(client, "_get", side_effect=error), patch(
            "cloudflare_radar_client.logger"
        ) as logger_mock:
            result = client.scan_url("https://example.com")

        logger_mock.debug.assert_called_once()
        logger_mock.error.assert_not_called()
        self.assertEqual(result.cloudflare_radar_verdict, Verdict.UNKNOWN)
        self.assertIn("Cloudflare Radar HTTP 403", result.error)


if __name__ == "__main__":
    unittest.main()
