import os
import unittest
from unittest.mock import Mock, patch

import requests

from config import Config
from virustotal_client import VirusTotalClient


class VirusTotalBackupKeyTests(unittest.TestCase):
    def test_uses_backup_key_after_429_response(self) -> None:
        with patch.dict(
            os.environ,
            {
                "VT_API_KEY": "primary-key",
                "VT_API_KEY_BACKUP": "backup-key",
            },
            clear=False,
        ):
            config = Config.from_env()

        client = VirusTotalClient(config)
        first = Mock()
        first.status_code = 429
        first.raise_for_status.side_effect = requests.HTTPError(response=first)
        second = Mock()
        second.raise_for_status.return_value = None
        second.json.return_value = {"data": {"id": "analysis-id"}}
        with patch.object(client._session, "post", side_effect=[first, second]) as post_mock:
            result = client.submit_url("https://example.com")

        self.assertEqual(result, "analysis-id")
        self.assertEqual(post_mock.call_count, 2)
        self.assertEqual(client._session.headers["x-apikey"], "backup-key")

    def test_no_backup_key_keeps_original_error(self) -> None:
        with patch.dict(
            os.environ,
            {
                "VT_API_KEY": "primary-key",
                "VT_API_KEY_BACKUP": "",
            },
            clear=False,
        ):
            config = Config.from_env()

        client = VirusTotalClient(config)
        failure = Mock()
        failure.status_code = 429
        failure.raise_for_status.side_effect = requests.HTTPError(response=failure)
        with patch.object(client._session, "get", return_value=failure) as get_mock:
            with self.assertRaises(requests.HTTPError):
                client._get("/urls/test")
        self.assertEqual(client._session.headers["x-apikey"], "primary-key")
        self.assertEqual(get_mock.call_count, 1)


if __name__ == "__main__":
    unittest.main()
