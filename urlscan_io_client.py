"""URLScan.io API v1 client with retries and simple rate limiting."""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import Config
from models import ScanResult, Verdict
from utils import extract_domain, normalize_url

logger = logging.getLogger(__name__)

_URLSCAN_BASE = "https://urlscan.io/api/v1"
_SUSPICIOUS_SCORE_THRESHOLD = 0


def _build_session(config: Config) -> requests.Session:
    """Create a requests Session with retry logic and URLScan auth header."""
    session = requests.Session()
    retry = Retry(
        total=config.max_retries,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(
        {
            "API-Key": config.urlscan_io_api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
    )
    return session


class RateLimiter:
    """Token-bucket style rate limiter (requests per second)."""

    def __init__(self, requests_per_second: int) -> None:
        self._min_interval = 1.0 / max(requests_per_second, 1)
        self._last_call: float = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last_call
        sleep_for = self._min_interval - elapsed
        if sleep_for > 0:
            logger.debug("URLScan rate limiter: sleeping %.2f s", sleep_for)
            time.sleep(sleep_for)
        self._last_call = time.monotonic()


class URLScanIOClient:
    """Client for urlscan.io scan submissions and results."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._session = _build_session(config)
        self._limiter = RateLimiter(
            requests_per_second=config.urlscan_io_requests_per_second
        )

    def _get(self, path: str) -> dict[str, Any]:
        self._limiter.wait()
        url = f"{_URLSCAN_BASE}{path}"
        resp = self._session.get(url, timeout=self._config.request_timeout_seconds)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._limiter.wait()
        url = f"{_URLSCAN_BASE}{path}"
        resp = self._session.post(
            url,
            json=payload,
            timeout=self._config.request_timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()

    def submit_url(self, url: str) -> str:
        """Submit URL and return scan UUID."""
        response = self._post(
            "/scan/",
            {"url": url, "visibility": self._config.urlscan_io_visibility},
        )
        uuid = response.get("uuid", "")
        if not uuid:
            raise ValueError("URLScan submission did not return uuid")
        return uuid

    def poll_result(self, uuid: str) -> Optional[dict[str, Any]]:
        """Poll URLScan result endpoint until available."""
        for attempt in range(1, self._config.poll_max_attempts + 1):
            try:
                data = self._get(f"/result/{uuid}/")
                if data:
                    return data
            except requests.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 404:
                    logger.debug(
                        "URLScan result not ready for %s (attempt %d/%d)",
                        uuid,
                        attempt,
                        self._config.poll_max_attempts,
                    )
                else:
                    raise
            time.sleep(self._config.poll_interval_seconds)
        logger.warning(
            "URLScan result %s did not complete after %d attempts",
            uuid,
            self._config.poll_max_attempts,
        )
        return None

    def scan_url(self, raw_url: str) -> ScanResult:
        """Run URLScan submission + polling and map to ScanResult."""
        norm = normalize_url(raw_url)
        domain = extract_domain(norm)
        result = ScanResult(url=raw_url, normalized_url=norm, domain=domain)
        try:
            uuid = self.submit_url(norm)
            result.urlscan_io_uuid = uuid
            report = self.poll_result(uuid)
            if not report:
                result.urlscan_io_verdict = Verdict.UNKNOWN
                return result
            verdicts = report.get("verdicts", {})
            overall = verdicts.get("overall", {}) if isinstance(verdicts, dict) else {}
            malicious = 0
            suspicious = 0
            if overall.get("malicious"):
                malicious = 1
            elif overall.get("score", 0) > _SUSPICIOUS_SCORE_THRESHOLD:
                suspicious = 1
            result.urlscan_io_malicious = malicious
            result.urlscan_io_suspicious = suspicious
            if malicious > 0:
                result.urlscan_io_verdict = Verdict.MALICIOUS
            elif suspicious > 0:
                result.urlscan_io_verdict = Verdict.SUSPICIOUS
            else:
                result.urlscan_io_verdict = Verdict.CLEAN
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "?"
            logger.error("URLScan HTTP error %s while scanning %s: %s", status_code, norm, exc)
            result.error = f"URLScan HTTP {status_code}: {exc}"
            result.urlscan_io_verdict = Verdict.UNKNOWN
        except Exception as exc:
            logger.error("Unexpected URLScan error while scanning %s: %s", norm, exc)
            result.error = f"URLScan error: {exc}"
            result.urlscan_io_verdict = Verdict.UNKNOWN
        return result
