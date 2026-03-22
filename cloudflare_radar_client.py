"""Cloudflare Radar URL scanner client."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import Config
from models import ScanResult, Verdict
from utils import extract_domain, normalize_url

logger = logging.getLogger(__name__)

_CLOUDFLARE_RADAR_BASE = "https://radar.cloudflare.com/api/url-scanner"


def _build_session(config: Config) -> requests.Session:
    """Create a requests Session with retry logic."""
    session = requests.Session()
    retry = Retry(
        total=config.max_retries,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"Accept": "application/json"})
    return session


class CloudflareRadarURLScannerClient:
    """Client for Cloudflare Radar URL Scanner."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._session = _build_session(config)

    def _get(self, url: str) -> dict[str, Any]:
        encoded = quote(url, safe="")
        endpoint = f"{_CLOUDFLARE_RADAR_BASE}/{encoded}"
        resp = self._session.get(
            endpoint,
            timeout=self._config.request_timeout_seconds,
        )
        resp.raise_for_status()
        return resp.json()

    def scan_url(self, raw_url: str) -> ScanResult:
        """Scan URL with Cloudflare Radar and map to ScanResult."""
        norm = normalize_url(raw_url)
        domain = extract_domain(norm)
        result = ScanResult(url=raw_url, normalized_url=norm, domain=domain)
        try:
            payload = self._get(norm)
            info = payload.get("result", payload)
            classification = str(info.get("classification", "")).lower()
            malicious = classification in {"malicious", "phishing"}
            suspicious = classification in {"suspicious", "spam"}
            if malicious:
                result.cloudflare_radar_malicious = 1
                result.cloudflare_radar_verdict = Verdict.MALICIOUS
            elif suspicious:
                result.cloudflare_radar_suspicious = 1
                result.cloudflare_radar_verdict = Verdict.SUSPICIOUS
            else:
                result.cloudflare_radar_verdict = Verdict.CLEAN
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "?"
            logger.error(
                "Cloudflare Radar HTTP error %s while scanning %s: %s",
                status_code,
                norm,
                exc,
            )
            result.error = f"Cloudflare Radar HTTP {status_code}: {exc}"
            result.cloudflare_radar_verdict = Verdict.UNKNOWN
        except Exception as exc:
            logger.error("Unexpected Cloudflare Radar error while scanning %s: %s", norm, exc)
            result.error = f"Cloudflare Radar error: {exc}"
            result.cloudflare_radar_verdict = Verdict.UNKNOWN
        return result
