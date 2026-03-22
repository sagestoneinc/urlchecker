"""VirusTotal API v3 client with rate limiting, retries, and exponential backoff."""

from __future__ import annotations

import logging
import time
from typing import Any, Optional
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import Config
from models import DomainResult, ScanResult, Verdict
from utils import extract_domain, normalize_url, vt_url_id

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
_VT_APIKEY_HEADER = "x-apikey"


def _build_session(config: Config) -> requests.Session:
    """Create a requests Session with retry logic and VT auth header."""
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
    # Set auth header – value is never logged
    session.headers.update(
        {
            _VT_APIKEY_HEADER: config.vt_api_key,
            "Accept": "application/json",
        }
    )
    return session


class RateLimiter:
    """Token-bucket style rate limiter (requests per minute)."""

    def __init__(self, requests_per_minute: int) -> None:
        self._min_interval = 60.0 / max(requests_per_minute, 1)
        self._last_call: float = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last_call
        sleep_for = self._min_interval - elapsed
        if sleep_for > 0:
            logger.debug("Rate limiter: sleeping %.1f s", sleep_for)
            time.sleep(sleep_for)
        self._last_call = time.monotonic()

    def reset(self) -> None:
        self._last_call = 0.0


class VirusTotalClient:
    """Client for VirusTotal API v3."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._session = _build_session(config)
        self._limiter = RateLimiter(config.rate_limit_requests_per_minute)
        self._using_backup_api_key = False

    def _switch_to_backup_api_key(self) -> bool:
        backup_api_key = self._config.vt_api_key_backup
        if self._using_backup_api_key or not backup_api_key:
            return False
        self._session.headers.update({_VT_APIKEY_HEADER: backup_api_key})
        self._using_backup_api_key = True
        self._limiter.reset()
        logger.warning("Primary VirusTotal API key hit rate limits; switching to backup API key")
        return True

    def _request_with_backup_fallback(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        self._limiter.wait()
        url = f"{_VT_BASE}{path}"
        request_method = getattr(self._session, method)
        resp = request_method(url, timeout=self._config.request_timeout_seconds, **kwargs)
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            if resp.status_code == 429 and self._switch_to_backup_api_key():
                self._limiter.wait()
                resp = request_method(
                    url,
                    timeout=self._config.request_timeout_seconds,
                    **kwargs,
                )
                resp.raise_for_status()
            else:
                raise
        return resp

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str) -> dict[str, Any]:
        """Perform a rate-limited GET request and return parsed JSON."""
        resp = self._request_with_backup_fallback("get", path)
        return resp.json()

    def _post(self, path: str, data: dict) -> dict[str, Any]:
        """Perform a rate-limited POST request and return parsed JSON."""
        resp = self._request_with_backup_fallback("post", path, data=data)
        return resp.json()

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def submit_url(self, url: str) -> str:
        """
        Submit a URL for analysis via POST /api/v3/urls.
        Returns the analysis ID for subsequent polling.
        """
        logger.debug("Submitting URL for analysis: %s", url)
        payload = {"url": url}
        response = self._post("/urls", payload)
        analysis_id: str = response["data"]["id"]
        logger.debug("Got analysis ID: %s", analysis_id)
        return analysis_id

    def poll_analysis(self, analysis_id: str) -> Optional[dict[str, Any]]:
        """
        Poll GET /api/v3/analyses/{id} until the analysis is complete.
        Returns the 'stats' dict or None on timeout.
        """
        for attempt in range(1, self._config.poll_max_attempts + 1):
            logger.debug(
                "Polling analysis %s (attempt %d/%d)",
                analysis_id,
                attempt,
                self._config.poll_max_attempts,
            )
            data = self._get(f"/analyses/{analysis_id}")
            status = data.get("data", {}).get("attributes", {}).get("status", "")
            if status == "completed":
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("stats", {})
                )
                logger.debug("Analysis completed: %s", stats)
                return stats
            logger.debug("Analysis status: %s – waiting %d s", status, self._config.poll_interval_seconds)
            time.sleep(self._config.poll_interval_seconds)
        logger.warning("Analysis %s did not complete after %d attempts", analysis_id, self._config.poll_max_attempts)
        return None

    def get_url_report(self, normalized_url: str) -> Optional[dict[str, Any]]:
        """
        Retrieve URL report from GET /api/v3/urls/{id}.
        Returns the 'last_analysis_stats' dict or None.
        """
        url_id = vt_url_id(normalized_url)
        logger.debug("Fetching URL report for id: %s", url_id)
        try:
            data = self._get(f"/urls/{url_id}")
            attrs = data.get("data", {}).get("attributes", {})
            return attrs.get("last_analysis_stats")
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                logger.debug("URL not yet in VT database, will use submitted analysis stats")
                return None
            raise

    def get_domain_info(self, domain: str) -> Optional[DomainResult]:
        """
        Retrieve domain reputation from GET /api/v3/domains/{domain}.
        Returns a DomainResult or None on error.
        """
        logger.debug("Fetching domain info: %s", domain)
        try:
            data = self._get(f"/domains/{domain}")
            attrs = data.get("data", {}).get("attributes", {})
            total_votes = attrs.get("total_votes", {})
            return DomainResult(
                domain=domain,
                malicious_votes=total_votes.get("malicious", 0),
                harmless_votes=total_votes.get("harmless", 0),
                suspicious_votes=attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                reputation=attrs.get("reputation", 0),
                categories=attrs.get("categories", {}),
                last_analysis_stats=attrs.get("last_analysis_stats", {}),
                raw=attrs,
            )
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                logger.debug("Domain %s not found in VirusTotal", domain)
                return None
            logger.warning("Error fetching domain info for %s: %s", domain, exc)
            return None
        except Exception as exc:
            logger.warning("Unexpected error fetching domain info for %s: %s", domain, exc)
            return None

    # ------------------------------------------------------------------
    # High-level scan method
    # ------------------------------------------------------------------

    def scan_url(self, raw_url: str) -> ScanResult:
        """
        Full scan pipeline for a single URL:
        1. Normalise and validate
        2. Submit URL → get analysis ID
        3. Poll until complete
        4. Optionally fetch URL report for richer stats
        5. Fetch domain context
        6. Derive verdict
        Returns a ScanResult.
        """
        norm = normalize_url(raw_url)
        domain = extract_domain(norm)

        result = ScanResult(
            url=raw_url,
            normalized_url=norm,
            domain=domain,
        )

        try:
            # Step 1 – submit
            analysis_id = self.submit_url(norm)
            result.analysis_id = analysis_id

            # Step 2 – poll
            stats = self.poll_analysis(analysis_id)

            if stats is None:
                # Fallback: try to fetch a cached report
                logger.info("Polling timed out; trying cached URL report for %s", norm)
                stats = self.get_url_report(norm)

            if stats:
                result.malicious_count = stats.get("malicious", 0)
                result.suspicious_count = stats.get("suspicious", 0)
                result.harmless_count = stats.get("harmless", 0)
                result.undetected_count = stats.get("undetected", 0)
                result.timeout_count = stats.get("timeout", 0)
                result.total_engines = sum(stats.values())
                result.verdict = _derive_verdict(result)
            else:
                result.verdict = Verdict.UNKNOWN
                logger.warning("No analysis stats available for %s", norm)

            # Step 3 – domain context
            if domain:
                result.domain_result = self.get_domain_info(domain)

        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "?"
            logger.error("HTTP error %s while scanning %s: %s", status_code, norm, exc)
            result.error = f"HTTP {status_code}: {exc}"
        except Exception as exc:
            logger.error("Unexpected error scanning %s: %s", norm, exc)
            result.error = str(exc)

        return result


def _derive_verdict(result: ScanResult) -> Verdict:
    """Map raw engine counts to a verdict."""
    if result.malicious_count > 0:
        return Verdict.MALICIOUS
    if result.suspicious_count > 0:
        return Verdict.SUSPICIOUS
    # Need some meaningful data to call it clean
    meaningful_count = result.harmless_count + result.undetected_count
    if meaningful_count > 0:
        return Verdict.CLEAN
    return Verdict.UNKNOWN
