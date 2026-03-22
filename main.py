"""Main entry point for the Daily Malicious URL Checker."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

# Load .env file if present (no-op when not found)
try:
    from dotenv import load_dotenv

    load_dotenv(override=False)
except ImportError:
    pass  # python-dotenv is listed in requirements.txt; this is a safety guard

from config import Config
from models import RunSummary, ScanResult, Verdict
from storage import Storage
from telegram_client import TelegramClient
from urlscan_io_client import URLScanIOClient
from utils import (
    extract_domain,
    is_valid_url,
    normalize_url,
    read_urls,
    setup_logging,
)
from virustotal_client import VirusTotalClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------

def _should_send_malicious_alert(
    result: ScanResult, previous: Optional[ScanResult]
) -> bool:
    if result.verdict != Verdict.MALICIOUS:
        return False
    if previous is None:
        return True
    if previous.verdict != Verdict.MALICIOUS:
        return True
    # Malicious count increased
    if result.malicious_count > previous.malicious_count:
        return True
    return False


def _should_send_suspicious_alert(
    result: ScanResult, previous: Optional[ScanResult]
) -> bool:
    if result.verdict != Verdict.SUSPICIOUS:
        return False
    if previous is None:
        return True
    if previous.verdict not in (Verdict.SUSPICIOUS, Verdict.MALICIOUS):
        return True
    # Suspicious count materially increased (by more than 1 engine)
    if result.suspicious_count > (previous.suspicious_count or 0) + 1:
        return True
    return False


def _should_send_clean_alert(
    result: ScanResult,
    previous: Optional[ScanResult],
    config: Config,
) -> bool:
    if not config.alert_on_clean:
        return False
    if result.verdict != Verdict.CLEAN:
        return False
    if previous is None:
        return False
    return previous.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)


def _domain_worsened(
    result: ScanResult, previous: Optional[ScanResult]
) -> bool:
    """Return True if the domain reputation significantly worsened."""
    if not result.domain_result:
        return False
    new_mal = result.domain_result.last_analysis_stats.get("malicious", 0)
    if new_mal == 0:
        return False
    if previous is None or not previous.domain_result:
        return True
    old_mal = previous.domain_result.last_analysis_stats.get("malicious", 0)
    return new_mal > old_mal


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------

def run_scan(
    config: Config,
    input_file: Path,
    dry_run: bool = False,
    send_summary: bool = True,
) -> int:
    """
    Main scan loop. Returns exit code (0 = success, 1 = errors occurred).
    """
    storage = Storage(config.results_dir)
    vt_client = VirusTotalClient(config)
    urlscan_client: Optional[URLScanIOClient] = None
    if config.enable_urlscan_io and config.urlscan_io_api_key:
        urlscan_client = URLScanIOClient(config)
        logger.info("URLScan.io scanner enabled")
    telegram: Optional[TelegramClient] = None
    if config.telegram_enabled:
        telegram = TelegramClient(config.telegram_bot_token, config.telegram_chat_id)
    else:
        logger.warning(
            "Telegram is not configured – alerts will be logged only. "
            "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to enable."
        )

    # Load previous results for change detection
    previous_results = storage.load_previous_results()

    # Read and validate URLs
    try:
        raw_urls = read_urls(input_file)
    except FileNotFoundError:
        logger.error("URL input file not found: %s", input_file)
        return 1

    if not raw_urls:
        logger.warning("No URLs found in %s – nothing to do", input_file)
        return 0

    logger.info("Read %d URL(s) from %s", len(raw_urls), input_file)

    results: list[ScanResult] = []
    summary = RunSummary()
    has_errors = False

    for raw_url in raw_urls:
        norm = normalize_url(raw_url)
        domain = extract_domain(norm)
        summary.total += 1

        if not is_valid_url(norm):
            logger.warning("Skipping malformed URL: %s", raw_url)
            err_result = ScanResult(
                url=raw_url,
                normalized_url=norm,
                domain=domain,
                verdict=Verdict.UNKNOWN,
                error="Malformed URL – skipped",
            )
            results.append(err_result)
            summary.failed += 1
            summary.unknown += 1
            has_errors = True
            continue

        logger.info("Scanning: %s", norm)
        if dry_run:
            logger.info("[DRY RUN] Would scan %s (skipped)", norm)
            results.append(
                ScanResult(
                    url=raw_url,
                    normalized_url=norm,
                    domain=domain,
                    verdict=Verdict.UNKNOWN,
                    error="dry-run",
                )
            )
            summary.unknown += 1
            continue

        result = vt_client.scan_url(raw_url)
        if urlscan_client:
            urlscan_result = urlscan_client.scan_url(raw_url)
            result.urlscan_io_uuid = urlscan_result.urlscan_io_uuid
            result.urlscan_io_verdict = urlscan_result.urlscan_io_verdict
            result.urlscan_io_malicious = urlscan_result.urlscan_io_malicious
            result.urlscan_io_suspicious = urlscan_result.urlscan_io_suspicious
            result.malicious_count += urlscan_result.urlscan_io_malicious
            result.suspicious_count += urlscan_result.urlscan_io_suspicious
            if result.urlscan_io_verdict == Verdict.MALICIOUS:
                result.verdict = Verdict.MALICIOUS
            elif (
                result.urlscan_io_verdict == Verdict.SUSPICIOUS
                and result.verdict != Verdict.MALICIOUS
            ):
                result.verdict = Verdict.SUSPICIOUS
            if result.urlscan_io_verdict in (
                Verdict.MALICIOUS,
                Verdict.SUSPICIOUS,
                Verdict.CLEAN,
            ):
                result.total_engines += 1
        results.append(result)

        # Update summary counters
        if result.error and result.verdict == Verdict.UNKNOWN:
            summary.failed += 1
        match result.verdict:
            case Verdict.MALICIOUS:
                summary.malicious += 1
            case Verdict.SUSPICIOUS:
                summary.suspicious += 1
            case Verdict.CLEAN:
                summary.clean += 1
            case _:
                summary.unknown += 1

        # Change detection
        previous = previous_results.get(result.normalized_url)

        if _should_send_malicious_alert(result, previous):
            summary.newly_malicious += 1
            if previous and previous.verdict in (Verdict.MALICIOUS,):
                summary.worsened += 1
            logger.warning("MALICIOUS: %s (%d engines)", norm, result.malicious_count)
            if telegram:
                telegram.send_malicious_alert(result, previous)
        elif _should_send_suspicious_alert(result, previous):
            summary.newly_suspicious += 1
            logger.warning("SUSPICIOUS: %s (%d engines)", norm, result.suspicious_count)
            if telegram:
                telegram.send_suspicious_alert(result, previous)
        elif _should_send_clean_alert(result, previous, config):
            summary.improved += 1
            logger.info("NOW CLEAN: %s", norm)
            if telegram:
                telegram.send_clean_alert(result, previous)
        else:
            summary.unchanged += 1

        # Check domain reputation separately
        if _domain_worsened(result, previous) and telegram:
            telegram.send_domain_alert(result)

    # Persist results
    if not dry_run:
        storage.save_results(results, summary)

    # Optional summary alert
    if send_summary and telegram and not dry_run:
        sources_checked = config.report_sources_checked
        if urlscan_client and "urlscan.io" not in sources_checked.lower():
            sources_checked = f"{sources_checked}, URLScan.io"
        telegram.send_summary(summary, sources_checked)

    logger.info(
        "Run complete – total=%d malicious=%d suspicious=%d clean=%d "
        "unknown=%d failed=%d",
        summary.total,
        summary.malicious,
        summary.suspicious,
        summary.clean,
        summary.unknown,
        summary.failed,
    )
    return 1 if has_errors else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Daily Malicious URL Checker using VirusTotal API v3"
    )
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Run the scanner once and exit (default behaviour)",
    )
    parser.add_argument(
        "--input",
        metavar="FILE",
        default=None,
        help="Path to URL list file (overrides URLS_FILE env var)",
    )
    parser.add_argument(
        "--alert-summary",
        action="store_true",
        help="Send a Telegram summary message at end of run",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and normalise URLs but do not call VirusTotal or send alerts",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug-level logging",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    setup_logging(debug=args.debug)

    # Load config – will raise EnvironmentError if VT_API_KEY is missing
    try:
        config = Config.from_env()
    except EnvironmentError as exc:
        # Use print here because logging may not be fully configured yet
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    # Override config from CLI flags
    if args.input:
        config.urls_file = Path(args.input)
    if args.alert_summary:
        config.send_summary = True

    return run_scan(
        config=config,
        input_file=config.urls_file,
        dry_run=args.dry_run,
        send_summary=config.send_summary,
    )


if __name__ == "__main__":
    sys.exit(main())
