"""Telegram bot client for sending alerts and summaries."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import requests

from models import RunSummary, ScanResult, Verdict

logger = logging.getLogger(__name__)

_TELEGRAM_API = "https://api.telegram.org"


class TelegramClient:
    """Send messages to a Telegram chat via the Bot API."""

    def __init__(self, bot_token: str, chat_id: str) -> None:
        # Tokens are never logged
        self._token = bot_token
        self._chat_id = chat_id
        self._base = f"{_TELEGRAM_API}/bot{bot_token}"

    def _send(self, text: str, parse_mode: str = "HTML") -> bool:
        """Send a message; return True on success."""
        try:
            resp = requests.post(
                f"{self._base}/sendMessage",
                json={
                    "chat_id": self._chat_id,
                    "text": text,
                    "parse_mode": parse_mode,
                    "disable_web_page_preview": True,
                },
                timeout=15,
            )
            resp.raise_for_status()
            return True
        except requests.HTTPError as exc:
            logger.error("Telegram HTTP error: %s", exc)
        except Exception as exc:
            logger.error("Telegram send failed: %s", exc)
        return False

    # ------------------------------------------------------------------
    # Alert messages
    # ------------------------------------------------------------------

    def send_malicious_alert(
        self,
        result: ScanResult,
        previous: Optional[ScanResult] = None,
    ) -> bool:
        """Send an alert for a newly malicious URL."""
        change_note = ""
        if previous and previous.verdict != Verdict.MALICIOUS:
            change_note = (
                f"\n🔄 <b>Status changed:</b> "
                f"{previous.verdict.value} → {result.verdict.value}"
            )
        elif previous and previous.malicious_count < result.malicious_count:
            change_note = (
                f"\n📈 <b>Malicious count increased:</b> "
                f"{previous.malicious_count} → {result.malicious_count}"
            )

        domain_note = ""
        if result.domain_result and result.domain_result.verdict == Verdict.MALICIOUS:
            domain_note = (
                f"\n🌐 <b>Domain also flagged:</b> "
                f"{result.domain_result.domain} "
                f"({result.domain_result.last_analysis_stats.get('malicious', 0)} engines)"
            )

        text = (
            f"🚨 <b>MALICIOUS URL DETECTED</b>\n\n"
            f"🔗 <code>{_escape(result.normalized_url)}</code>\n"
            f"🌐 Domain: <code>{_escape(result.domain)}</code>\n"
            f"🔴 Malicious engines: <b>{result.malicious_count}</b> / {result.total_engines}\n"
            f"🟡 Suspicious engines: {result.suspicious_count}\n"
            f"⏰ Scanned at: {result.scanned_at}"
            f"{change_note}"
            f"{domain_note}"
        )
        logger.info("Sending malicious alert for %s", result.normalized_url)
        return self._send(text)

    def send_suspicious_alert(
        self,
        result: ScanResult,
        previous: Optional[ScanResult] = None,
    ) -> bool:
        """Send an alert for a newly suspicious URL."""
        change_note = ""
        if previous and previous.verdict not in (Verdict.SUSPICIOUS, Verdict.MALICIOUS):
            change_note = (
                f"\n🔄 <b>Status changed:</b> "
                f"{previous.verdict.value} → {result.verdict.value}"
            )
        elif previous and previous.suspicious_count < result.suspicious_count:
            change_note = (
                f"\n📈 <b>Suspicious count increased:</b> "
                f"{previous.suspicious_count} → {result.suspicious_count}"
            )

        text = (
            f"⚠️ <b>SUSPICIOUS URL DETECTED</b>\n\n"
            f"🔗 <code>{_escape(result.normalized_url)}</code>\n"
            f"🌐 Domain: <code>{_escape(result.domain)}</code>\n"
            f"🟡 Suspicious engines: <b>{result.suspicious_count}</b> / {result.total_engines}\n"
            f"🟢 Harmless engines: {result.harmless_count}\n"
            f"⏰ Scanned at: {result.scanned_at}"
            f"{change_note}"
        )
        logger.info("Sending suspicious alert for %s", result.normalized_url)
        return self._send(text)

    def send_clean_alert(self, result: ScanResult, previous: ScanResult) -> bool:
        """Send an optional alert when a previously bad URL is now clean."""
        text = (
            f"✅ <b>URL NOW CLEAN</b>\n\n"
            f"🔗 <code>{_escape(result.normalized_url)}</code>\n"
            f"🌐 Domain: <code>{_escape(result.domain)}</code>\n"
            f"🔄 <b>Status changed:</b> {previous.verdict.value} → {result.verdict.value}\n"
            f"🟢 Harmless engines: {result.harmless_count} / {result.total_engines}\n"
            f"⏰ Scanned at: {result.scanned_at}"
        )
        logger.info("Sending clean alert for %s", result.normalized_url)
        return self._send(text)

    def send_domain_alert(self, result: ScanResult) -> bool:
        """Send a domain-specific alert when the domain reputation is bad."""
        if not result.domain_result:
            return False
        dr = result.domain_result
        text = (
            f"🌐 <b>MALICIOUS DOMAIN DETECTED</b>\n\n"
            f"🔗 URL: <code>{_escape(result.normalized_url)}</code>\n"
            f"🌐 Domain: <code>{_escape(dr.domain)}</code>\n"
            f"🔴 Domain malicious engines: "
            f"<b>{dr.last_analysis_stats.get('malicious', 0)}</b>\n"
            f"⭐ Reputation score: {dr.reputation}\n"
            f"⏰ Scanned at: {result.scanned_at}"
        )
        logger.info("Sending domain alert for %s", dr.domain)
        return self._send(text)

    def send_summary(
        self,
        summary: RunSummary,
        sources_checked: str,
    ) -> bool:
        """Send a run summary message."""
        report_date = summary.run_at
        try:
            report_date = datetime.fromisoformat(
                summary.run_at.replace("Z", "+00:00")
            ).strftime("%m/%d/%Y")
        except ValueError:
            pass
        flagged_urls = summary.malicious + summary.suspicious
        takedowns_requested = summary.malicious
        text = (
            f"🛡️ Malicious URL Checks — {report_date}\n\n"
            f"Summary\n"
            f"- Sources Checked: {_escape(sources_checked)}\n"
            f"- URLs Checked: {summary.total}\n"
            f"- Flagged URLs: {flagged_urls}\n"
            f"- Takedowns Requested: {takedowns_requested}"
        )
        logger.info("Sending run summary")
        return self._send(text)


def _escape(text: str) -> str:
    """Minimal HTML escaping for Telegram HTML parse mode."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
