"""Telegram bot client for sending alerts and summaries."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import requests

from models import RunSummary, ScanResult, Verdict

logger = logging.getLogger(__name__)

_TELEGRAM_API = "https://api.telegram.org"
_TAKEDOWN_REQUEST_URL = "https://www.virustotal.com/gui/contact-us"
_TELEGRAM_MAX_MESSAGE_LENGTH = 4096
_FLAGGED_DETAILS_HEADER = "\n\n- Flagged URL Details:\n"
_FLAGGED_DETAILS_MORE_TEMPLATE = "  • …and {count} more flagged URL(s)"


class TelegramClient:
    """Send messages to a Telegram chat via the Bot API."""

    def __init__(self, bot_token: str, chat_id: str | list[str]) -> None:
        # Tokens are never logged
        self._token = bot_token
        if isinstance(chat_id, list):
            self._chat_ids = [item.strip() for item in chat_id if item and item.strip()]
        else:
            self._chat_ids = [item.strip() for item in chat_id.split(",") if item.strip()]
        self._base = f"{_TELEGRAM_API}/bot{bot_token}"

    def _send(self, text: str, parse_mode: str = "HTML") -> bool:
        """Send a message; return True on success."""
        sent_any = False
        for chat_id in self._chat_ids:
            try:
                resp = requests.post(
                    f"{self._base}/sendMessage",
                    json={
                        "chat_id": chat_id,
                        "text": text,
                        "parse_mode": parse_mode,
                        "disable_web_page_preview": True,
                    },
                    timeout=15,
                )
                resp.raise_for_status()
                sent_any = True
            except requests.HTTPError as exc:
                logger.error("Telegram HTTP error for chat %s: %s", chat_id, exc)
            except Exception as exc:
                logger.error("Telegram send failed for chat %s: %s", chat_id, exc)
        return sent_any

    # ------------------------------------------------------------------
    # Alert messages
    # ------------------------------------------------------------------

    def send_malicious_alert(
        self,
        result: ScanResult,
        previous: Optional[ScanResult] = None,
    ) -> bool:
        """Send an alert for a newly malicious URL."""
        text = self._build_malicious_alert_text(result, previous, include_flag_removal=False)
        logger.info("Sending malicious alert for %s", result.normalized_url)
        return self._send(text)

    def send_malicious_alert_with_flag_removal(
        self,
        result: ScanResult,
        previous: Optional[ScanResult] = None,
    ) -> bool:
        """Send a malicious alert that includes a flag-removal action link."""
        text = self._build_malicious_alert_text(result, previous, include_flag_removal=True)
        logger.info("Sending malicious alert for %s", result.normalized_url)
        return self._send(text)

    def _build_malicious_alert_text(
        self,
        result: ScanResult,
        previous: Optional[ScanResult],
        *,
        include_flag_removal: bool,
    ) -> str:
        """Build malicious alert text; optionally include a flag-removal link."""
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

        removal_note = ""
        if include_flag_removal:
            removal_note = f"\n📝 Request flag removal: {_TAKEDOWN_REQUEST_URL}"

        text = (
            f"🚨 <b>MALICIOUS URL DETECTED</b>\n\n"
            f"🔗 <code>{_escape(result.normalized_url)}</code>\n"
            f"🌐 Domain: <code>{_escape(result.domain)}</code>\n"
            f"🔴 Malicious engines: <b>{result.malicious_count}</b> / {result.total_engines}\n"
            f"🟡 Suspicious engines: {result.suspicious_count}\n"
            f"⏰ Scanned at: {result.scanned_at}\n"
            f"{removal_note}"
            f"{change_note}"
            f"{domain_note}"
        )
        return text

    def send_suspicious_alert(
        self,
        result: ScanResult,
        previous: Optional[ScanResult] = None,
    ) -> bool:
        """Send an alert for a newly suspicious URL."""
        text = self._build_suspicious_alert_text(result, previous, include_flag_removal=False)
        logger.info("Sending suspicious alert for %s", result.normalized_url)
        return self._send(text)

    def send_suspicious_alert_with_flag_removal(
        self,
        result: ScanResult,
        previous: Optional[ScanResult] = None,
    ) -> bool:
        """Send a suspicious alert that includes a flag-removal action link."""
        text = self._build_suspicious_alert_text(result, previous, include_flag_removal=True)
        logger.info("Sending suspicious alert for %s", result.normalized_url)
        return self._send(text)

    def _build_suspicious_alert_text(
        self,
        result: ScanResult,
        previous: Optional[ScanResult],
        *,
        include_flag_removal: bool,
    ) -> str:
        """Build suspicious alert text; optionally include a flag-removal link."""
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

        removal_note = ""
        if include_flag_removal:
            removal_note = f"\n📝 Request flag removal: {_TAKEDOWN_REQUEST_URL}"

        text = (
            f"⚠️ <b>SUSPICIOUS URL DETECTED</b>\n\n"
            f"🔗 <code>{_escape(result.normalized_url)}</code>\n"
            f"🌐 Domain: <code>{_escape(result.domain)}</code>\n"
            f"🟡 Suspicious engines: <b>{result.suspicious_count}</b> / {result.total_engines}\n"
            f"🟢 Harmless engines: {result.harmless_count}\n"
            f"⏰ Scanned at: {result.scanned_at}\n"
            f"{removal_note}"
            f"{change_note}"
        )
        return text

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
        flagged_url_details: Optional[list[tuple[str, str]]] = None,
    ) -> bool:
        """Send a run summary message."""
        text = self._build_summary_text(
            summary,
            sources_checked,
            flagged_url_details=flagged_url_details,
            include_scan_date=False,
            include_flag_removal=False,
        )
        logger.info("Sending run summary")
        return self._send(text)

    def send_summary_with_scan_date_and_flag_removal(
        self,
        summary: RunSummary,
        sources_checked: str,
        flagged_url_details: Optional[list[tuple[str, str]]] = None,
    ) -> bool:
        """Send an enhanced run summary with explicit scan date and action link."""
        text = self._build_summary_text(
            summary,
            sources_checked,
            flagged_url_details=flagged_url_details,
            include_scan_date=True,
            include_flag_removal=True,
        )
        logger.info("Sending run summary")
        return self._send(text)

    def _build_summary_text(
        self,
        summary: RunSummary,
        sources_checked: str,
        flagged_url_details: Optional[list[tuple[str, str]]] = None,
        *,
        include_scan_date: bool,
        include_flag_removal: bool,
    ) -> str:
        """Build summary text with optional scan-date and flag-removal lines."""
        report_date = summary.run_at
        try:
            report_date = datetime.fromisoformat(
                summary.run_at.replace("Z", "+00:00")
            ).strftime("%m/%d/%Y")
        except ValueError:
            pass
        flagged_urls = summary.malicious + summary.suspicious
        takedowns_requested = summary.malicious
        scan_date_line = ""
        if include_scan_date:
            scan_date_line = f"- Date When The Scan is Done: {report_date}\n"

        text = (
            f"🛡️ Malicious URL Checks — {report_date}\n\n"
            f"Summary\n"
            f"{scan_date_line}"
            f"- Sources Checked: {_escape(sources_checked)}\n"
            f"- URLs Checked: {summary.total}\n"
            f"- Flagged URLs: {flagged_urls}\n"
            f"- Takedowns Requested: {takedowns_requested}"
        )
        if include_flag_removal and flagged_urls > 0:
            text += f"\n- Request Flag Removal: {_TAKEDOWN_REQUEST_URL}"
        if flagged_url_details:
            text = _append_flagged_url_details_with_limit(text, flagged_url_details)
        return text


def _escape(text: str) -> str:
    """Minimal HTML escaping for Telegram HTML parse mode."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _append_flagged_url_details_with_limit(
    text: str, flagged_url_details: list[tuple[str, str]]
) -> str:
    """Append flagged URL lines without exceeding Telegram message size limit."""
    details_lines = [
        f"  • <code>{_escape(url)}</code> ({_escape(scanner)})"
        for url, scanner in flagged_url_details
    ]
    max_body_length = _TELEGRAM_MAX_MESSAGE_LENGTH
    available = max_body_length - len(text) - len(_FLAGGED_DETAILS_HEADER)
    if available <= 0:
        return text
    kept_lines: list[str] = []
    used = 0
    for idx, line in enumerate(details_lines):
        sep_len = 1 if kept_lines else 0
        remaining = len(details_lines) - idx - 1
        more_line = (
            _FLAGGED_DETAILS_MORE_TEMPLATE.format(count=remaining) if remaining > 0 else ""
        )
        more_len = (1 + len(more_line)) if more_line else 0
        needed = used + sep_len + len(line) + more_len
        if needed > available:
            break
        kept_lines.append(line)
        used += sep_len + len(line)
    if not kept_lines:
        return text
    remaining = len(details_lines) - len(kept_lines)
    if remaining > 0:
        kept_lines.append(_FLAGGED_DETAILS_MORE_TEMPLATE.format(count=remaining))
    return text + _FLAGGED_DETAILS_HEADER + "\n".join(kept_lines)
