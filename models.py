"""Data models for URL scan results and state tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    """Possible verdicts for a scanned URL."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


@dataclass
class DomainResult:
    """Reputation data for a domain extracted from a URL."""

    domain: str
    malicious_votes: int = 0
    harmless_votes: int = 0
    suspicious_votes: int = 0
    reputation: int = 0
    categories: dict[str, str] = field(default_factory=dict)
    last_analysis_stats: dict[str, int] = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    @property
    def verdict(self) -> Verdict:
        """Derive verdict from domain analysis stats."""
        malicious = self.last_analysis_stats.get("malicious", 0)
        suspicious = self.last_analysis_stats.get("suspicious", 0)
        if malicious > 0:
            return Verdict.MALICIOUS
        if suspicious > 0:
            return Verdict.SUSPICIOUS
        if self.harmless_votes > 0 or self.last_analysis_stats.get("harmless", 0) > 0:
            return Verdict.CLEAN
        return Verdict.UNKNOWN


@dataclass
class ScanResult:
    """Complete scan result for a single URL."""

    url: str
    normalized_url: str
    domain: str
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # VirusTotal URL analysis stats
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    timeout_count: int = 0
    total_engines: int = 0

    # Derived verdict
    verdict: Verdict = Verdict.UNKNOWN

    # Domain context
    domain_result: Optional[DomainResult] = None

    # VirusTotal analysis ID (used for polling)
    analysis_id: Optional[str] = None

    # URLScan.io analysis details (optional)
    urlscan_io_uuid: Optional[str] = None
    urlscan_io_verdict: Optional[Verdict] = None
    urlscan_io_malicious: int = 0
    urlscan_io_suspicious: int = 0

    # Error info if scan failed
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialise to a plain dict suitable for JSON storage."""
        d = {
            "url": self.url,
            "normalized_url": self.normalized_url,
            "domain": self.domain,
            "scanned_at": self.scanned_at,
            "malicious_count": self.malicious_count,
            "suspicious_count": self.suspicious_count,
            "harmless_count": self.harmless_count,
            "undetected_count": self.undetected_count,
            "timeout_count": self.timeout_count,
            "total_engines": self.total_engines,
            "verdict": self.verdict.value,
            "analysis_id": self.analysis_id,
            "urlscan_io_uuid": self.urlscan_io_uuid,
            "urlscan_io_verdict": (
                self.urlscan_io_verdict.value if self.urlscan_io_verdict else None
            ),
            "urlscan_io_malicious": self.urlscan_io_malicious,
            "urlscan_io_suspicious": self.urlscan_io_suspicious,
            "error": self.error,
            "domain_info": None,
        }
        if self.domain_result:
            dr = self.domain_result
            d["domain_info"] = {
                "domain": dr.domain,
                "malicious_votes": dr.malicious_votes,
                "harmless_votes": dr.harmless_votes,
                "suspicious_votes": dr.suspicious_votes,
                "reputation": dr.reputation,
                "categories": dr.categories,
                "last_analysis_stats": dr.last_analysis_stats,
                "verdict": dr.verdict.value,
            }
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResult":
        """Deserialise from a plain dict (loaded from JSON storage)."""
        domain_info = data.get("domain_info")
        domain_result: Optional[DomainResult] = None
        if domain_info:
            domain_result = DomainResult(
                domain=domain_info.get("domain", ""),
                malicious_votes=domain_info.get("malicious_votes", 0),
                harmless_votes=domain_info.get("harmless_votes", 0),
                suspicious_votes=domain_info.get("suspicious_votes", 0),
                reputation=domain_info.get("reputation", 0),
                categories=domain_info.get("categories", {}),
                last_analysis_stats=domain_info.get("last_analysis_stats", {}),
            )
        return cls(
            url=data.get("url", ""),
            normalized_url=data.get("normalized_url", ""),
            domain=data.get("domain", ""),
            scanned_at=data.get("scanned_at", ""),
            malicious_count=data.get("malicious_count", 0),
            suspicious_count=data.get("suspicious_count", 0),
            harmless_count=data.get("harmless_count", 0),
            undetected_count=data.get("undetected_count", 0),
            timeout_count=data.get("timeout_count", 0),
            total_engines=data.get("total_engines", 0),
            verdict=Verdict(data.get("verdict", Verdict.UNKNOWN.value)),
            domain_result=domain_result,
            analysis_id=data.get("analysis_id"),
            urlscan_io_uuid=data.get("urlscan_io_uuid"),
            urlscan_io_verdict=(
                Verdict(data["urlscan_io_verdict"])
                if data.get("urlscan_io_verdict")
                else None
            ),
            urlscan_io_malicious=data.get("urlscan_io_malicious", 0),
            urlscan_io_suspicious=data.get("urlscan_io_suspicious", 0),
            error=data.get("error"),
        )


@dataclass
class RunSummary:
    """Aggregated statistics for a single scanner run."""

    run_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    total: int = 0
    malicious: int = 0
    suspicious: int = 0
    clean: int = 0
    unknown: int = 0
    failed: int = 0
    unchanged: int = 0
    newly_malicious: int = 0
    newly_suspicious: int = 0
    worsened: int = 0
    improved: int = 0

    def to_dict(self) -> dict:
        return {
            "run_at": self.run_at,
            "total": self.total,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "clean": self.clean,
            "unknown": self.unknown,
            "failed": self.failed,
            "unchanged": self.unchanged,
            "newly_malicious": self.newly_malicious,
            "newly_suspicious": self.newly_suspicious,
            "worsened": self.worsened,
            "improved": self.improved,
        }
