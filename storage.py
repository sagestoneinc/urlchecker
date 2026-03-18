"""Storage layer: read/write scan results as JSON, JSONL, and CSV."""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from models import ScanResult, RunSummary

logger = logging.getLogger(__name__)

_LATEST_FILE = "latest_results.json"
_HISTORY_FILE = "history.jsonl"
_CSV_FILE = "latest_results.csv"
_SUMMARY_FILE = "run_summaries.jsonl"

# CSV column order
_CSV_FIELDS = [
    "url",
    "normalized_url",
    "domain",
    "scanned_at",
    "verdict",
    "malicious_count",
    "suspicious_count",
    "harmless_count",
    "undetected_count",
    "total_engines",
    "domain_verdict",
    "error",
]


class Storage:
    """Manages persisting and loading scan results."""

    def __init__(self, results_dir: Path) -> None:
        self._dir = results_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------

    @property
    def latest_path(self) -> Path:
        return self._dir / _LATEST_FILE

    @property
    def history_path(self) -> Path:
        return self._dir / _HISTORY_FILE

    @property
    def csv_path(self) -> Path:
        return self._dir / _CSV_FILE

    @property
    def summary_path(self) -> Path:
        return self._dir / _SUMMARY_FILE

    # ------------------------------------------------------------------
    # Previous state (used for change detection)
    # ------------------------------------------------------------------

    def load_previous_results(self) -> dict[str, ScanResult]:
        """
        Load the most recent scan results keyed by normalized URL.
        Returns an empty dict if no previous results exist.
        """
        if not self.latest_path.exists():
            logger.info("No previous results found at %s", self.latest_path)
            return {}
        try:
            data = json.loads(self.latest_path.read_text(encoding="utf-8"))
            results: dict[str, ScanResult] = {}
            for item in data:
                result = ScanResult.from_dict(item)
                results[result.normalized_url] = result
            logger.info("Loaded %d previous results", len(results))
            return results
        except Exception as exc:
            logger.warning("Failed to load previous results: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Save helpers
    # ------------------------------------------------------------------

    def save_results(
        self,
        results: list[ScanResult],
        summary: Optional[RunSummary] = None,
    ) -> None:
        """
        Persist results to disk:
        - latest_results.json  (full current state)
        - history.jsonl        (append one record per URL per run)
        - latest_results.csv   (human-readable spreadsheet)
        - run_summaries.jsonl  (append one record per run)
        """
        self._save_latest(results)
        self._append_history(results)
        self._save_csv(results)
        if summary:
            self._append_summary(summary)

    def _save_latest(self, results: list[ScanResult]) -> None:
        payload = [r.to_dict() for r in results]
        self.latest_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        logger.info("Saved %d results to %s", len(results), self.latest_path)

    def _append_history(self, results: list[ScanResult]) -> None:
        with self.history_path.open("a", encoding="utf-8") as fh:
            for result in results:
                fh.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")
        logger.info("Appended %d records to %s", len(results), self.history_path)

    def _save_csv(self, results: list[ScanResult]) -> None:
        with self.csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for r in results:
                row = r.to_dict()
                row["domain_verdict"] = (
                    r.domain_result.verdict.value if r.domain_result else ""
                )
                writer.writerow(row)
        logger.info("Saved CSV to %s", self.csv_path)

    def _append_summary(self, summary: RunSummary) -> None:
        with self.summary_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(summary.to_dict(), ensure_ascii=False) + "\n")
        logger.info("Appended run summary to %s", self.summary_path)
