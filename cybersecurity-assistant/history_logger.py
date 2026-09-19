"""
history_logger.py
-----------------
Appends and retrieves analysis log entries from a local logs.json file.
No Streamlit imports — pure logic only.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from exceptions import LogFileError

# ---------------------------------------------------------------------------
# Default log file location (same directory as this module)
# ---------------------------------------------------------------------------
DEFAULT_LOG_PATH: Path = Path(__file__).parent / "logs.json"

VALID_ANALYSIS_TYPES: frozenset[str] = frozenset(
    {"phishing", "password", "quiz", "chat"}
)


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------
@dataclass
class LogEntry:
    """A single entry in the analysis log."""

    entry_id: int
    analysis_type: str           # "phishing", "password", "quiz", "chat"
    summary: str                 # One-line result description (no raw passwords)
    timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )


# ---------------------------------------------------------------------------
# HistoryLogger class
# ---------------------------------------------------------------------------
class HistoryLogger:
    """
    Persists analysis log entries to a local JSON file and provides
    read/search access to the log history.

    Usage
    -----
    logger = HistoryLogger()
    logger.log_entry("phishing", "High Risk — 3 flags detected")
    entries = logger.get_all_entries()
    results = logger.search_entries("phishing")
    """

    def __init__(self, log_path: Path | str = DEFAULT_LOG_PATH) -> None:
        self._path = Path(log_path)
        self._ensure_file_exists()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_entry(self, analysis_type: str, summary: str) -> LogEntry:
        """
        Append a new entry to the log file.

        Parameters
        ----------
        analysis_type : str
            One of "phishing", "password", "quiz", "chat".
        summary : str
            A short description of the result (must not contain raw passwords).

        Returns
        -------
        LogEntry
            The entry that was written.

        Raises
        ------
        LogFileError
            If the file cannot be read or written.
        """
        entries = self._read_all()
        next_id = (entries[-1]["entry_id"] + 1) if entries else 1
        entry = LogEntry(
            entry_id=next_id,
            analysis_type=analysis_type,
            summary=summary,
        )
        entries.append(asdict(entry))
        self._write_all(entries)
        return entry

    def get_all_entries(self) -> list[LogEntry]:
        """Return all log entries as a list of LogEntry objects, newest first."""
        raw = self._read_all()
        entries = [LogEntry(**item) for item in raw]
        return list(reversed(entries))

    def search_entries(self, keyword: str) -> list[LogEntry]:
        """
        Return log entries whose summary or analysis_type contains the keyword
        (case-insensitive).

        Parameters
        ----------
        keyword : str
            Search term (minimum 2 characters).

        Raises
        ------
        EmptyInputError is not raised here; callers should validate before calling.
        """
        keyword_lower = keyword.strip().lower()
        all_entries = self.get_all_entries()
        return [
            e
            for e in all_entries
            if keyword_lower in e.summary.lower()
            or keyword_lower in e.analysis_type.lower()
        ]

    def clear_history(self) -> None:
        """Delete all log entries from the log file."""
        self._write_all([])

    def get_entry_count(self) -> int:
        """Return the total number of log entries."""
        return len(self._read_all())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _ensure_file_exists(self) -> None:
        """Create the log file with an empty list if it does not exist."""
        try:
            if not self._path.exists():
                self._path.write_text("[]", encoding="utf-8")
        except OSError as exc:
            raise LogFileError(
                f"Could not create log file at '{self._path}': {exc}"
            ) from exc

    def _read_all(self) -> list[dict]:
        """Read and deserialise the JSON log file."""
        try:
            text = self._path.read_text(encoding="utf-8")
            data = json.loads(text)
            if not isinstance(data, list):
                raise LogFileError(
                    f"Log file '{self._path}' is corrupted (expected a JSON array). "
                    "Recreating the file."
                )
            return data
        except json.JSONDecodeError as exc:
            # File is corrupted — recreate it gracefully
            self._path.write_text("[]", encoding="utf-8")
            return []
        except OSError as exc:
            raise LogFileError(
                f"Could not read log file at '{self._path}': {exc}"
            ) from exc

    def _write_all(self, entries: list[dict]) -> None:
        """Serialise and write the full list of entries to the log file."""
        try:
            self._path.write_text(
                json.dumps(entries, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            raise LogFileError(
                f"Could not write log file at '{self._path}': {exc}"
            ) from exc
