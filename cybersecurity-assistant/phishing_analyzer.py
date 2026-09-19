"""
phishing_analyzer.py
--------------------
Rule-based phishing and URL analyzer.
All analysis logic lives here — no Streamlit imports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from exceptions import EmptyInputError, InputTooLongError, InvalidURLFormatError
from keyword_rules import (
    CREDENTIAL_PHRASES,
    FINANCIAL_PHRASES,
    FLAG_LABELS,
    RISK_THRESHOLDS,
    SUSPICIOUS_TLDS,
    SUSPICIOUS_URL_PATTERNS,
    UNICODE_LOOKALIKES,
    URGENCY_PHRASES,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_INPUT_LENGTH: int = 5_000
URL_REGEX: re.Pattern = re.compile(
    r"^https?://"                        # scheme
    r"(?:[a-zA-Z0-9\-._~%\u0080-\uFFFF]+)"  # host (ASCII + Unicode for IDN / lookalikes)
    r"(?:\:[0-9]+)?"                     # optional port
    r"(?:/[^\s]*)?"                      # optional path
    r"$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class AnalysisResult:
    """Holds the full result of a phishing / URL analysis."""

    input_text: str
    input_type: str                          # "text" or "url"
    risk_level: str                          # "Safe", "Suspicious", "High Risk"
    matched_flags: list[str] = field(default_factory=list)
    explanation: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )


# ---------------------------------------------------------------------------
# PhishingAnalyzer class
# ---------------------------------------------------------------------------
class PhishingAnalyzer:
    """
    Analyzes a piece of text or a URL for phishing indicators using
    rule-based keyword and pattern matching.

    Usage
    -----
    analyzer = PhishingAnalyzer()
    result = analyzer.analyze("Click here to verify your account urgently!")
    """

    # Valid answer choices for the quiz (kept here as a reference constant)
    VALID_INPUT_TYPES: tuple[str, ...] = ("text", "url")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, input_text: str) -> AnalysisResult:
        """
        Main entry point. Validates input, detects type, runs rules, and
        returns a fully populated AnalysisResult.

        Parameters
        ----------
        input_text : str
            Raw user input (message body, SMS text, or URL).

        Returns
        -------
        AnalysisResult

        Raises
        ------
        EmptyInputError
            If input_text is empty or whitespace-only.
        InputTooLongError
            If input_text exceeds MAX_INPUT_LENGTH characters.
        """
        cleaned = self._validate_and_clean(input_text)
        input_type = self.detect_input_type(cleaned)

        if input_type == "url":
            self._validate_url(cleaned)

        flags = self.extract_flags(cleaned, input_type)
        risk_level = self.calculate_risk_level(flags)
        explanation = self.build_explanation(flags, risk_level)

        return AnalysisResult(
            input_text=cleaned,
            input_type=input_type,
            risk_level=risk_level,
            matched_flags=flags,
            explanation=explanation,
        )

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def detect_input_type(self, text: str) -> str:
        """Return 'url' if the text looks like a URL, otherwise 'text'."""
        stripped = text.strip()
        return "url" if stripped.lower().startswith(("http://", "https://")) else "text"

    def extract_flags(self, text: str, input_type: str) -> list[str]:
        """
        Scan the text for all matching red-flag categories and return a list
        of human-readable flag label strings.
        """
        flags: list[str] = []
        lower_text = text.lower()

        if input_type == "text":
            if self._matches_any(lower_text, URGENCY_PHRASES):
                flags.append(FLAG_LABELS["urgency"])
            if self._matches_any(lower_text, CREDENTIAL_PHRASES):
                flags.append(FLAG_LABELS["credential"])
            if self._matches_any(lower_text, FINANCIAL_PHRASES):
                flags.append(FLAG_LABELS["financial"])

        if input_type == "url":
            if self._matches_any(lower_text, SUSPICIOUS_URL_PATTERNS):
                flags.append(FLAG_LABELS["suspicious_url"])
            if self._matches_any(lower_text, SUSPICIOUS_TLDS):
                flags.append(FLAG_LABELS["suspicious_tld"])

        # Check for Unicode lookalike characters in both types
        if self._contains_unicode_lookalikes(text):
            flags.append(FLAG_LABELS["unicode_lookalike"])

        return flags

    def calculate_risk_level(self, flags: list[str]) -> str:
        """Map flag count to a risk label."""
        count = len(flags)
        if count >= RISK_THRESHOLDS["high"]:
            return "High Risk"
        if count >= RISK_THRESHOLDS["medium"]:
            return "Suspicious"
        return "Safe"

    def build_explanation(self, flags: list[str], risk_level: str) -> str:
        """Convert matched flags into a single plain-English explanation string."""
        if not flags:
            return (
                "No red-flag patterns were detected in this input. "
                "It appears to be safe, but always stay cautious."
            )

        flag_list = "; ".join(flags)
        intro = {
            "High Risk": "This input contains multiple strong indicators of a phishing attempt",
            "Suspicious": "This input contains indicators that may suggest a phishing attempt",
        }.get(risk_level, "This input raised some flags")

        return f"{intro}. Detected: {flag_list}."

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate_and_clean(self, input_text: str) -> str:
        """Strip whitespace and enforce length rules."""
        if not isinstance(input_text, str):
            raise EmptyInputError("Input must be a string.")
        cleaned = input_text.strip()
        if not cleaned:
            raise EmptyInputError("Input must not be empty.")
        if len(cleaned) > MAX_INPUT_LENGTH:
            raise InputTooLongError(
                f"Input exceeds the maximum allowed length of {MAX_INPUT_LENGTH} characters."
            )
        return cleaned

    def _validate_url(self, url: str) -> None:
        """Raise InvalidURLFormatError if the URL does not match the expected pattern."""
        if not URL_REGEX.match(url):
            raise InvalidURLFormatError(
                f"'{url}' does not appear to be a valid URL. "
                "URLs must start with http:// or https://"
            )

    @staticmethod
    def _matches_any(text: str, patterns: list[str]) -> bool:
        """Return True if any pattern string is found as a substring of text."""
        return any(pattern in text for pattern in patterns)

    @staticmethod
    def _contains_unicode_lookalikes(text: str) -> bool:
        """Return True if any Unicode lookalike character is present in the text."""
        return any(char in text for char in UNICODE_LOOKALIKES)
