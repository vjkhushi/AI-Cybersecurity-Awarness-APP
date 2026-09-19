"""
password_checker.py
-------------------
Password strength evaluator.
Scores passwords against five criteria and generates actionable tips.
No Streamlit imports — pure logic only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from exceptions import EmptyInputError


# ---------------------------------------------------------------------------
# Scoring criteria
# ---------------------------------------------------------------------------
MIN_LENGTH: int = 12
STRONG_LENGTH: int = 16

_CRITERIA: list[dict] = [
    {
        "key": "length",
        "test": lambda p: len(p) >= MIN_LENGTH,
        "tip": f"Use at least {MIN_LENGTH} characters. Longer passwords are exponentially harder to crack.",
    },
    {
        "key": "uppercase",
        "test": lambda p: bool(re.search(r"[A-Z]", p)),
        "tip": "Add at least one uppercase letter (A–Z).",
    },
    {
        "key": "lowercase",
        "test": lambda p: bool(re.search(r"[a-z]", p)),
        "tip": "Add at least one lowercase letter (a–z).",
    },
    {
        "key": "digit",
        "test": lambda p: bool(re.search(r"\d", p)),
        "tip": "Add at least one number (0–9).",
    },
    {
        "key": "special",
        "test": lambda p: bool(re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/`~\"\\]", p)),
        "tip": "Add at least one special character (e.g. !, @, #, $, %).",
    },
]

# Extra warning: detect repeated characters (e.g. aaaaaa)
_REPEATED_CHAR_REGEX: re.Pattern = re.compile(r"(.)\1{4,}")

# Common weak passwords to flag explicitly
_COMMON_PASSWORDS: frozenset[str] = frozenset(
    [
        "password",
        "password123",
        "123456",
        "12345678",
        "qwerty",
        "abc123",
        "letmein",
        "monkey",
        "1234567890",
        "iloveyou",
        "admin",
        "welcome",
        "login",
        "passw0rd",
        "password1",
    ]
)

# Label thresholds (score out of 5)
_LABEL_MAP: list[tuple[int, str]] = [
    (5, "Strong 💪"),
    (4, "Good 👍"),
    (3, "Fair ⚠️"),
    (2, "Weak ❌"),
    (1, "Very Weak ❌"),
    (0, "Very Weak ❌"),
]


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------
@dataclass
class PasswordResult:
    """Result of a password strength check."""

    strength_score: int                          # 0–5
    strength_label: str                          # e.g. "Strong", "Weak"
    tips: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# PasswordChecker class
# ---------------------------------------------------------------------------
class PasswordChecker:
    """
    Evaluates password strength against five criteria and generates tips.

    Usage
    -----
    checker = PasswordChecker()
    result = checker.check_password("MyS3cur3P@ssw0rd!")
    """

    def check_password(self, password: str) -> PasswordResult:
        """
        Run all strength checks and return a PasswordResult.

        Parameters
        ----------
        password : str
            The password to evaluate. Never stored in logs.

        Returns
        -------
        PasswordResult

        Raises
        ------
        EmptyInputError
            If the password is empty or whitespace-only.
        """
        if not isinstance(password, str) or not password:
            raise EmptyInputError("Password must not be empty.")
        # Note: we do NOT strip whitespace — spaces are valid in passwords.

        score = self.score_password(password)
        label = self._score_to_label(score)
        tips = self.generate_tips(password)
        warnings = self._generate_warnings(password)

        return PasswordResult(
            strength_score=score,
            strength_label=label,
            tips=tips,
            warnings=warnings,
        )

    def score_password(self, password: str) -> int:
        """Return an integer score from 0 to 5 based on criteria met."""
        return sum(1 for criterion in _CRITERIA if criterion["test"](password))

    def generate_tips(self, password: str) -> list[str]:
        """Return only the tips for criteria the password has NOT met."""
        return [
            criterion["tip"]
            for criterion in _CRITERIA
            if not criterion["test"](password)
        ]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _score_to_label(score: int) -> str:
        """Map a numeric score to a human-readable label."""
        for threshold, label in _LABEL_MAP:
            if score >= threshold:
                return label
        return "Very Weak ❌"

    @staticmethod
    def _generate_warnings(password: str) -> list[str]:
        """
        Generate additional warnings for specific bad patterns that are not
        captured by the five scoring criteria.
        """
        warnings: list[str] = []

        if password.lower() in _COMMON_PASSWORDS:
            warnings.append(
                "⚠️ This is one of the most commonly used passwords and would be "
                "cracked instantly. Please choose something completely different."
            )

        if _REPEATED_CHAR_REGEX.search(password):
            warnings.append(
                "⚠️ Your password contains a long sequence of repeated characters "
                "(e.g. 'aaaaaaa'). This reduces entropy significantly."
            )

        if password.isdigit():
            warnings.append(
                "⚠️ Your password consists only of numbers. Add letters and special "
                "characters to make it significantly harder to crack."
            )

        return warnings
