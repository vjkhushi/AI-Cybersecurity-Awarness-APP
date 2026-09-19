"""
keyword_rules.py
----------------
Central store of red-flag patterns, suspicious keywords, and domain indicators
used by the phishing analyzer. No logic lives here — data only.
"""

# ---------------------------------------------------------------------------
# Urgency / pressure phrases
# ---------------------------------------------------------------------------
URGENCY_PHRASES: list[str] = [
    "act now",
    "immediate action required",
    "your account will be suspended",
    "account suspended",
    "verify immediately",
    "click immediately",
    "respond immediately",
    "limited time",
    "expires today",
    "expires soon",
    "last chance",
    "urgent",
    "as soon as possible",
    "within 24 hours",
    "within 48 hours",
]

# ---------------------------------------------------------------------------
# Credential-harvesting / social-engineering phrases
# ---------------------------------------------------------------------------
CREDENTIAL_PHRASES: list[str] = [
    "verify your account",
    "confirm your account",
    "update your information",
    "update your details",
    "enter your password",
    "provide your password",
    "submit your credentials",
    "confirm your password",
    "re-enter your",
    "validate your",
    "login to verify",
    "sign in to confirm",
    "your account has been compromised",
    "suspicious activity detected",
    "unusual sign-in activity",
    "we need to verify your identity",
]

# ---------------------------------------------------------------------------
# Financial / prize lure phrases
# ---------------------------------------------------------------------------
FINANCIAL_PHRASES: list[str] = [
    "you have won",
    "congratulations, you",
    "claim your prize",
    "free gift",
    "free money",
    "transfer funds",
    "wire transfer",
    "bank account details",
    "send money",
    "lottery winner",
    "unclaimed funds",
    "inheritance",
]

# ---------------------------------------------------------------------------
# Suspicious URL patterns (substrings to look for in URLs)
# ---------------------------------------------------------------------------
SUSPICIOUS_URL_PATTERNS: list[str] = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "confirm",
    "banking",
    "paypal",
    "amazon",
    "apple",
    "microsoft",
    "google",
    "support",
    "password",
    "signin",
    "sign-in",
    "webscr",
    "cmd=",
    "token=",
    "reset",
]

# ---------------------------------------------------------------------------
# Known typo-squatted or suspicious TLD patterns
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS: list[str] = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".click",
    ".loan",
    ".work",
    ".win",
    ".download",
    ".racing",
    ".date",
]

# ---------------------------------------------------------------------------
# Unicode lookalike characters mapped to their ASCII equivalents
# (used to detect homograph attacks)
# ---------------------------------------------------------------------------
UNICODE_LOOKALIKES: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "r",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0440": "p",  # Cyrillic р (alternate)
    "\u04cf": "l",  # Cyrillic ӏ
    "\u0456": "i",  # Cyrillic і
}

# ---------------------------------------------------------------------------
# Risk thresholds
# ---------------------------------------------------------------------------
RISK_THRESHOLDS: dict[str, int] = {
    "high": 3,       # >= 3 flags → High Risk
    "medium": 1,     # 1–2 flags  → Suspicious / Medium
    # 0 flags → Safe
}

# ---------------------------------------------------------------------------
# Flag category human-readable labels
# ---------------------------------------------------------------------------
FLAG_LABELS: dict[str, str] = {
    "urgency": "urgency or pressure language",
    "credential": "credential harvesting or account verification language",
    "financial": "financial lure or prize language",
    "suspicious_url": "suspicious keywords in the URL path",
    "suspicious_tld": "suspicious or free top-level domain",
    "unicode_lookalike": "Unicode lookalike characters (possible homograph attack)",
}
