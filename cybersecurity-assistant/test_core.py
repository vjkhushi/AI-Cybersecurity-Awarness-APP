"""
test_core.py
------------
Pytest unit tests for all core logic modules:
  - PhishingAnalyzer
  - PasswordChecker
  - QuizChatbot
  - HistoryLogger

Run with:
    pytest test_core.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Ensure the project root is on the path so imports resolve correctly
sys.path.insert(0, str(Path(__file__).parent))

from exceptions import (
    EmptyInputError,
    InputTooLongError,
    InvalidQuizAnswerError,
    InvalidURLFormatError,
    LogFileError,
    QuestionNotFoundError,
)
from history_logger import HistoryLogger, LogEntry
from password_checker import PasswordChecker, PasswordResult
from phishing_analyzer import AnalysisResult, PhishingAnalyzer
from quiz_chatbot import QuizChatbot, QuizSession


# ===========================================================================
# PhishingAnalyzer tests
# ===========================================================================
class TestPhishingAnalyzer:
    """Tests for phishing_analyzer.PhishingAnalyzer."""

    def setup_method(self) -> None:
        self.analyzer = PhishingAnalyzer()

    # --- detect_input_type ------------------------------------------------

    def test_detect_url_http(self) -> None:
        assert self.analyzer.detect_input_type("http://example.com") == "url"

    def test_detect_url_https(self) -> None:
        assert self.analyzer.detect_input_type("https://example.com/path") == "url"

    def test_detect_text(self) -> None:
        assert self.analyzer.detect_input_type("Hello, please verify your account") == "text"

    def test_detect_text_with_url_inside(self) -> None:
        # Starts with text → should be "text" type
        assert self.analyzer.detect_input_type("Click this link http://bad.tk") == "text"

    # --- analyze — safe inputs --------------------------------------------

    def test_safe_normal_text(self) -> None:
        result = self.analyzer.analyze("Hello, how are you doing today?")
        assert result.risk_level == "Safe"
        assert result.matched_flags == []

    def test_safe_legitimate_url(self) -> None:
        result = self.analyzer.analyze("https://www.python.org")
        assert result.risk_level == "Safe"

    # --- analyze — suspicious text ----------------------------------------

    def test_suspicious_one_flag_urgency(self) -> None:
        result = self.analyzer.analyze("Act now or your account will be closed!")
        # "act now" + "your account" triggers urgency
        assert result.risk_level in ("Suspicious", "High Risk")
        assert len(result.matched_flags) >= 1

    def test_high_risk_multiple_flags(self) -> None:
        result = self.analyzer.analyze(
            "URGENT: Verify your account immediately or your account will be suspended. "
            "You have won a prize — enter your password to claim your free gift."
        )
        assert result.risk_level == "High Risk"
        assert len(result.matched_flags) >= 3

    def test_credential_phrase_detected(self) -> None:
        result = self.analyzer.analyze("Please verify your account by clicking below.")
        flags = result.matched_flags
        assert any("credential" in f for f in flags)

    def test_financial_lure_detected(self) -> None:
        result = self.analyzer.analyze("Congratulations, you have won a prize! Claim now.")
        flags = result.matched_flags
        assert any("financial" in f for f in flags)

    # --- analyze — URLs ---------------------------------------------------

    def test_suspicious_url_keyword_in_path(self) -> None:
        result = self.analyzer.analyze("https://example.com/login/verify-account")
        assert result.risk_level in ("Suspicious", "High Risk")

    def test_suspicious_tld(self) -> None:
        result = self.analyzer.analyze("https://freeprize.tk")
        flags = result.matched_flags
        assert any("top-level domain" in f for f in flags)

    def test_unicode_lookalike_in_url(self) -> None:
        # Cyrillic 'а' in paypal
        result = self.analyzer.analyze("https://p\u0430ypal.com/login")
        flags = result.matched_flags
        assert any("unicode" in f.lower() for f in flags)

    def test_invalid_url_raises_error(self) -> None:
        with pytest.raises(InvalidURLFormatError):
            # Starts with https but malformed — stripped of host, no dot
            self.analyzer.analyze("https://")

    # --- input validation -------------------------------------------------

    def test_empty_input_raises(self) -> None:
        with pytest.raises(EmptyInputError):
            self.analyzer.analyze("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(EmptyInputError):
            self.analyzer.analyze("   \n\t  ")

    def test_input_too_long_raises(self) -> None:
        with pytest.raises(InputTooLongError):
            self.analyzer.analyze("x" * 5_001)

    def test_input_at_max_length_passes(self) -> None:
        result = self.analyzer.analyze("a" * 5_000)
        assert isinstance(result, AnalysisResult)

    def test_non_string_raises(self) -> None:
        with pytest.raises(EmptyInputError):
            self.analyzer.analyze(None)  # type: ignore[arg-type]

    # --- result structure -------------------------------------------------

    def test_result_has_timestamp(self) -> None:
        result = self.analyzer.analyze("Hello world")
        assert result.timestamp != ""

    def test_result_input_type_url(self) -> None:
        result = self.analyzer.analyze("https://example.com")
        assert result.input_type == "url"

    def test_result_input_type_text(self) -> None:
        result = self.analyzer.analyze("Some message here")
        assert result.input_type == "text"

    def test_explanation_not_empty(self) -> None:
        result = self.analyzer.analyze("Verify your account now — urgent!")
        assert len(result.explanation) > 0

    def test_safe_explanation_contains_no_flags(self) -> None:
        result = self.analyzer.analyze("Good morning, see you tomorrow.")
        assert "No red-flag" in result.explanation


# ===========================================================================
# PasswordChecker tests
# ===========================================================================
class TestPasswordChecker:
    """Tests for password_checker.PasswordChecker."""

    def setup_method(self) -> None:
        self.checker = PasswordChecker()

    # --- score_password ---------------------------------------------------

    def test_strong_password_score_5(self) -> None:
        assert self.checker.score_password("Tr0ub4dor&3!xQ") == 5

    def test_short_password_loses_length_criterion(self) -> None:
        # Under 12 chars but has upper/lower/digit/special
        score = self.checker.score_password("Ab1!")
        assert score == 4  # loses only the length criterion

    def test_all_lowercase_short(self) -> None:
        score = self.checker.score_password("abcde")
        assert score == 1  # only lowercase criterion met

    def test_digits_only(self) -> None:
        score = self.checker.score_password("12345678")
        assert score == 1  # only digit criterion met

    def test_password_with_spaces_valid(self) -> None:
        # Spaces are allowed — should not raise
        result = self.checker.check_password("correct horse battery staple!")
        assert isinstance(result, PasswordResult)

    # --- check_password ---------------------------------------------------

    def test_strong_password_label(self) -> None:
        result = self.checker.check_password("Tr0ub4dor&3!xQ")
        assert "Strong" in result.strength_label

    def test_weak_password_label(self) -> None:
        result = self.checker.check_password("abc")
        assert "Weak" in result.strength_label

    def test_common_password_warning(self) -> None:
        result = self.checker.check_password("password123")
        assert any("commonly used" in w for w in result.warnings)

    def test_repeated_chars_warning(self) -> None:
        result = self.checker.check_password("aaaaaaaaaaaaa")
        assert any("repeated" in w for w in result.warnings)

    def test_digits_only_warning(self) -> None:
        result = self.checker.check_password("1234567890123")
        assert any("only of numbers" in w for w in result.warnings)

    def test_no_tips_for_strong_password(self) -> None:
        result = self.checker.check_password("Tr0ub4dor&3!xQ")
        assert result.tips == []

    def test_tips_generated_for_weak_password(self) -> None:
        result = self.checker.check_password("abc")
        assert len(result.tips) > 0

    # --- input validation -------------------------------------------------

    def test_empty_password_raises(self) -> None:
        with pytest.raises(EmptyInputError):
            self.checker.check_password("")

    def test_non_string_raises(self) -> None:
        with pytest.raises(EmptyInputError):
            self.checker.check_password(None)  # type: ignore[arg-type]

    # --- generate_tips ----------------------------------------------------

    def test_tip_for_missing_uppercase(self) -> None:
        tips = self.checker.generate_tips("no_upper_1234!")
        assert any("uppercase" in t for t in tips)

    def test_tip_for_missing_digit(self) -> None:
        tips = self.checker.generate_tips("NoDigitHere!Special")
        assert any("number" in t for t in tips)

    def test_tip_for_missing_special(self) -> None:
        tips = self.checker.generate_tips("NoSpecialChar123")
        assert any("special" in t for t in tips)


# ===========================================================================
# QuizChatbot tests
# ===========================================================================
class TestQuizChatbot:
    """Tests for quiz_chatbot.QuizChatbot."""

    def setup_method(self) -> None:
        self.qc = QuizChatbot()

    # --- get_question -----------------------------------------------------

    def test_get_question_valid_id(self) -> None:
        q = self.qc.get_question(1)
        assert q.question_id == 1
        assert len(q.question_text) > 0

    def test_get_question_invalid_id_raises(self) -> None:
        with pytest.raises(QuestionNotFoundError):
            self.qc.get_question(9999)

    def test_question_has_four_options(self) -> None:
        q = self.qc.get_question(1)
        assert set(q.options.keys()) == {"A", "B", "C", "D"}

    def test_correct_answer_is_valid_key(self) -> None:
        for q in self.qc.get_all_questions():
            assert q.correct_answer in {"A", "B", "C", "D"}

    # --- start_session / submit_answer ------------------------------------

    def test_start_session_default_5_questions(self) -> None:
        session = self.qc.start_session(5)
        assert session.total_questions == 5

    def test_start_session_clamped_to_available(self) -> None:
        session = self.qc.start_session(1000)
        assert session.total_questions == len(self.qc.get_all_questions())

    def test_submit_correct_answer_increments_score(self) -> None:
        session = self.qc.start_session(1)
        question = self.qc.get_current_question(session)
        correct = question.correct_answer
        session = self.qc.submit_answer(session, correct)
        assert session.score == 1

    def test_submit_wrong_answer_does_not_increment_score(self) -> None:
        session = self.qc.start_session(1)
        question = self.qc.get_current_question(session)
        # Pick a wrong answer
        wrong = next(k for k in "ABCD" if k != question.correct_answer)
        session = self.qc.submit_answer(session, wrong)
        assert session.score == 0

    def test_session_is_complete_after_all_answers(self) -> None:
        session = self.qc.start_session(3)
        for _ in range(3):
            q = self.qc.get_current_question(session)
            session = self.qc.submit_answer(session, q.correct_answer)
        assert session.is_complete

    def test_get_current_question_returns_none_when_complete(self) -> None:
        session = self.qc.start_session(1)
        q = self.qc.get_current_question(session)
        self.qc.submit_answer(session, q.correct_answer)
        assert self.qc.get_current_question(session) is None

    def test_percentage_100_when_all_correct(self) -> None:
        session = self.qc.start_session(3)
        for _ in range(3):
            q = self.qc.get_current_question(session)
            session = self.qc.submit_answer(session, q.correct_answer)
        assert session.percentage == 100.0

    def test_invalid_answer_raises(self) -> None:
        session = self.qc.start_session(1)
        with pytest.raises(InvalidQuizAnswerError):
            self.qc.submit_answer(session, "X")

    def test_answer_lowercased_accepted(self) -> None:
        session = self.qc.start_session(1)
        q = self.qc.get_current_question(session)
        correct_lower = q.correct_answer.lower()
        session = self.qc.submit_answer(session, correct_lower)
        assert session.score == 1

    def test_submit_on_complete_session_raises(self) -> None:
        session = self.qc.start_session(1)
        q = self.qc.get_current_question(session)
        self.qc.submit_answer(session, q.correct_answer)
        with pytest.raises(QuestionNotFoundError):
            self.qc.submit_answer(session, "A")

    # --- chatbot ----------------------------------------------------------

    def test_chatbot_responds_to_phishing(self) -> None:
        response = self.qc.get_chatbot_response("Tell me about phishing")
        assert "phishing" in response.lower() or "Phishing" in response

    def test_chatbot_responds_to_password(self) -> None:
        response = self.qc.get_chatbot_response("how to make a strong password")
        assert "password" in response.lower()

    def test_chatbot_fallback_for_unknown_topic(self) -> None:
        response = self.qc.get_chatbot_response("banana smoothie recipe")
        # Should return the fallback message
        assert "not sure" in response.lower() or "general tip" in response.lower()

    def test_chatbot_empty_input_raises(self) -> None:
        with pytest.raises(EmptyInputError):
            self.qc.get_chatbot_response("")

    def test_chatbot_whitespace_only_raises(self) -> None:
        with pytest.raises(EmptyInputError):
            self.qc.get_chatbot_response("  ")

    def test_chatbot_single_char_raises(self) -> None:
        with pytest.raises(EmptyInputError):
            self.qc.get_chatbot_response("a")

    def test_chatbot_2fa_response(self) -> None:
        response = self.qc.get_chatbot_response("what is 2FA?")
        assert "2fa" in response.lower() or "two-factor" in response.lower() or "Two-factor" in response


# ===========================================================================
# HistoryLogger tests
# ===========================================================================
class TestHistoryLogger:
    """Tests for history_logger.HistoryLogger."""

    @pytest.fixture
    def tmp_logger(self, tmp_path: Path) -> HistoryLogger:
        """Return a HistoryLogger backed by a temp file for each test."""
        return HistoryLogger(log_path=tmp_path / "test_logs.json")

    def test_log_entry_creates_entry(self, tmp_logger: HistoryLogger) -> None:
        entry = tmp_logger.log_entry("phishing", "High Risk | 3 flags")
        assert entry.entry_id == 1
        assert entry.analysis_type == "phishing"
        assert entry.summary == "High Risk | 3 flags"

    def test_multiple_entries_auto_increment_id(self, tmp_logger: HistoryLogger) -> None:
        tmp_logger.log_entry("phishing", "Safe")
        tmp_logger.log_entry("password", "Strong")
        entries = tmp_logger.get_all_entries()
        ids = [e.entry_id for e in entries]
        assert sorted(ids) == [1, 2]

    def test_get_all_entries_newest_first(self, tmp_logger: HistoryLogger) -> None:
        tmp_logger.log_entry("phishing", "First")
        tmp_logger.log_entry("password", "Second")
        entries = tmp_logger.get_all_entries()
        assert entries[0].entry_id == 2   # newest
        assert entries[1].entry_id == 1

    def test_get_all_entries_empty_returns_empty_list(self, tmp_logger: HistoryLogger) -> None:
        assert tmp_logger.get_all_entries() == []

    def test_search_entries_finds_match(self, tmp_logger: HistoryLogger) -> None:
        tmp_logger.log_entry("phishing", "High Risk detected")
        tmp_logger.log_entry("password", "Weak password")
        results = tmp_logger.search_entries("High Risk")
        assert len(results) == 1
        assert "High Risk" in results[0].summary

    def test_search_entries_case_insensitive(self, tmp_logger: HistoryLogger) -> None:
        tmp_logger.log_entry("phishing", "HIGH RISK detected")
        results = tmp_logger.search_entries("high risk")
        assert len(results) == 1

    def test_search_entries_no_match_returns_empty(self, tmp_logger: HistoryLogger) -> None:
        tmp_logger.log_entry("phishing", "Safe result")
        results = tmp_logger.search_entries("nonexistent")
        assert results == []

    def test_search_by_analysis_type(self, tmp_logger: HistoryLogger) -> None:
        tmp_logger.log_entry("phishing", "Some phishing result")
        tmp_logger.log_entry("password", "Some password result")
        results = tmp_logger.search_entries("password")
        assert all(e.analysis_type == "password" or "password" in e.summary for e in results)

    def test_clear_history_removes_all(self, tmp_logger: HistoryLogger) -> None:
        tmp_logger.log_entry("phishing", "Test")
        tmp_logger.log_entry("password", "Test2")
        tmp_logger.clear_history()
        assert tmp_logger.get_all_entries() == []

    def test_get_entry_count(self, tmp_logger: HistoryLogger) -> None:
        tmp_logger.log_entry("phishing", "a")
        tmp_logger.log_entry("quiz", "b")
        assert tmp_logger.get_entry_count() == 2

    def test_log_persists_to_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "persist.json"
        logger1 = HistoryLogger(log_path=log_file)
        logger1.log_entry("phishing", "Persisted entry")

        # New instance reading same file
        logger2 = HistoryLogger(log_path=log_file)
        entries = logger2.get_all_entries()
        assert len(entries) == 1
        assert entries[0].summary == "Persisted entry"

    def test_corrupted_file_recovers_gracefully(self, tmp_path: Path) -> None:
        log_file = tmp_path / "corrupted.json"
        log_file.write_text("NOT VALID JSON {{{", encoding="utf-8")
        logger = HistoryLogger(log_path=log_file)
        # Should not raise; returns empty list after recovery
        entries = logger.get_all_entries()
        assert entries == []

    def test_entry_has_timestamp(self, tmp_logger: HistoryLogger) -> None:
        entry = tmp_logger.log_entry("quiz", "score 5/5")
        assert entry.timestamp != ""
        assert "T" in entry.timestamp  # ISO format contains 'T'
