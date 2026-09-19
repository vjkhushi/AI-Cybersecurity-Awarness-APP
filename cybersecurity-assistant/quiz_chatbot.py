"""
quiz_chatbot.py
---------------
Manages the cybersecurity quiz and rule-based chatbot.
No Streamlit imports — pure logic only.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from exceptions import (
    EmptyInputError,
    InvalidQuizAnswerError,
    QuestionNotFoundError,
)
from quiz_data import CHATBOT_FALLBACK, CHATBOT_RESPONSES, QUIZ_QUESTIONS

# Valid answer keys
VALID_ANSWERS: frozenset[str] = frozenset({"A", "B", "C", "D"})


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class QuizQuestion:
    """Represents a single quiz question."""

    question_id: int
    question_text: str
    options: dict[str, str]      # {"A": "...", "B": "...", ...}
    correct_answer: str
    explanation: str


@dataclass
class QuizResult:
    """Holds the result of checking a single quiz answer."""

    question_id: int
    submitted_answer: str
    correct_answer: str
    is_correct: bool
    explanation: str


@dataclass
class QuizSession:
    """Tracks progress through a quiz session."""

    questions: list[QuizQuestion] = field(default_factory=list)
    current_index: int = 0
    score: int = 0
    answers: list[QuizResult] = field(default_factory=list)

    @property
    def total_questions(self) -> int:
        return len(self.questions)

    @property
    def is_complete(self) -> bool:
        return self.current_index >= self.total_questions

    @property
    def percentage(self) -> float:
        if self.total_questions == 0:
            return 0.0
        return round((self.score / self.total_questions) * 100, 1)


# ---------------------------------------------------------------------------
# QuizChatbot class
# ---------------------------------------------------------------------------
class QuizChatbot:
    """
    Provides quiz functionality and a simple rule-based chatbot.

    Usage
    -----
    qc = QuizChatbot()

    # Quiz
    session = qc.start_session(num_questions=5)
    question = qc.get_current_question(session)
    session = qc.submit_answer(session, "B")

    # Chatbot
    response = qc.get_chatbot_response("Tell me about phishing")
    """

    def __init__(self) -> None:
        self._questions: list[QuizQuestion] = self._load_questions()

    # ------------------------------------------------------------------
    # Question bank helpers
    # ------------------------------------------------------------------

    def _load_questions(self) -> list[QuizQuestion]:
        """Convert raw dicts from quiz_data.py into QuizQuestion objects."""
        return [QuizQuestion(**q) for q in QUIZ_QUESTIONS]

    def get_question(self, question_id: int) -> QuizQuestion:
        """
        Return a QuizQuestion by its ID.

        Raises
        ------
        QuestionNotFoundError
            If no question with the given ID exists.
        """
        for q in self._questions:
            if q.question_id == question_id:
                return q
        raise QuestionNotFoundError(
            f"No quiz question found with ID {question_id}."
        )

    def get_all_questions(self) -> list[QuizQuestion]:
        """Return a copy of the full question list."""
        return list(self._questions)

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def start_session(self, num_questions: int = 5) -> QuizSession:
        """
        Start a new quiz session with a random selection of questions.

        Parameters
        ----------
        num_questions : int
            How many questions to include. Clamped to available question count.
        """
        available = len(self._questions)
        count = min(max(1, num_questions), available)
        selected = random.sample(self._questions, count)
        return QuizSession(questions=selected)

    def get_current_question(self, session: QuizSession) -> QuizQuestion | None:
        """Return the current unanswered question, or None if the session is complete."""
        if session.is_complete:
            return None
        return session.questions[session.current_index]

    def submit_answer(self, session: QuizSession, answer: str) -> QuizSession:
        """
        Validate and record the user's answer, then advance to the next question.

        Parameters
        ----------
        session : QuizSession
            The active quiz session.
        answer : str
            The user's answer key ("A", "B", "C", or "D").

        Returns
        -------
        QuizSession
            The updated session (mutated in place and returned).

        Raises
        ------
        InvalidQuizAnswerError
            If the answer is not one of A, B, C, D.
        QuestionNotFoundError
            If the session is already complete.
        """
        answer = answer.strip().upper()

        if answer not in VALID_ANSWERS:
            raise InvalidQuizAnswerError(
                f"'{answer}' is not a valid answer. Choose A, B, C, or D."
            )

        if session.is_complete:
            raise QuestionNotFoundError("The quiz session is already complete.")

        question = session.questions[session.current_index]
        is_correct = answer == question.correct_answer

        result = QuizResult(
            question_id=question.question_id,
            submitted_answer=answer,
            correct_answer=question.correct_answer,
            is_correct=is_correct,
            explanation=question.explanation,
        )

        session.answers.append(result)
        if is_correct:
            session.score += 1
        session.current_index += 1

        return session

    # ------------------------------------------------------------------
    # Chatbot
    # ------------------------------------------------------------------

    def get_chatbot_response(self, user_input: str) -> str:
        """
        Match user input against keyword lists and return a relevant tip.
        Returns a fallback message if no keyword matches.

        Parameters
        ----------
        user_input : str
            Free-text input from the user.

        Raises
        ------
        EmptyInputError
            If user_input is empty or whitespace-only after stripping.
        """
        if not isinstance(user_input, str):
            raise EmptyInputError("Chatbot input must be a string.")

        cleaned = user_input.strip()
        if len(cleaned) < 2:
            raise EmptyInputError(
                "Please enter at least 2 characters to get a response."
            )

        lower = cleaned.lower()
        for entry in CHATBOT_RESPONSES:
            if any(keyword in lower for keyword in entry["keywords"]):
                return entry["response"]

        return CHATBOT_FALLBACK
