"""
exceptions.py
-------------
Custom exception classes for the Cybersecurity Awareness Assistant.
All exceptions extend the built-in Exception class.
"""


class EmptyInputError(Exception):
    """Raised when the user submits an empty or whitespace-only input."""


class InputTooLongError(Exception):
    """Raised when the user's input exceeds the maximum allowed character length."""


class InvalidURLFormatError(Exception):
    """Raised when a URL does not match the expected http/https format."""


class InvalidQuizAnswerError(Exception):
    """Raised when a submitted quiz answer is not one of A, B, C, or D."""


class QuestionNotFoundError(Exception):
    """Raised when a quiz question ID does not exist in the question bank."""


class LogFileError(Exception):
    """Raised when the log file cannot be read from or written to."""
