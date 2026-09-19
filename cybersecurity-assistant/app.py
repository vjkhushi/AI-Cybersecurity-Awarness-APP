"""
app.py
------
Streamlit entry point for the Cybersecurity Awareness Assistant.
All display logic lives here. Core logic is imported from separate modules.

Run with:
    streamlit run app.py
"""

from __future__ import annotations

import streamlit as st

from exceptions import (
    EmptyInputError,
    InputTooLongError,
    InvalidURLFormatError,
    LogFileError,
)
from history_logger import HistoryLogger
from password_checker import PasswordChecker
from phishing_analyzer import PhishingAnalyzer
from quiz_chatbot import QuizChatbot

# ---------------------------------------------------------------------------
# Page configuration (must be the first Streamlit call)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Cybersecurity Awareness Assistant",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Module instances (cached so they are only created once per session)
# ---------------------------------------------------------------------------


@st.cache_resource
def get_analyzer() -> PhishingAnalyzer:
    return PhishingAnalyzer()


@st.cache_resource
def get_checker() -> PasswordChecker:
    return PasswordChecker()


@st.cache_resource
def get_quiz_chatbot() -> QuizChatbot:
    return QuizChatbot()


@st.cache_resource
def get_logger() -> HistoryLogger:
    return HistoryLogger()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

RISK_COLOURS: dict[str, str] = {
    "High Risk": "🔴",
    "Suspicious": "🟡",
    "Safe": "🟢",
}


def risk_badge(risk_level: str) -> str:
    icon = RISK_COLOURS.get(risk_level, "⚪")
    return f"{icon} **{risk_level}**"


# ---------------------------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------------------------

PAGES: list[str] = [
    "🔍 Phishing Analyzer",
    "🔑 Password Checker",
    "🎓 Quiz & Chatbot",
    "📋 History & Logs",
]

st.sidebar.title("🔐 CyberGuard")
st.sidebar.caption("Cybersecurity Awareness Assistant")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigate to", PAGES, key="nav_page")
st.sidebar.markdown("---")
st.sidebar.info(
    "**Tip:** This tool uses rule-based analysis. "
    "For production security needs, consult a professional cybersecurity service."
)

# ===========================================================================
# PAGE 1 — PHISHING ANALYZER
# ===========================================================================
if page == PAGES[0]:
    st.title("🔍 Phishing & Link Analyzer")
    st.write(
        "Paste a suspicious email, SMS message, or website URL below. "
        "The analyzer will check for common phishing indicators and give you "
        "an instant risk assessment."
    )

    analyzer = get_analyzer()
    logger = get_logger()

    input_type_choice = st.radio(
        "What are you analyzing?",
        ["📧 Text message / Email / SMS", "🔗 Website URL"],
        horizontal=True,
        key="phishing_input_type",
    )

    placeholder = (
        "Paste your suspicious URL here, e.g. https://payp4l.com/verify-account"
        if "URL" in input_type_choice
        else "Paste the suspicious email or message text here…"
    )

    user_input = st.text_area(
        "Input",
        height=160,
        placeholder=placeholder,
        key="phishing_input",
        label_visibility="collapsed",
    )

    col1, col2 = st.columns([1, 5])
    with col1:
        analyze_clicked = st.button("Analyze 🔍", type="primary", use_container_width=True)

    if analyze_clicked:
        if not user_input.strip():
            st.error("⚠️ Please enter some text or a URL before clicking Analyze.")
        else:
            try:
                result = analyzer.analyze(user_input)

                st.markdown("---")
                st.subheader("Risk Assessment")

                badge_col, _ = st.columns([1, 3])
                with badge_col:
                    st.markdown(f"### {risk_badge(result.risk_level)}")

                st.markdown(f"**Input type detected:** `{result.input_type}`")

                if result.matched_flags:
                    st.markdown("**Red flags detected:**")
                    for flag in result.matched_flags:
                        st.markdown(f"- {flag}")
                else:
                    st.markdown("**Red flags detected:** None")

                st.markdown("---")
                st.markdown("**Explanation**")
                st.info(result.explanation)

                # Log the result
                summary = (
                    f"{result.risk_level} | {result.input_type} | "
                    f"{len(result.matched_flags)} flag(s) | "
                    f"Input: {result.input_text[:60]}{'…' if len(result.input_text) > 60 else ''}"
                )
                logger.log_entry("phishing", summary)
                st.caption(f"✅ Result logged at {result.timestamp}")

            except (EmptyInputError, InputTooLongError, InvalidURLFormatError) as exc:
                st.error(f"⚠️ {exc}")
            except LogFileError as exc:
                st.warning(f"⚠️ Could not save to log: {exc}")


# ===========================================================================
# PAGE 2 — PASSWORD CHECKER
# ===========================================================================
elif page == PAGES[1]:
    st.title("🔑 Password Strength Checker")
    st.write(
        "Enter a password below to see how strong it is and receive "
        "specific advice on how to improve it. "
        "**Your password is never saved or logged.**"
    )

    checker = get_checker()
    logger = get_logger()

    password_input = st.text_input(
        "Password",
        type="password",
        placeholder="Enter a password to test…",
        key="password_input",
    )

    show_password = st.checkbox("Show password as plain text", key="show_pw")
    if show_password and password_input:
        st.code(password_input, language=None)

    check_clicked = st.button("Check Strength 🔑", type="primary")

    if check_clicked:
        if not password_input:
            st.error("⚠️ Please enter a password to check.")
        else:
            try:
                result = checker.check_password(password_input)

                st.markdown("---")
                st.subheader("Strength Result")

                # Colour the score bar
                score = result.strength_score
                st.metric("Score", f"{score} / 5")
                st.progress(score / 5)
                st.markdown(f"**Rating:** {result.strength_label}")

                if result.warnings:
                    st.markdown("**⚠️ Warnings:**")
                    for w in result.warnings:
                        st.error(w)

                if result.tips:
                    st.markdown("---")
                    st.markdown("**💡 Improvement tips:**")
                    for tip in result.tips:
                        st.markdown(f"- {tip}")
                else:
                    st.success(
                        "✅ Your password meets all five strength criteria. Well done!"
                    )

                # Log only the label — never the password
                logger.log_entry(
                    "password",
                    f"{result.strength_label} | Score {result.strength_score}/5",
                )

            except EmptyInputError as exc:
                st.error(f"⚠️ {exc}")
            except LogFileError as exc:
                st.warning(f"⚠️ Could not save to log: {exc}")


# ===========================================================================
# PAGE 3 — QUIZ & CHATBOT
# ===========================================================================
elif page == PAGES[2]:
    st.title("🎓 Quiz & Cybersecurity Chatbot")
    st.write(
        "Choose between the interactive quiz to test your knowledge, "
        "or the chatbot to ask cybersecurity questions."
    )

    qc = get_quiz_chatbot()
    logger = get_logger()

    tab_quiz, tab_chat = st.tabs(["📝 Quiz", "💬 Chatbot"])

    # -----------------------------------------------------------------------
    # Quiz tab
    # -----------------------------------------------------------------------
    with tab_quiz:
        st.subheader("Cybersecurity Knowledge Quiz")

        NUM_QUESTIONS = 5

        # Initialise session state for the quiz
        if "quiz_session" not in st.session_state:
            st.session_state.quiz_session = None
        if "quiz_feedback" not in st.session_state:
            st.session_state.quiz_feedback = None

        session = st.session_state.quiz_session

        if session is None or session.is_complete:
            if session is not None and session.is_complete:
                # Show final score
                pct = session.percentage
                st.markdown("---")
                st.subheader("🏁 Quiz Complete!")
                st.metric(
                    "Final Score",
                    f"{session.score} / {session.total_questions}",
                    f"{pct}%",
                )
                if pct == 100:
                    st.balloons()
                    st.success("🎉 Perfect score! You're a cybersecurity pro!")
                elif pct >= 60:
                    st.info(f"👍 Good effort! You scored {pct}%.")
                else:
                    st.warning(
                        f"⚠️ You scored {pct}%. Review the explanations below and try again!"
                    )

                # Show answer review
                with st.expander("📖 Review your answers"):
                    for r in session.answers:
                        q = qc.get_question(r.question_id)
                        icon = "✅" if r.is_correct else "❌"
                        st.markdown(f"**{icon} Q: {q.question_text}**")
                        st.markdown(
                            f"Your answer: **{r.submitted_answer}** "
                            f"({q.options.get(r.submitted_answer, '?')}) | "
                            f"Correct: **{r.correct_answer}** "
                            f"({q.options.get(r.correct_answer, '?')})"
                        )
                        st.caption(f"📘 {r.explanation}")
                        st.markdown("---")

                logger.log_entry(
                    "quiz",
                    f"Quiz completed | Score: {session.score}/{session.total_questions} ({pct}%)",
                )

                st.markdown("")

            if st.button("▶️ Start New Quiz", type="primary"):
                st.session_state.quiz_session = qc.start_session(NUM_QUESTIONS)
                st.session_state.quiz_feedback = None
                st.rerun()
        else:
            # Active quiz
            q_num = session.current_index + 1
            question = qc.get_current_question(session)

            st.progress(session.current_index / session.total_questions)
            st.caption(
                f"Question {q_num} of {session.total_questions} | "
                f"Score so far: {session.score}"
            )
            st.markdown(f"**{question.question_text}**")

            answer_choice = st.radio(
                "Choose your answer:",
                options=list(question.options.keys()),
                format_func=lambda k: f"{k}: {question.options[k]}",
                key=f"quiz_answer_{session.current_index}",
            )

            if st.session_state.quiz_feedback:
                feedback = st.session_state.quiz_feedback
                if feedback["correct"]:
                    st.success(f"✅ Correct! {feedback['explanation']}")
                else:
                    st.error(
                        f"❌ Incorrect. The correct answer was **{feedback['correct_answer']}**: "
                        f"{feedback['correct_option']}. {feedback['explanation']}"
                    )

                if st.button("Next Question ➡️", type="primary"):
                    st.session_state.quiz_feedback = None
                    st.rerun()
            else:
                if st.button("Submit Answer ✔️", type="primary"):
                    session = qc.submit_answer(session, answer_choice)
                    last_result = session.answers[-1]
                    q_data = qc.get_question(last_result.question_id)
                    st.session_state.quiz_session = session
                    st.session_state.quiz_feedback = {
                        "correct": last_result.is_correct,
                        "correct_answer": last_result.correct_answer,
                        "correct_option": q_data.options.get(
                            last_result.correct_answer, ""
                        ),
                        "explanation": last_result.explanation,
                    }
                    st.rerun()

    # -----------------------------------------------------------------------
    # Chatbot tab
    # -----------------------------------------------------------------------
    with tab_chat:
        st.subheader("Cybersecurity Tip Chatbot")
        st.write(
            "Ask me about: phishing, passwords, 2FA, VPN, malware, "
            "public Wi-Fi, backups, HTTPS, scams, or data breaches."
        )

        # Initialise chat history
        if "chat_history" not in st.session_state:
            st.session_state.chat_history = []

        # Display chat history
        for msg in st.session_state.chat_history:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

        # Chat input
        user_message = st.chat_input("Ask a cybersecurity question…")
        if user_message:
            # Show user message
            st.session_state.chat_history.append(
                {"role": "user", "content": user_message}
            )
            with st.chat_message("user"):
                st.markdown(user_message)

            # Get and show bot response
            try:
                response = qc.get_chatbot_response(user_message)
            except EmptyInputError as exc:
                response = f"⚠️ {exc}"

            st.session_state.chat_history.append(
                {"role": "assistant", "content": response}
            )
            with st.chat_message("assistant"):
                st.markdown(response)

            # Log chat interaction
            try:
                logger.log_entry(
                    "chat",
                    f"User asked: {user_message[:80]}{'…' if len(user_message) > 80 else ''}",
                )
            except LogFileError:
                pass  # Silent fail for chat logging

        if st.session_state.chat_history:
            if st.button("🗑️ Clear Chat History"):
                st.session_state.chat_history = []
                st.rerun()


# ===========================================================================
# PAGE 4 — HISTORY & LOGS
# ===========================================================================
elif page == PAGES[3]:
    st.title("📋 Analysis History & Logs")
    st.write(
        "All your analysis results from this application are stored below. "
        "Logs survive page refreshes and app restarts."
    )

    logger = get_logger()

    try:
        total = logger.get_entry_count()
        st.metric("Total Logged Analyses", total)

        st.markdown("---")

        col_search, col_clear = st.columns([4, 1])
        with col_search:
            search_term = st.text_input(
                "🔎 Search logs",
                placeholder="Search by keyword, e.g. 'High Risk', 'phishing', 'password'…",
                key="log_search",
            )
        with col_clear:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🗑️ Clear All Logs", use_container_width=True):
                logger.clear_history()
                st.success("✅ All logs cleared.")
                st.rerun()

        # Retrieve entries
        if search_term.strip():
            entries = logger.search_entries(search_term.strip())
            st.caption(
                f"Showing {len(entries)} result(s) matching '{search_term.strip()}'"
            )
        else:
            entries = logger.get_all_entries()

        if not entries:
            st.info(
                "📭 No log entries yet. Run a phishing analysis, password check, "
                "or quiz to see entries appear here."
            )
        else:
            TYPE_ICONS: dict[str, str] = {
                "phishing": "🔍",
                "password": "🔑",
                "quiz": "🎓",
                "chat": "💬",
            }
            for entry in entries:
                icon = TYPE_ICONS.get(entry.analysis_type, "📄")
                with st.expander(
                    f"{icon} [{entry.analysis_type.upper()}] #{entry.entry_id} — {entry.timestamp}"
                ):
                    st.markdown(f"**Summary:** {entry.summary}")
                    st.caption(f"Logged at: {entry.timestamp}")

    except LogFileError as exc:
        st.error(f"⚠️ Could not access the log file: {exc}")
