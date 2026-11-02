"""Offline, app-scoped help guide for PhishGuard.

Answers are selected only from the built-in PhishGuard FAQ. No user question is
sent to an LLM, search engine, or other external service.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from engine import store

RATE_WINDOW_SECONDS = 600
RATE_MAX_REQUESTS = 30
MAX_QUESTION_LENGTH = 1200

# A single distinctive app term can select an answer. Generic terms such as
# "password" or "email" alone are not enough to answer unrelated questions.
DISTINCTIVE_TERMS = {
    "urlhaus", "virustotal", "phishtank", "safebrowsing",
    "otp", "gmail", "recovery", "signup", "register", "login", "log", "signin",
    "link", "url", "eml", "scan", "phishing", "suspicious",
}


class AssistantError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


def _validate_question(question: str) -> str:
    if not isinstance(question, str) or not question.strip():
        raise AssistantError("Type a question first.", 400)
    question = question.strip()
    if len(question) > MAX_QUESTION_LENGTH:
        raise AssistantError(f"Question must be {MAX_QUESTION_LENGTH} characters or fewer.", 400)
    return question


FAQS = [
    {
        "keywords": {"create", "account", "register", "signup", "new"},
        "answer": (
            "On the sign-in screen, choose Create account and follow the three steps: "
            "choose a username, enter a valid Indian mobile number, set a password of "
            "at least 8 characters with a letter and a number, then choose a recovery "
            "question and answer. Gmail is optional during registration. After creating "
            "the account, you will be signed in."
        ),
    },
    {
        "keywords": {"login", "log", "signin", "sign", "password", "enter", "access", "phishguard"},
        "answer": (
            "On the PhishGuard login screen, enter the username and password used when "
            "the account was created, then choose Log in. Passwords are case-sensitive. "
            "If you cannot remember the password, choose Forgot password to use the "
            "recovery question or a code sent to a verified Gmail address."
        ),
    },
    {
        "keywords": {"switch", "multiple", "account", "accounts", "another", "change"},
        "answer": (
            "To switch accounts after signing in, open the profile button in the top-right "
            "corner and choose another saved username. You must enter that account's password. "
            "You can also choose Add account. Only usernames are remembered in the browser; "
            "passwords are never saved there."
        ),
    },
    {
        "keywords": {"profile", "user", "details", "mobile", "username"},
        "answer": (
            "Select your username in the top-right corner to see the active account details. "
            "Open Settings from the same menu to manage your profile, security, notifications, "
            "privacy, and appearance."
        ),
    },
    {
        "keywords": {"settings", "theme", "dark", "light", "appearance"},
        "answer": (
            "Open the top-right profile menu and select Settings. Choose a settings category "
            "to manage profile details, sign-in and security, notifications, privacy and data, "
            "appearance, or saved usernames on this device."
        ),
    },
    {
        "keywords": {"forgot", "reset", "password", "recovery", "code", "gmail", "phishguard"},
        "answer": (
            "On the login screen, choose Forgot password and enter the username. You can "
            "reset with the account's recovery question, or request a one-time code if a "
            "Gmail address has been added and verified. The email code expires after "
            "10 minutes. Never share a password or recovery code in the Help Guide."
        ),
    },
    {
        "keywords": {"change", "password", "current", "new"},
        "answer": (
            "After signing in, open the profile menu and choose Settings → Sign-in & security "
            "→ Change password. Enter your current password, choose a new password with at "
            "least 8 characters including a letter and a number, confirm it, and save."
        ),
    },
    {
        "keywords": {"change", "number", "mobile", "phone", "update"},
        "answer": (
            "Open Settings → Sign-in & security → Mobile number. Enter the new valid 10-digit "
            "Indian number and your current password, then save it. The number is checked for "
            "format but its ownership is not verified by OTP."
        ),
    },
    {
        "keywords": {"logout", "log", "out", "signout", "exit"},
        "answer": (
            "Open the profile menu in the top-right corner and select Log out. The active "
            "session ends immediately. Saved usernames may remain available, but a password "
            "is always required to sign in again."
        ),
    },
    {
        "keywords": {"link", "url", "check", "analyse", "analyze", "scan", "website", "phishing", "suspicious"},
        "answer": (
            "Choose Check a link from the left menu. Paste the URL and select Analyse. A quick "
            "check examines the URL locally; full analysis can add DNS, registration, and other "
            "signals. Third-party reputation lookups are optional per scan. Never open a "
            "suspicious link directly in your browser."
        ),
    },
    {
        "keywords": {"email", "mail", "eml", "message", "attachment", "header", "check"},
        "answer": (
            "Choose Check an email. Upload an .eml file or switch to Paste source and paste the "
            "complete raw message. PhishGuard checks available sender-authentication, link, "
            "attachment, and message-content signals. Outlook .msg files are not supported."
        ),
    },
    {
        "keywords": {"otp", "gmail", "verification", "code", "verify", "email"},
        "answer": (
            "Gmail verification is optional. After signing in, open Settings → Sign-in & security "
            "and verify an address you control. A verified Gmail can be used for one-time password "
            "recovery codes and, if email delivery is configured, opted-in scan or campaign updates. "
            "Mobile numbers are format-checked but are not OTP-verified."
        ),
    },
    {
        "keywords": {"data", "save", "saved", "database", "remember", "stored", "lost", "history"},
        "answer": (
            "PhishGuard saves accounts and scan history in its configured persistent database. "
            "The hosted site uses its production database; local development uses a local database. "
            "Do not delete or replace the hosted database to troubleshoot the app. Use Settings → "
            "Privacy & data to export or manage your own account data."
        ),
    },
    {
        "keywords": {"provider", "reputation", "virustotal", "urlhaus", "phishtank", "safebrowsing", "api", "key", "consent"},
        "answer": (
            "PhishGuard's own analysis runs independently. Optional Google Safe Browsing, "
            "VirusTotal, URLhaus, or PhishTank lookups run only when the per-scan sharing option "
            "is selected and that provider is configured. A provider no-match is not proof that "
            "a URL is safe. Never paste API keys into chat; only the site operator should store "
            "them in Vercel environment variables."
        ),
    },
    {
        "keywords": {"internet", "connection", "online", "offline", "network", "website"},
        "answer": (
            "The hosted PhishGuard site needs an internet connection. The Help Guide itself works "
            "offline, while full URL checks may need network access for DNS and registration data. "
            "If the hosted app fails to load, refresh once; if the problem continues, share the "
            "non-sensitive error message without passwords, recovery codes, or API keys."
        ),
    },
    {
        "keywords": {"error", "problem", "issue", "not", "working", "broken", "start"},
        "answer": (
            "If PhishGuard is not working, refresh the page and try again. If the problem remains, "
            "note the screen and exact error message and share it without passwords, one-time codes, "
            "or API keys. The Help Guide can only explain PhishGuard features; it cannot inspect "
            "your account or change settings for you."
        ),
    },
]


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _best_answer(question: str) -> str:
    tokens = _tokens(question)
    best = None
    best_score = 0
    for item in FAQS:
        score = len(tokens & item["keywords"])
        if score > best_score:
            best = item["answer"]
            best_score = score
    matched_terms = tokens & DISTINCTIVE_TERMS
    if best and (best_score >= 2 or matched_terms):
        return best
    return (
        "I can answer only PhishGuard questions, such as how to log in, recover an account, "
        "check a link or email, manage settings, or understand optional scan signals. I can't "
        "help with general topics. Please rephrase your question about the app."
    )


def answer_public(question: str) -> dict:
    """Answer a pre-login help request without storing it or requiring an account."""
    question = _validate_question(question)
    return {"answer": _best_answer(question), "sources": [], "searched": False, "mode": "offline"}


def answer(question: str, username: str, request_ip: str) -> dict:
    question = _validate_question(question)
    request_ip = request_ip or "unknown"
    since = _iso(_now() - timedelta(seconds=RATE_WINDOW_SECONDS))
    if store.count_recent_assistant_requests(username, request_ip, since) >= RATE_MAX_REQUESTS:
        raise AssistantError("Help Guide rate limit reached. Please try again later.", 429)
    store.record_assistant_request(username, request_ip, _iso(_now()))
    return {"answer": _best_answer(question), "sources": [], "searched": False, "mode": "offline"}
