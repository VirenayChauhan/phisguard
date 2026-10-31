"""Offline Help AI for PhishGuard.

This is a small local help chatbot. It uses the app's built-in question-and-
solution guide, so it needs no OpenAI key, web-search API, or external service.
The rest of PhishGuard may still use the internet when the user requests a full
URL analysis.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from engine import store

RATE_WINDOW_SECONDS = 600
RATE_MAX_REQUESTS = 30
MAX_QUESTION_LENGTH = 1200


class AssistantError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


FAQS = [
    {
        "keywords": {"create", "account", "register", "signup", "new"},
        "answer": (
            "To create an account, open the Log in screen and choose Create account. "
            "Enter a username, a valid 10-digit Indian mobile number, and a password "
            "with at least 8 characters, including a letter and a number. Confirm the "
            "password and select Create account. You will be logged in automatically."
        ),
    },
    {
        "keywords": {"login", "log", "signin", "sign", "password", "enter", "access"},
        "answer": (
            "Choose Log in on the welcome screen, enter the username and password used "
            "when the account was created, then select Log in. Passwords are case-sensitive. "
            "After several incorrect attempts, wait for the temporary security limit to finish."
        ),
    },
    {
        "keywords": {"switch", "multiple", "account", "accounts", "another", "change"},
        "answer": (
            "To switch accounts, open the profile button in the top-right corner and choose "
            "another saved username. The current account is logged out first, then you must "
            "enter that account's password. You can also choose Add account to register a new one. "
            "Only usernames are remembered in the browser; passwords are never saved there."
        ),
    },
    {
        "keywords": {"profile", "user", "details", "mobile", "username"},
        "answer": (
            "Select your username in the top-right corner to see the active account's username "
            "and mobile number. Open Settings from the same menu for the full account panel."
        ),
    },
    {
        "keywords": {"settings", "theme", "dark", "light", "appearance"},
        "answer": (
            "Open the top-right profile menu and select Settings. You can review the active "
            "account details, switch between dark and light appearance, view saved accounts, "
            "or add another account."
        ),
    },
    {
        "keywords": {"change", "password", "forgot", "current", "new"},
        "answer": (
            "Open the top-right profile menu and select Settings. In Change password, enter "
            "your current password, enter a new password with at least 8 characters including "
            "a letter and a number, confirm it, and select Change password. Older sessions are "
            "signed out for security."
        ),
    },
    {
        "keywords": {"change", "number", "mobile", "phone", "update"},
        "answer": (
            "Open Profile → Settings. Under Change mobile number, enter the new valid 10-digit "
            "Indian number and your current password, then select Save mobile number. The number "
            "is format-validated but not OTP-verified."
        ),
    },
    {
        "keywords": {"logout", "log", "out", "signout", "exit"},
        "answer": (
            "Open the profile menu in the top-right corner and select Log out. The active session "
            "ends immediately. Saved usernames remain available, but you must enter a password "
            "to log in again."
        ),
    },
    {
        "keywords": {"link", "url", "check", "analyse", "analyze", "scan", "website"},
        "answer": (
            "Choose Check a link from the left menu. Paste the URL into the input box and select "
            "Analyse. Quick analysis checks the URL structure locally; full analysis can use DNS, "
            "registration, reputation, and a safe server-side preview. Never open a suspicious link "
            "directly in your browser."
        ),
    },
    {
        "keywords": {"email", "mail", "eml", "message", "attachment", "header"},
        "answer": (
            "Choose Check an email. Upload an .eml file or switch to Paste source and paste the "
            "complete raw message. PhishGuard checks authentication headers, links, attachments, "
            "BEC language, and bank-detail changes."
        ),
    },
    {
        "keywords": {"otp", "gmail", "verification", "code", "phone", "verify"},
        "answer": (
            "This version does not use OTP or Gmail verification. It uses a local username and "
            "password account system. The mobile number is checked for valid Indian-number format, "
            "but its ownership is not verified."
        ),
    },
    {
        "keywords": {"data", "save", "saved", "database", "remember", "stored", "lost"},
        "answer": (
            "Accounts and PhishGuard records are stored in data/phishguard.db. Keep that file when "
            "moving the project or updating the code. Deleting it removes the saved local accounts "
            "and application history."
        ),
    },
    {
        "keywords": {"internet", "connection", "online", "offline", "network"},
        "answer": (
            "The website runs locally at http://localhost:8000. The built-in Help AI works without "
            "an AI API, while full URL infrastructure checks may need an internet connection. If the "
            "site does not open, confirm that run.bat is still running and open the localhost address."
        ),
    },
    {
        "keywords": {"error", "problem", "issue", "not", "working", "broken", "run", "start"},
        "answer": (
            "If the site is not working, stop any old server window, open PowerShell inside the inner "
            "phishguard folder, and run .\\run.bat. Wait until it shows the localhost address, then "
            "open http://localhost:8000. If an error remains, copy the exact red error text so it can "
            "be diagnosed."
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
    if best:
        return best
    return (
        "I can help with PhishGuard account creation, login, switching accounts, settings, "
        "link analysis, email analysis, saved data, and running the website. Try asking: "
        "‘How do I create an account?’, ‘How do I switch accounts?’, or ‘How do I check a link?’"
    )


def answer(question: str, username: str, request_ip: str) -> dict:
    if not isinstance(question, str) or not question.strip():
        raise AssistantError("Type a question first.", 400)
    question = question.strip()
    if len(question) > MAX_QUESTION_LENGTH:
        raise AssistantError(f"Question must be {MAX_QUESTION_LENGTH} characters or fewer.", 400)

    request_ip = request_ip or "unknown"
    since = _iso(_now() - timedelta(seconds=RATE_WINDOW_SECONDS))
    if store.count_recent_assistant_requests(username, request_ip, since) >= RATE_MAX_REQUESTS:
        raise AssistantError("Help AI rate limit reached. Please try again later.", 429)
    store.record_assistant_request(username, request_ip, _iso(_now()))
    return {"answer": _best_answer(question), "sources": [], "searched": False, "mode": "offline"}
