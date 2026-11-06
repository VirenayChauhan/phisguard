"""Offline, app-scoped help guide for PhishGuard.

Answers are selected only from the built-in PhishGuard FAQ. No user question is
sent to an LLM, search engine, or other external service.
"""
from __future__ import annotations

import re
from difflib import get_close_matches
from datetime import datetime, timedelta, timezone

from engine import store

RATE_WINDOW_SECONDS = 600
RATE_MAX_REQUESTS = 30
MAX_QUESTION_LENGTH = 1200

# App-oriented words allow short natural questions, while synonym and phrase
# hints cover common ways people describe the same task without exact FAQ terms.
DISTINCTIVE_TERMS = {
    "urlhaus", "virustotal", "phishtank", "safebrowsing", "otp", "gmail",
    "recovery", "signup", "register", "login", "signin", "link", "url",
    "eml", "scan", "phishing", "suspicious",
}
TOKEN_SYNONYMS = {
    "signin": {"login"}, "sign-in": {"login"}, "logged": {"login"},
    "access": {"login"}, "enter": {"login"}, "locked": {"login"},
    "blocked": {"login"}, "unlock": {"login"},
    "forgotten": {"forgot"}, "lost": {"forgot"}, "recover": {"recovery"},
    "retrieve": {"recovery"}, "passcode": {"password"}, "passphrase": {"password"},
    "secret": {"password"}, "signup": {"register"}, "join": {"register"},
    "setup": {"create"}, "make": {"create"}, "start": {"create"},
    "inspect": {"check"}, "review": {"check"}, "test": {"check"},
    "analyze": {"check"}, "analyse": {"check"}, "examine": {"check"},
    "website": {"link"}, "site": {"link"}, "webpage": {"link"},
    "address": {"url"}, "mail": {"email"}, "message": {"email"},
    "inbox": {"email"}, "preferences": {"settings"}, "options": {"settings"},
    "option": {"settings"}, "history": {"data"}, "records": {"data"},
    "stored": {"data"}, "alerts": {"notifications"}, "notify": {"notifications"},
    "broken": {"problem"}, "issue": {"problem"}, "trouble": {"problem"},
    "stuck": {"problem"}, "wrong": {"problem"}, "confused": {"help"},
}
PHRASE_HINTS = [
    (re.compile(r"\b(?:log|sign)\s+in(?:to|\s+to)?\b"), {"login", "signin", "access", "phishguard"}),
    (re.compile(r"\b(?:can't|cannot|can not|unable to|won't|will not)\s+(?:log|sign)\s+in(?:to|\s+to)?\b"), {"login", "signin", "access", "phishguard", "problem"}),
    (re.compile(r"\b(?:can't|cannot|can not|unable to|won't|will not)\s+(?:get in|access|enter)\b"), {"login", "signin", "access", "phishguard", "problem"}),
    (re.compile(r"\b(?:locked out|lockout|can't get into|cannot get into|won't let me in)\b"), {"login", "signin", "access", "phishguard", "problem"}),
    (re.compile(r"\b(?:password|passcode)\b.{0,30}\b(?:not working|isn't working|wrong|rejected|keeps failing)\b"), {"login", "password", "problem", "phishguard"}),
    (re.compile(r"\b(?:forgot|forgotten|lost|can't remember|cannot remember)\b.{0,35}\b(?:password|passcode|secret|log in|sign in)\b"), {"forgot", "password", "reset"}),
    (re.compile(r"\b(?:reset|change|update)\b.{0,30}\b(?:password|passcode)\b"), {"reset", "password"}),
    (re.compile(r"\b(?:set up|make|open|start)\b.{0,20}\b(?:new\s+)?account\b"), {"create", "register", "account"}),
    (re.compile(r"\b(?:email|mail|message)\b.{0,35}\b(?:looks?|seems?)?\s*(?:weird|odd|fake|off|suspicious|strange)\b"), {"suspicious", "email", "message", "check"}),
    (re.compile(r"\b(?:weird|odd|fake|off|suspicious|strange)\s+(?:email|mail|message)\b"), {"suspicious", "email", "message", "check"}),
    (re.compile(r"\b(?:link|url|website|site)\b.{0,35}\b(?:looks?|seems?)?\s*(?:weird|odd|fake|off|suspicious|strange)\b"), {"suspicious", "link", "url", "check"}),
    (re.compile(r"\b(?:weird|odd|fake|off|suspicious|strange)\s+(?:link|url|website|site)\b"), {"suspicious", "link", "url", "check"}),
]
VAGUE_WORDS = {"help", "problem", "issue", "trouble", "stuck", "wrong", "confused", "something", "anything", "thing", "isn", "working"}
STOP_WORDS = {
    "a", "about", "am", "an", "and", "are", "can", "could", "do", "does", "for",
    "give", "have", "i", "in", "is", "it", "me", "my", "of", "please", "the",
    "to", "what", "when", "where", "which", "who", "why", "with", "would", "you",
    "your", "need", "want", "just", "some", "s", "t", "there", "this", "that",
}
SUGGESTED_QUESTIONS = [
    "How do I log in to PhishGuard?",
    "How do I reset my PhishGuard password?",
    "How do I create a PhishGuard account?",
    "How do I check a suspicious link?",
    "How do I check an email in PhishGuard?",
    "How do I manage PhishGuard settings?",
]


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
            "and verify an address you control. A verified Gmail can receive one-time password "
            "recovery codes. If you opt in to monthly summaries, PhishGuard emails only flagged "
            "domains from your own scans—not full URLs or submitted email contents. Mobile numbers "
            "are format-checked but are not OTP-verified."
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


def _expanded_tokens(question: str) -> set[str]:
    tokens = _tokens(question)
    expanded = set(tokens)
    for token in tokens:
        expanded.update(TOKEN_SYNONYMS.get(token, ()))

    normalized = question.lower().replace("’", "'")
    for pattern, hints in PHRASE_HINTS:
        if pattern.search(normalized):
            expanded.update(hints)

    vocabulary = {word for item in FAQS for word in item["keywords"]}
    for token in tokens:
        if len(token) < 5 or token in vocabulary:
            continue
        close = get_close_matches(token, vocabulary, n=1, cutoff=0.82)
        if close:
            expanded.add(close[0])
    return expanded


def _best_answer(question: str) -> tuple[str, list[str]]:
    tokens = _tokens(question)
    expanded = _expanded_tokens(question)
    best_answer = None
    best_score = 0
    for item in FAQS:
        score = len(expanded & item["keywords"])
        if score > best_score:
            best_answer = item["answer"]
            best_score = score

    # If the wording is vague, ask one simple follow-up instead of guessing.
    meaningful = tokens - STOP_WORDS
    if best_score < 2 and (not meaningful or meaningful <= VAGUE_WORDS):
        return (
            "Sure — which part of PhishGuard do you need help with? Pick one of these, "
            "or tell me a little more:",
            SUGGESTED_QUESTIONS,
        )

    matched_terms = expanded & DISTINCTIVE_TERMS
    if best_answer and (best_score >= 2 or matched_terms):
        return best_answer, []

    return (
        "I can answer only PhishGuard questions. I may have missed what you mean — try "
        "rephrasing it, or choose one of these common topics:",
        SUGGESTED_QUESTIONS,
    )


def answer_public(question: str) -> dict:
    """Answer a pre-login help request without storing it or requiring an account."""
    question = _validate_question(question)
    answer_text, suggestions = _best_answer(question)
    return {
        "answer": answer_text,
        "suggestions": suggestions,
        "sources": [],
        "searched": False,
        "mode": "offline",
    }


def answer(question: str, username: str, request_ip: str) -> dict:
    question = _validate_question(question)
    request_ip = request_ip or "unknown"
    since = _iso(_now() - timedelta(seconds=RATE_WINDOW_SECONDS))
    if store.count_recent_assistant_requests(username, request_ip, since) >= RATE_MAX_REQUESTS:
        raise AssistantError("Help Guide rate limit reached. Please try again later.", 429)
    store.record_assistant_request(username, request_ip, _iso(_now()))
    answer_text, suggestions = _best_answer(question)
    return {
        "answer": answer_text,
        "suggestions": suggestions,
        "sources": [],
        "searched": False,
        "mode": "offline",
    }
