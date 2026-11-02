"""Low-volume Gmail SMTP delivery for account recovery and opt-in notices.

This only activates when server-side Gmail credentials are configured. It never
logs message bodies, recipient addresses, usernames, or credential values.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage


class MailDeliveryError(RuntimeError):
    pass


def _settings() -> dict[str, str]:
    username = os.environ.get("GMAIL_SMTP_USERNAME", "").strip()
    password = os.environ.get("GMAIL_SMTP_APP_PASSWORD", "").replace(" ", "").strip()
    return {
        "host": os.environ.get("GMAIL_SMTP_HOST", "smtp.gmail.com").strip(),
        "port": os.environ.get("GMAIL_SMTP_PORT", "587").strip(),
        "username": username,
        "password": password,
        "sender": os.environ.get("GMAIL_FROM_ADDRESS", username).strip(),
    }


def configured() -> bool:
    settings = _settings()
    return bool(settings["username"] and settings["password"] and settings["sender"])


def send_email(recipient: str, subject: str, text: str) -> None:
    settings = _settings()
    if not configured():
        raise MailDeliveryError("Gmail SMTP is not configured.")
    message = EmailMessage()
    message["From"] = settings["sender"]
    message["To"] = recipient
    message["Subject"] = subject[:180]
    message.set_content(text[:12000])
    try:
        with smtplib.SMTP(settings["host"], int(settings["port"]), timeout=8) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            smtp.login(settings["username"], settings["password"])
            smtp.send_message(message)
    except Exception as exc:
        raise MailDeliveryError(f"Gmail SMTP delivery failed ({type(exc).__name__}).") from exc
