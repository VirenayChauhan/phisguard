"""Low-volume Mailjet delivery for account security and opted-in summaries.

Secrets are read only from server-side environment variables and are never
logged. Mailjet delivery uses its HTTPS Send API (no SMTP egress dependency).
"""
from __future__ import annotations

import os

import requests

MAILJET_SEND_URL = "https://api.mailjet.com/v3.1/send"


class MailDeliveryError(RuntimeError):
    pass


def _settings() -> dict[str, str]:
    return {
        "api_key": os.environ.get("MAILJET_API_KEY", "").strip(),
        "secret_key": os.environ.get("MAILJET_SECRET_KEY", "").strip(),
        "sender": os.environ.get("MAILJET_FROM_EMAIL", "").strip(),
        "sender_name": os.environ.get("MAILJET_FROM_NAME", "PhishGuard").strip() or "PhishGuard",
    }


def configured() -> bool:
    settings = _settings()
    return bool(settings["api_key"] and settings["secret_key"] and settings["sender"])


def _provider_error_reference(response: requests.Response) -> str:
    """Return only non-sensitive Mailjet error identifiers, never its body."""
    try:
        body = response.json()
    except (ValueError, TypeError):
        return ""
    if not isinstance(body, dict):
        return ""
    parts = []
    for field in ("ErrorCode", "ErrorIdentifier"):
        value = body.get(field)
        if isinstance(value, str) and value and len(value) <= 80:
            # Avoid reflecting arbitrary provider text into the user-facing error.
            if all(char.isalnum() or char in "-_" for char in value):
                parts.append(f"{field}={value}")
    return "; ".join(parts)


def send_email(recipient: str, subject: str, text: str) -> None:
    settings = _settings()
    if not configured():
        raise MailDeliveryError("Mailjet is not configured.")
    payload = {
        "Messages": [{
            "From": {"Email": settings["sender"], "Name": settings["sender_name"]},
            "To": [{"Email": recipient}],
            "Subject": subject[:180],
            "TextPart": text[:12000],
        }]
    }
    try:
        response = requests.post(
            MAILJET_SEND_URL,
            auth=(settings["api_key"], settings["secret_key"]),
            json=payload,
            timeout=8,
        )
        if response.status_code >= 400:
            reference = _provider_error_reference(response)
            suffix = f"; {reference}" if reference else ""
            raise MailDeliveryError(
                f"Mailjet delivery failed (HTTP {response.status_code}{suffix})."
            )
        result = response.json()
        messages = result.get("Messages", []) if isinstance(result, dict) else []
        if not messages or messages[0].get("Status") != "success":
            raise MailDeliveryError("Mailjet did not accept the message.")
    except MailDeliveryError:
        raise
    except Exception as exc:
        raise MailDeliveryError(f"Mailjet delivery failed ({type(exc).__name__}).") from exc
