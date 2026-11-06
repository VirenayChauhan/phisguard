"""Optional standards-based Web Push using owner-supplied VAPID keys."""
from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from engine import store


def _settings() -> tuple[str, str, str]:
    return (
        os.environ.get("VAPID_PUBLIC_KEY", "").strip(),
        os.environ.get("VAPID_PRIVATE_KEY", "").strip(),
        os.environ.get("VAPID_SUBJECT", "").strip(),
    )


def configured() -> bool:
    return all(_settings())


def public_key() -> str:
    public, _, _ = _settings()
    return public


def valid_endpoint(endpoint: str) -> bool:
    parsed = urlparse(endpoint or "")
    host = (parsed.hostname or "").lower().rstrip(".")
    allowed = (
        host == "fcm.googleapis.com"
        or host.endswith(".push.services.mozilla.com")
        or host == "updates.push.services.mozilla.com"
        or host == "web.push.apple.com"
    )
    return parsed.scheme == "https" and allowed and len(endpoint) <= 4096


def send_to_user(user_id: str, title: str, body: str, url: str = "/") -> int:
    """Deliver to that account's registered devices; prune expired subscriptions."""
    public, private, subject = _settings()
    if not (public and private and subject):
        return 0
    try:
        from pywebpush import WebPushException, webpush
    except ImportError:
        return 0
    sent = 0
    payload = json.dumps({
        "title": str(title)[:120],
        "body": str(body)[:500],
        "url": url if url.startswith("/") else "/",
    })
    for row in store.list_push_subscriptions(user_id):
        endpoint = row["endpoint"]
        try:
            subscription = json.loads(row["subscription_json"])
            webpush(
                subscription_info=subscription,
                data=payload,
                vapid_private_key=private,
                vapid_claims={"sub": subject},
                timeout=4,
                ttl=60 * 60,
            )
            sent += 1
        except WebPushException as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status in {404, 410}:
                store.delete_push_subscription(endpoint)
        except Exception:
            # Delivery is best-effort: an unavailable push service never breaks a scan.
            continue
    return sent
