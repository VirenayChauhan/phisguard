"""PhishGuard — a phishing link & email checker with receipts.

Run:  python3 app.py     (binds 0.0.0.0:8000)
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone

from authlib.integrations.flask_client import OAuth
from flask import Flask, g, jsonify, make_response, redirect, render_template, request, send_from_directory, session, url_for

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # requirements.txt installs this; keep imports resilient for tests
    pass

from engine import assistant, auth, emailscan, mailer, push, store, urlscan

MAX_UPLOAD = 12 * 1024 * 1024  # 12 MB .eml ceiling

# Keep Flask's same-origin /static URL contract while placing deployable assets
# under Vercel's public directory for edge/CDN delivery. Locally Flask serves the
# same files from this folder as usual.
app = Flask(__name__, static_folder="public/static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
app.config["AUTH_COOKIE_SECURE"] = os.environ.get("AUTH_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"}
app.config["AUTH_COOKIE_NAME"] = "__Host-pg_session" if app.config["AUTH_COOKIE_SECURE"] else "pg_session"
# Flask's signed session carries only OAuth state/nonce for the short Google redirect.
# Configure FLASK_SECRET_KEY persistently in every production/container environment.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "").strip() or secrets.token_urlsafe(48)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = app.config["AUTH_COOKIE_SECURE"]
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["GOOGLE_CLIENT_ID"] = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
app.config["GOOGLE_CLIENT_SECRET"] = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
app.config["GOOGLE_REDIRECT_URI"] = os.environ.get("GOOGLE_REDIRECT_URI", "").strip()
app.config["MICROSOFT_CLIENT_ID"] = os.environ.get("MICROSOFT_CLIENT_ID", "").strip()
app.config["MICROSOFT_CLIENT_SECRET"] = os.environ.get("MICROSOFT_CLIENT_SECRET", "").strip()
app.config["MICROSOFT_REDIRECT_URI"] = os.environ.get("MICROSOFT_REDIRECT_URI", "").strip()
app.config["MICROSOFT_TENANT_ID"] = os.environ.get("MICROSOFT_TENANT_ID", "common").strip() or "common"
# Templates/CSS are edited during pilots; never serve a stale cached page.
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
_oauth = OAuth(app)
_google = _oauth.register(
    name="google",
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)
_microsoft = _oauth.register(
    name="microsoft",
    client_id=app.config["MICROSOFT_CLIENT_ID"],
    client_secret=app.config["MICROSOFT_CLIENT_SECRET"],
    server_metadata_url=(
        "https://login.microsoftonline.com/"
        f"{app.config['MICROSOFT_TENANT_ID']}/v2.0/.well-known/openid-configuration"
    ),
    client_kwargs={"scope": "openid profile email"},
)

def google_auth_configured() -> bool:
    return bool(
        app.config["GOOGLE_CLIENT_ID"]
        and app.config["GOOGLE_CLIENT_SECRET"]
        and app.config["GOOGLE_REDIRECT_URI"]
        and os.environ.get("FLASK_SECRET_KEY", "").strip()
    )


def microsoft_auth_configured() -> bool:
    tenant_id = app.config["MICROSOFT_TENANT_ID"]
    valid_tenant = tenant_id == "common"
    if not valid_tenant:
        try:
            valid_tenant = str(uuid.UUID(tenant_id)) == tenant_id.lower()
        except (ValueError, TypeError, AttributeError):
            valid_tenant = False
    return bool(
        app.config["MICROSOFT_CLIENT_ID"]
        and app.config["MICROSOFT_CLIENT_SECRET"]
        and app.config["MICROSOFT_REDIRECT_URI"]
        and valid_tenant
        and os.environ.get("FLASK_SECRET_KEY", "").strip()
    )


def _microsoft_issuer_is_valid(profile) -> bool:
    """Validate Microsoft common-endpoint issuer against the signed tenant ID."""
    try:
        tenant_id = str(uuid.UUID(str(profile.get("tid", ""))))
    except (ValueError, TypeError, AttributeError):
        return False
    expected_issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    if profile.get("iss") != expected_issuer:
        return False
    configured_tenant = app.config["MICROSOFT_TENANT_ID"]
    if configured_tenant == "common":
        return True
    try:
        return str(uuid.UUID(configured_tenant)) == tenant_id
    except (ValueError, TypeError, AttributeError):
        return False


PUBLIC_API_PATHS = {
    "/api/health",
    "/api/public-check-count",
    "/api/auth/session",
    "/api/auth/register",
    "/api/auth/login",
    "/api/auth/forgot-password/question",
    "/api/auth/forgot-password/reset",
    "/api/auth/forgot-password/email/request",
    "/api/auth/forgot-password/email/reset",
    "/api/auth/logout",
    "/api/cron/cluster-digest",
    "/api/cron/monthly-scan-summary",
}


@app.before_request
def start_request_timer():
    g.phishguard_request_started = time.perf_counter()


@app.before_request
def require_authentication():
    """Keep the dashboard and every analysis API behind the verified session."""
    if not request.path.startswith("/api/"):
        return None
    if request.path == "/api/assistant":
        # The built-in, read-only FAQ is available before login. Still require the
        # normal request-protection header when an authenticated user submits it.
        user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
        if user and request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.headers.get("X-Requested-With") != "XMLHttpRequest":
            return jsonify({"error": "missing request protection header"}), 403
        return None
    if request.path in PUBLIC_API_PATHS:
        return None
    if auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"])):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.headers.get("X-Requested-With") != "XMLHttpRequest":
            return jsonify({"error": "missing request protection header"}), 403
        return None
    return jsonify({"error": "authentication required"}), 401


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/sw.js")
def service_worker():
    response = make_response(send_from_directory(app.static_folder, "sw.js"))
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/login")
def login_page():
    """Serve the sign-in view as a distinct route from the public landing page."""
    return render_template("index.html", login_page=True)


@app.get("/ui-trial")
def ui_trial():
    """Render the isolated editorial split-screen sign-in trial."""
    return render_template("index.html", ui_trial=True)


@app.get("/auth/google/start")
def google_sign_in_start():
    if not google_auth_configured():
        return redirect(url_for("login_page", google_error="setup"))
    nonce = secrets.token_urlsafe(32)
    session["google_oauth_nonce"] = nonce
    try:
        return _google.authorize_redirect(app.config["GOOGLE_REDIRECT_URI"], nonce=nonce)
    except Exception as exc:
        session.pop("google_oauth_nonce", None)
        app.logger.warning("Could not start Google sign-in (%s)", type(exc).__name__)
        return redirect(url_for("login_page", google_error="failed"))


@app.get("/auth/google/callback")
def google_sign_in_callback():
    if not google_auth_configured():
        return redirect(url_for("login_page", google_error="setup"))
    if request.args.get("error") == "access_denied":
        session.pop("google_oauth_nonce", None)
        return redirect(url_for("login_page", google_error="cancelled"))
    nonce = session.pop("google_oauth_nonce", None)
    if not nonce:
        return redirect(url_for("login_page", google_error="state"))
    try:
        token = _google.authorize_access_token()
        profile = token.get("userinfo")
        if not profile:
            profile = _google.parse_id_token(token, nonce=nonce)
        user, raw_token = auth.google_login_account(
            profile.get("sub", ""), profile.get("email", ""),
            profile.get("email_verified") is True, profile.get("name", ""),
            request.remote_addr or "unknown", request.headers.get("User-Agent", ""),
        )
        session.clear()
        response = redirect("/")
        return _set_auth_cookie(response, raw_token)
    except auth.AuthError as exc:
        app.logger.info("Google account sign-in was declined (status %s)", exc.status)
        return redirect(url_for("login_page", google_error="account"))
    except Exception as exc:
        app.logger.warning("Google sign-in failed (%s)", type(exc).__name__)
        return redirect(url_for("login_page", google_error="failed"))


@app.get("/auth/microsoft/start")
def microsoft_sign_in_start():
    if not microsoft_auth_configured():
        return redirect(url_for("login_page", microsoft_error="setup"))
    nonce = secrets.token_urlsafe(32)
    session["microsoft_oauth_nonce"] = nonce
    try:
        return _microsoft.authorize_redirect(
            app.config["MICROSOFT_REDIRECT_URI"], nonce=nonce
        )
    except Exception as exc:
        session.pop("microsoft_oauth_nonce", None)
        app.logger.warning("Could not start Microsoft sign-in (%s)", type(exc).__name__)
        return redirect(url_for("login_page", microsoft_error="failed"))


@app.get("/auth/microsoft/callback")
def microsoft_sign_in_callback():
    if not microsoft_auth_configured():
        return redirect(url_for("login_page", microsoft_error="setup"))
    if request.args.get("error") == "access_denied":
        session.pop("microsoft_oauth_nonce", None)
        return redirect(url_for("login_page", microsoft_error="cancelled"))
    nonce = session.pop("microsoft_oauth_nonce", None)
    if not nonce:
        return redirect(url_for("login_page", microsoft_error="state"))
    try:
        token = _microsoft.authorize_access_token(
            claims_options={"iss": {"essential": True}}
        )
        profile = token.get("userinfo")
        if not profile:
            profile = _microsoft.parse_id_token(
                token, nonce=nonce, claims_options={"iss": {"essential": True}}
            )
        if not profile or not _microsoft_issuer_is_valid(profile):
            raise auth.AuthError("Microsoft returned an invalid tenant identity.", 401)
        email = profile.get("email") or profile.get("preferred_username") or ""
        user, raw_token = auth.microsoft_login_account(
            profile.get("sub", ""), email, profile.get("name", ""),
            request.remote_addr or "unknown", request.headers.get("User-Agent", ""),
            email_verified=profile.get("email_verified") is True,
        )
        session.clear()
        response = redirect("/")
        return _set_auth_cookie(response, raw_token)
    except auth.AuthError as exc:
        app.logger.info("Microsoft account sign-in was declined (status %s)", exc.status)
        return redirect(url_for("login_page", microsoft_error="account"))
    except Exception as exc:
        app.logger.warning("Microsoft sign-in failed (%s)", type(exc).__name__)
        return redirect(url_for("login_page", microsoft_error="failed"))


@app.get("/api/health")
def health():
    from engine import intel
    return jsonify({"ok": True, "intel": intel.configured(), "stats": store.stats()})


@app.get("/api/public-check-count")
def public_check_count():
    """Expose only the aggregate completed-scan total used on the public landing page."""
    return jsonify({"checks_completed": store.completed_check_count()})


@app.get("/api/auth/session")
def auth_session():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    return jsonify({"authenticated": bool(user), "user": user})


def _set_auth_cookie(response, token: str):
    response.set_cookie(
        app.config["AUTH_COOKIE_NAME"], token,
        max_age=auth.SESSION_TTL_SECONDS,
        httponly=True,
        secure=app.config["AUTH_COOKIE_SECURE"],
        samesite="Lax",
        path="/",
    )
    return response


def _session_response(user: dict, token: str):
    response = make_response(jsonify({"ok": True, "user": user}))
    return _set_auth_cookie(response, token)


def _record_flagged_scan(username: str, result: dict, channel: str) -> None:
    """Store only flagged domains for accounts opted in to monthly summaries."""
    account = store.get_auth_account(username)
    if not account or not account["notify_monthly_summary"]:
        return
    scan_time = str(result.get("generated_at") or datetime.now(timezone.utc).isoformat())
    score = int(result.get("score") or 0)
    if channel == "url":
        if result.get("label") not in {"malicious", "suspicious"}:
            return
        domain = (result.get("facts") or {}).get("registrable_domain") or ""
        if domain:
            store.record_flagged_scan(
                account["user_id"], scan_time, "url", domain,
                str(result.get("label")), score,
            )
        return

    # For email scans, retain only domains of links that crossed the suspicious
    # threshold; never store the message, subject, sender, full URL, or attachment.
    for link in result.get("links") or []:
        if int(link.get("score") or 0) < 30:
            continue
        domain = link.get("registrable_domain") or ""
        if domain:
            store.record_flagged_scan(
                account["user_id"], scan_time, "email", domain,
                "malicious" if int(link.get("score") or 0) >= 65 else "suspicious",
                int(link.get("score") or 0),
            )


def _send_scan_push(username: str, result: dict, channel: str) -> None:
    """Best-effort browser push; email is reserved for monthly summaries."""
    account = store.get_auth_account(username)
    if not account or not account["notify_push_scan"]:
        return
    label = str(result.get("label") or "unknown").replace("_", " ")[:40]
    try:
        push.send_to_user(
            account["user_id"], "PhishGuard scan complete",
            f"{channel.title()} scan: {label}. Review the evidence in PhishGuard.", "/",
        )
    except Exception as exc:
        app.logger.info("Optional browser push was not delivered (%s)", type(exc).__name__)


@app.post("/api/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    try:
        user, token = auth.register_account(
            data.get("username", ""), data.get("password", ""),
            data.get("mobile", ""), data.get("email", ""),
            data.get("recovery_question", ""), data.get("recovery_answer", ""),
            request.remote_addr or "unknown", request.headers.get("User-Agent", ""),
            data.get("monthly_summary", False),
        )
        return _session_response(user, token)
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    try:
        user, token = auth.login_account(
            data.get("username", ""), data.get("password", ""),
            request.remote_addr or "unknown", request.headers.get("User-Agent", "")
        )
        return _session_response(user, token)
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/auth/forgot-password/question")
def forgot_password_question():
    data = request.get_json(silent=True) or {}
    try:
        question = auth.get_recovery_question(data.get("username", ""))
        return jsonify({"ok": True, "question": question})
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/auth/forgot-password/reset")
def forgot_password_reset():
    data = request.get_json(silent=True) or {}
    try:
        user, token = auth.reset_password(
            data.get("username", ""), data.get("recovery_answer", ""),
            data.get("new_password", ""), request.remote_addr or "unknown",
            request.headers.get("User-Agent", "")
        )
        return _session_response(user, token)
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/auth/forgot-password/email/request")
def forgot_password_email_request():
    data = request.get_json(silent=True) or {}
    if not mailer.configured():
        return jsonify({"error": "Email delivery is not configured on this deployment yet."}), 503
    try:
        username = auth.normalize_username(data.get("username", ""))
    except auth.AuthError:
        return jsonify({"ok": True, "message": "If this account has a verified Gmail address, a code has been sent."})
    account = store.get_auth_account(username)
    if account and account["email"] and account["email_verified_at"]:
        try:
            _, code = auth.issue_email_otp(account["email"], "password_reset", request.remote_addr or "unknown")
            mailer.send_email(
                account["email"], "PhishGuard password reset code",
                f"Your PhishGuard password-reset code is {code}. It expires in 10 minutes. "
                "If you did not request this, you can ignore this message.\n",
            )
        except auth.AuthError as exc:
            # Keep account existence and OTP throttle state out of the response.
            app.logger.info("Password-recovery code was not issued (status %s)", exc.status)
        except mailer.MailDeliveryError as exc:
            app.logger.info("Password-recovery email was not delivered (%s)", type(exc).__name__)
    return jsonify({"ok": True, "message": "If this account has a verified Gmail address, a code has been sent."})


@app.post("/api/auth/forgot-password/email/reset")
def forgot_password_email_reset():
    data = request.get_json(silent=True) or {}
    try:
        user, token = auth.reset_password_with_email_otp(
            data.get("username", ""), data.get("code", ""), data.get("new_password", ""),
            request.remote_addr or "unknown", request.headers.get("User-Agent", "")
        )
        return _session_response(user, token)
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/auth/email/request-verification")
def request_email_verification():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    account = store.get_auth_account(user["username"])
    if not account or not account["email"]:
        return jsonify({"error": "Add a Gmail address before verifying it."}), 400
    if account["email_verified_at"]:
        return jsonify({"ok": True, "message": "This Gmail address is already verified."})
    if not mailer.configured():
        return jsonify({"error": "Email delivery is not configured on this deployment yet."}), 503
    try:
        _, code = auth.issue_email_otp(account["email"], "verify_email", request.remote_addr or "unknown")
        mailer.send_email(
            account["email"], "Verify your PhishGuard email address",
            f"Your PhishGuard email verification code is {code}. It expires in 10 minutes.\n",
        )
        return jsonify({"ok": True, "message": "A verification code has been sent to your Gmail address."})
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status
    except mailer.MailDeliveryError as exc:
        return jsonify({"error": str(exc)}), 503


@app.post("/api/auth/email/verify")
def verify_email_address():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    data = request.get_json(silent=True) or {}
    try:
        updated_user = auth.verify_account_email(user["username"], data.get("code", ""))
        return jsonify({"ok": True, "user": updated_user})
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/auth/change-password")
def change_password():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    if not user:
        return jsonify({"error": "authentication required"}), 401
    data = request.get_json(silent=True) or {}
    try:
        updated_user, token = auth.change_password(
            user["username"], data.get("current_password", ""), data.get("new_password", ""),
            request.remote_addr or "unknown", request.headers.get("User-Agent", "")
        )
        return _session_response(updated_user, token)
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/auth/change-mobile")
def change_mobile():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    if not user:
        return jsonify({"error": "authentication required"}), 401
    data = request.get_json(silent=True) or {}
    try:
        updated_user = auth.change_mobile(
            user["username"], data.get("current_password", ""), data.get("mobile", "")
        )
        return jsonify({"ok": True, "user": updated_user})
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/auth/change-email")
def change_email():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    if not user:
        return jsonify({"error": "authentication required"}), 401
    data = request.get_json(silent=True) or {}
    try:
        updated_user = auth.change_gmail(
            user["username"], data.get("current_password", ""), data.get("email", "")
        )
        return jsonify({"ok": True, "user": updated_user})
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/auth/recovery-question")
def recovery_question():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    if not user:
        return jsonify({"error": "authentication required"}), 401
    data = request.get_json(silent=True) or {}
    try:
        updated_user = auth.update_recovery_question(
            user["username"], data.get("current_password", ""),
            data.get("recovery_question", ""), data.get("recovery_answer", "")
        )
        return jsonify({"ok": True, "user": updated_user})
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.get("/api/notifications/push/key")
def push_public_key():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    return jsonify({"configured": push.configured(), "public_key": push.public_key() if user and push.configured() else ""})


@app.post("/api/notifications/push/subscribe")
def push_subscribe():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    account = store.get_auth_account(user["username"])
    data = request.get_json(silent=True) or {}
    subscription = data.get("subscription") or {}
    endpoint = subscription.get("endpoint") if isinstance(subscription, dict) else ""
    keys = subscription.get("keys") if isinstance(subscription, dict) else {}
    if (not push.configured() or not isinstance(endpoint, str)
            or not push.valid_endpoint(endpoint) or not isinstance(keys, dict)
            or not all(isinstance(keys.get(k), str) and keys.get(k) for k in ("p256dh", "auth"))
            or len(keys.get("p256dh", "")) > 200 or len(keys.get("auth", "")) > 100):
        return jsonify({"error": "Invalid subscription or browser push is not configured."}), 400
    safe_subscription = {
        "endpoint": endpoint,
        "expirationTime": None,
        "keys": {"p256dh": keys["p256dh"], "auth": keys["auth"]},
    }
    store.save_push_subscription(
        endpoint, account["user_id"], json.dumps(safe_subscription), store.now()
    )
    return jsonify({"ok": True})


@app.post("/api/notifications/push/unsubscribe")
def push_unsubscribe():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    account = store.get_auth_account(user["username"])
    data = request.get_json(silent=True) or {}
    endpoint = data.get("endpoint", "")
    if not isinstance(endpoint, str) or not push.valid_endpoint(endpoint):
        return jsonify({"error": "Invalid subscription endpoint."}), 400
    store.delete_push_subscription(endpoint, account["user_id"])
    return jsonify({"ok": True})


@app.post("/api/account/profile")
def update_profile():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    if not user:
        return jsonify({"error": "authentication required"}), 401
    data = request.get_json(silent=True) or {}
    try:
        updated_user = auth.update_profile(
            user["username"], data.get("current_password", ""),
            data.get("display_name", ""), data.get("avatar_initials", "")
        )
        return jsonify({"ok": True, "user": updated_user})
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/account/preferences")
def update_preferences():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    if not user:
        return jsonify({"error": "authentication required"}), 401
    data = request.get_json(silent=True) or {}
    try:
        updated_user = auth.update_preferences(user["username"], data)
        return jsonify({"ok": True, "user": updated_user})
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.get("/api/account/login-history")
def account_login_history():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    if not user:
        return jsonify({"error": "authentication required"}), 401
    try:
        return jsonify({"login_history": auth.login_history(user["username"])})
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.get("/api/account/export")
def account_export():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    if not user:
        return jsonify({"error": "authentication required"}), 401
    try:
        response = make_response(jsonify(auth.export_data(user["username"])))
        response.headers["Content-Disposition"] = (
            f'attachment; filename="phishguard-{user["username"]}-data.json"'
        )
        response.headers["Cache-Control"] = "no-store"
        return response
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/account/delete")
def delete_account():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    if not user:
        return jsonify({"error": "authentication required"}), 401
    data = request.get_json(silent=True) or {}
    if data.get("confirmation") != "DELETE":
        return jsonify({"error": "Type DELETE to confirm account removal."}), 400
    try:
        auth.delete_account(user["username"], data.get("current_password", ""))
        response = make_response(jsonify({"ok": True}))
        response.delete_cookie(app.config["AUTH_COOKIE_NAME"], path="/")
        return response
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/account/clear-data")
def clear_account_data():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    if not user:
        return jsonify({"error": "authentication required"}), 401
    data = request.get_json(silent=True) or {}
    if data.get("confirmation") != "CLEAR":
        return jsonify({"error": "Type CLEAR to confirm personal data removal."}), 400
    try:
        auth.clear_data(user["username"], data.get("current_password", ""))
        return jsonify({"ok": True})
    except auth.AuthError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/auth/logout")
def logout():
    auth.revoke(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    response = make_response(jsonify({"ok": True}))
    response.delete_cookie(app.config["AUTH_COOKIE_NAME"], path="/")
    return response


@app.get("/api/stats")
def stats():
    return jsonify(store.stats())


@app.post("/api/assistant")
def help_assistant():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    try:
        if user:
            result = assistant.answer(
                data.get("question", ""), user["username"], request.remote_addr or "unknown"
            )
        else:
            # Pre-login questions are answered from the bundled FAQ only and are
            # not written to the account-help request history.
            result = assistant.answer_public(data.get("question", ""))
        return jsonify(result)
    except assistant.AssistantError as exc:
        return jsonify({"error": str(exc)}), exc.status


@app.post("/api/check/url")
def check_url():
    """?mode=quick  -> lexical only (milliseconds)
       ?mode=full   -> + registration/DNS/TLS/reputation/click-preview"""
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "no url provided"}), 400
    if len(url) > 4000:
        return jsonify({"error": "url too long"}), 400
    mode = (request.args.get("mode") or data.get("mode") or "full").lower()
    try:
        if mode == "quick":
            result = urlscan.analyze_quick(url)
        else:
            result = urlscan.analyze_full(
                url, do_preview=data.get("preview", True),
                include_reputation=bool(data.get("include_reputation", False)),
            )
        result["cluster_hint"] = (result.get("facts") or {}).get(
            "registrable_domain") or "unknown"
        scan_user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
        if scan_user:
            _record_flagged_scan(scan_user["username"], result, "url")
            if mode != "quick":
                _send_scan_push(scan_user["username"], result, "url")
        return jsonify(result)
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


@app.post("/api/check/email")
def check_email():
    raw = None
    if "file" in request.files:
        f = request.files["file"]
        raw = f.read()
    else:
        data = request.get_json(silent=True) or {}
        text = data.get("raw") or ""
        if text.strip():
            raw = text.encode("utf-8", "replace")
    if not raw:
        return jsonify({"error": "provide an .eml file or paste raw message source"}), 400
    if len(raw) > MAX_UPLOAD:
        return jsonify({"error": "message too large (12 MB max)"}), 413
    try:
        result = emailscan.scan_eml(raw)
        scan_user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
        if scan_user:
            _record_flagged_scan(scan_user["username"], result, "email")
            _send_scan_push(scan_user["username"], result, "email")
        return jsonify(result)
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": f"could not parse message: {type(exc).__name__}: {exc}"}), 400


@app.get("/api/cron/cluster-digest")
def cluster_digest_cron():
    """Send weekly campaign-cluster notices through opted-in browser push only."""
    secret = os.environ.get("CRON_SECRET", "").strip()
    if not secret:
        return jsonify({"error": "CRON_SECRET is not configured."}), 503
    if not hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {secret}"):
        return jsonify({"error": "unauthorized"}), 401
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=7)).isoformat(timespec="seconds")
    cluster_count = store.count_report_clusters_since(since)
    if not cluster_count:
        return jsonify({"ok": True, "push_sent": 0, "new_clusters": 0})
    iso_year, iso_week, _ = now.isocalendar()
    event_key = f"cluster-push-digest:{iso_year}-W{iso_week:02d}"
    push_sent = 0
    for subscribed in store.list_push_user_ids():
        user_id = subscribed["user_id"]
        if store.has_notification_delivery(user_id, event_key):
            continue
        if store.count_notification_deliveries_since(since) >= 100:
            break
        try:
            delivered = push.send_to_user(
                user_id, "PhishGuard campaign digest",
                f"{cluster_count} campaign cluster(s) were reported this week. Review in PhishGuard.", "/",
            )
            if delivered and store.create_notification_delivery(
                user_id, event_key, now.isoformat(timespec="seconds")
            ):
                push_sent += delivered
        except Exception as exc:
            app.logger.info("Optional push digest was not delivered (%s)", type(exc).__name__)
    return jsonify({"ok": True, "push_sent": push_sent,
                    "new_clusters": cluster_count})


@app.get("/api/cron/monthly-scan-summary")
def monthly_scan_summary_cron():
    """Email opted-in users a domain-only summary of flagged scans from last month."""
    secret = os.environ.get("CRON_SECRET", "").strip()
    if not secret:
        return jsonify({"error": "CRON_SECRET is not configured."}), 503
    if not hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {secret}"):
        return jsonify({"error": "unauthorized"}), 401
    if not mailer.configured():
        return jsonify({"ok": True, "sent": 0, "skipped": "Mailjet is not configured."})

    now = datetime.now(timezone.utc)
    current_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    previous_month = current_month - timedelta(days=1)
    month_key = previous_month.strftime("%Y-%m")
    month_label = previous_month.strftime("%B %Y")
    event_key = f"monthly-flagged-scans:{month_key}"
    daily_since = (now - timedelta(days=1)).isoformat(timespec="seconds")
    sent = 0
    skipped_empty = 0
    recipients = store.list_email_notification_accounts()
    for recipient in recipients:
        if store.has_notification_delivery(recipient["user_id"], event_key):
            continue
        rows = store.list_monthly_flagged_scans(recipient["user_id"], month_key)
        if not rows:
            skipped_empty += 1
            continue
        if store.count_notification_deliveries_since(daily_since) >= 100:
            break
        lines = [
            f"PhishGuard flagged-site summary for {month_label}",
            "",
            "These are domains from your own scans that PhishGuard marked suspicious or malicious:",
            "",
        ]
        for row in rows:
            checked = str(row["last_scanned_at"] or "")[:10]
            lines.append(
                f"{row['domain']} — {row['verdict']} (score {row['score']}/100; "
                f"{row['scan_type']} scan; {row['scan_count']} check(s); last seen {checked})"
            )
        lines.extend([
            "",
            "This message contains domains only—not full URLs, message contents, or attachments.",
            "A flag is a warning signal, not proof; no match is not proof of safety.",
            "You can turn off monthly summaries in PhishGuard Settings → Notifications.",
        ])
        try:
            mailer.send_email(
                recipient["email"], f"Your PhishGuard flagged-site summary — {month_label}",
                "\n".join(lines),
            )
            if store.create_notification_delivery(
                recipient["user_id"], event_key, now.isoformat(timespec="seconds")
            ):
                sent += 1
        except Exception as exc:
            app.logger.info("Monthly flagged-site email was not delivered (%s)", type(exc).__name__)
    return jsonify({"ok": True, "sent": sent, "skipped_empty": skipped_empty,
                    "month": month_key})


@app.post("/api/report")
def report():
    """Report-to-sweep: one report protects everyone who got the same mail."""
    data = request.get_json(silent=True) or {}
    cluster = (data.get("cluster_key") or "").strip() or "unknown"
    out = store.add_report(
        cluster_key=cluster,
        subject=(data.get("subject") or "")[:300],
        sender=(data.get("sender") or "")[:200],
        links=data.get("links") or [],
        reporter=(data.get("reporter") or "anonymous")[:60],
        clicked=bool(data.get("clicked")),
        verdict=(data.get("verdict") or "unknown")[:40],
        score=int(data.get("score") or 0),
    )
    return jsonify(out)


SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")


@app.get("/api/sample/<name>")
def sample(name):
    """Built-in demo messages so the app can be evaluated in one click."""
    if not name.isalnum() and "_" not in name:
        return jsonify({"error": "bad name"}), 400
    path = os.path.join(SAMPLE_DIR, f"{name}.eml")
    if not os.path.isfile(path):
        return jsonify({"error": "sample not found"}), 404
    with open(path, "rb") as fh:
        data = fh.read()
    return app.response_class(data, mimetype="text/plain")


@app.post("/api/vendor/confirm")
def vendor_confirm():
    """Only a human, after an out-of-band check, may move a vendor's bank baseline."""
    data = request.get_json(silent=True) or {}
    out = store.confirm_vendor_account((data.get("vendor_key") or "").strip(),
                                       (data.get("by") or "analyst")[:60])
    return jsonify(out), (200 if out.get("ok") else 400)


@app.get("/api/clusters")
def clusters():
    return jsonify({"clusters": store.all_clusters()})


@app.get("/api/receipt/<rid>")
def receipt(rid):
    payload = store.get_receipt(rid)
    if not payload:
        return jsonify({"error": "receipt not found"}), 404
    return app.response_class(json.dumps(payload, indent=2), mimetype="application/json")


@app.get("/api/money-deterred")
def money_deterred():
    """The metric a CFO signs a renewal on: prevented loss, not detections."""
    s = store.stats()
    clusters = store.all_clusters()
    prevented = sum(1 for c in clusters if c["verdict"] == "malicious")
    return jsonify({
        "reports_handled": s["reports"],
        "clusters_neutralised": prevented,
        "people_protected": sum(max(c["reports"] - 1, 0) for c in clusters),
        "est_value_protected_inr": prevented * 185000,
        "method": "est. ₹1.85L average BEC loss per prevented cluster (industry median)",
        "note": "Deliberately conservative: counts only clusters confirmed malicious.",
    })


@app.after_request
def headers(resp):
    started = getattr(g, "phishguard_request_started", None)
    if started is not None:
        elapsed_ms = max(0.0, (time.perf_counter() - started) * 1000)
        resp.headers["Server-Timing"] = f"app;dur={elapsed_ms:.1f}"
        if request.path in {"/", "/login", "/ui-trial"} or request.path.startswith("/api/"):
            # Record endpoint-level timing without logging URLs, query values, or user data.
            app.logger.info(
                "request endpoint=%s method=%s status=%d app_ms=%.1f",
                request.endpoint or "unmatched", request.method, resp.status_code, elapsed_ms,
            )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; font-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    if app.config["AUTH_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
