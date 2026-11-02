"""PhishGuard — a phishing link & email checker with receipts.

Run:  python3 app.py     (binds 0.0.0.0:8000)
"""
from __future__ import annotations

import json
import os
import traceback

from flask import Flask, jsonify, make_response, render_template, request

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # requirements.txt installs this; keep imports resilient for tests
    pass

from engine import assistant, auth, emailscan, store, urlscan

MAX_UPLOAD = 12 * 1024 * 1024  # 12 MB .eml ceiling

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
app.config["AUTH_COOKIE_SECURE"] = os.environ.get("AUTH_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"}
app.config["AUTH_COOKIE_NAME"] = "__Host-pg_session" if app.config["AUTH_COOKIE_SECURE"] else "pg_session"
# Templates/CSS are edited during pilots; never serve a stale cached page.
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
store.init()


PUBLIC_API_PATHS = {
    "/api/health",
    "/api/auth/session",
    "/api/auth/register",
    "/api/auth/login",
    "/api/auth/forgot-password/question",
    "/api/auth/forgot-password/reset",
    "/api/auth/logout",
}


@app.before_request
def require_authentication():
    """Keep the dashboard and every analysis API behind the verified session."""
    if not request.path.startswith("/api/") or request.path in PUBLIC_API_PATHS:
        return None
    if auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"])):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.headers.get("X-Requested-With") != "XMLHttpRequest":
            return jsonify({"error": "missing request protection header"}), 403
        return None
    return jsonify({"error": "authentication required"}), 401


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/login")
def login_page():
    """Serve the sign-in view as a distinct route from the public landing page."""
    return render_template("index.html", login_page=True)


@app.get("/ui-trial")
def ui_trial():
    """Render the isolated editorial split-screen sign-in trial."""
    return render_template("index.html", ui_trial=True)


@app.get("/api/health")
def health():
    from engine import intel
    return jsonify({"ok": True, "intel": intel.configured(), "stats": store.stats()})


@app.get("/api/auth/session")
def auth_session():
    user = auth.current_user(request.cookies.get(app.config["AUTH_COOKIE_NAME"]))
    return jsonify({"authenticated": bool(user), "user": user})


def _session_response(user: dict, token: str):
    response = make_response(jsonify({"ok": True, "user": user}))
    response.set_cookie(
        app.config["AUTH_COOKIE_NAME"], token,
        max_age=auth.SESSION_TTL_SECONDS,
        httponly=True,
        secure=app.config["AUTH_COOKIE_SECURE"],
        samesite="Lax",
        path="/",
    )
    return response


@app.post("/api/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    try:
        user, token = auth.register_account(
            data.get("username", ""), data.get("password", ""),
            data.get("mobile", ""), data.get("email", ""),
            data.get("recovery_question", ""), data.get("recovery_answer", ""),
            request.remote_addr or "unknown", request.headers.get("User-Agent", "")
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
    if not user:
        return jsonify({"error": "authentication required"}), 401
    data = request.get_json(silent=True) or {}
    try:
        result = assistant.answer(
            data.get("question", ""), user["username"], request.remote_addr or "unknown"
        )
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
            result = urlscan.analyze_full(url, do_preview=data.get("preview", True))
        result["cluster_hint"] = (result.get("facts") or {}).get(
            "registrable_domain") or "unknown"
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
        return jsonify(emailscan.scan_eml(raw))
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": f"could not parse message: {type(exc).__name__}: {exc}"}), 400


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
