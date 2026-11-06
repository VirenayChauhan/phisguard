"""Optional Vercel function entry point; root Flask framework uses app.py."""
from __future__ import annotations

import os

from engine.database_config import database_url_from_env

if os.getenv("VERCEL") and not database_url_from_env(os.environ):
    from flask import Flask, jsonify

    app = Flask(__name__)

    @app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    @app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def database_setup_required(path: str):
        return jsonify({
            "error": "PhishGuard needs a persistent Postgres database before it can serve traffic.",
            "setup": "Configure the persistent Postgres URL for this Vercel environment; Preview requires PHISGUARD_PREVIEW_DATABASE_URL.",
        }), 503
else:
    os.environ.setdefault("AUTH_COOKIE_SECURE", "1" if os.getenv("VERCEL") else "0")
    from app import app
