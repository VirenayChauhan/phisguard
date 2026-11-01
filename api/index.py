"""Optional Vercel function entry point; root Flask framework uses app.py."""
from __future__ import annotations

import os

if os.getenv("VERCEL") and not any(os.getenv(name) for name in (
    "DATABASE_URL", "DATABASE_POSTGRES_PRISMA_URL", "DATABASE_URL_UNPOOLED"
)):
    from flask import Flask, jsonify

    app = Flask(__name__)

    @app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    @app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def database_setup_required(path: str):
        return jsonify({
            "error": "PhishGuard needs a persistent Postgres database before it can serve traffic.",
            "setup": "Connect a Postgres provider to this Vercel project and set DATABASE_URL.",
        }), 503
else:
    os.environ.setdefault("AUTH_COOKIE_SECURE", "1" if os.getenv("VERCEL") else "0")
    from app import app
