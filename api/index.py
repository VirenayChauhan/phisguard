"""Vercel serverless entry point for the Flask application."""
from __future__ import annotations

import os

# Never silently use a serverless instance's disposable filesystem for accounts.
# The page remains reachable while setup is pending, but data APIs explain the
# missing persistent store instead of creating a misleading ephemeral database.
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
