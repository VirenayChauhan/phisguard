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


class _VercelOriginalPath:
    """Restore the external path after Vercel rewrites requests to this function."""
    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        from urllib.parse import parse_qsl, urlencode

        params = parse_qsl(environ.get("QUERY_STRING", ""), keep_blank_values=True)
        import json
        body = json.dumps({"path_info": environ.get("PATH_INFO"), "query": environ.get("QUERY_STRING"),
                           "headers": {k: v for k, v in environ.items() if k.startswith("HTTP_X_")}}).encode()
        start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]
        path = None
        remaining = []
        for key, value in params:
            if key == "__pg_original_path":
                path = value
            else:
                remaining.append((key, value))
        if path and path.startswith("/") and "\\\\" not in path and ".." not in path.split("/"):
            environ["PATH_INFO"] = path
            environ["QUERY_STRING"] = urlencode(remaining, doseq=True)
        return self.application(environ, start_response)


app.wsgi_app = _VercelOriginalPath(app.wsgi_app)
