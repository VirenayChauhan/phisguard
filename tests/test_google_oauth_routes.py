from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as phishguard_app  # noqa: E402
from engine import store  # noqa: E402


class GoogleOAuthRouteTests(unittest.TestCase):
    def setUp(self):
        self.old_path, self.old_url = store.DB_PATH, store.DATABASE_URL
        self.old_config = {
            key: phishguard_app.app.config.get(key)
            for key in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI")
        }
        self.temp = tempfile.TemporaryDirectory(prefix="phisguard-google-routes-")
        store.DB_PATH = os.path.join(self.temp.name, "isolated.sqlite3")
        store.DATABASE_URL = ""
        store.init()
        self.client = phishguard_app.app.test_client()

    def tearDown(self):
        store.DB_PATH, store.DATABASE_URL = self.old_path, self.old_url
        phishguard_app.app.config.update(self.old_config)
        self.temp.cleanup()

    def test_google_start_redirects_to_login_when_not_configured(self):
        phishguard_app.app.config.update({
            "GOOGLE_CLIENT_ID": "",
            "GOOGLE_CLIENT_SECRET": "",
            "GOOGLE_REDIRECT_URI": "",
        })
        with patch.dict(os.environ, {"FLASK_SECRET_KEY": ""}):
            response = self.client.get("/auth/google/start")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login?google_error=setup")

    def test_callback_rejects_missing_oauth_nonce(self):
        phishguard_app.app.config.update({
            "GOOGLE_CLIENT_ID": "client-id",
            "GOOGLE_CLIENT_SECRET": "client-secret",
            "GOOGLE_REDIRECT_URI": "https://example.test/auth/google/callback",
        })
        with patch.dict(os.environ, {"FLASK_SECRET_KEY": "a-stable-test-secret"}):
            response = self.client.get("/auth/google/callback")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login?google_error=state")

    def test_callback_creates_account_and_sets_phishguard_session(self):
        phishguard_app.app.config.update({
            "GOOGLE_CLIENT_ID": "client-id",
            "GOOGLE_CLIENT_SECRET": "client-secret",
            "GOOGLE_REDIRECT_URI": "https://example.test/auth/google/callback",
        })
        token = {"userinfo": {
            "sub": "google-route-subject", "email": "route@example.org",
            "email_verified": True, "name": "Route Tester",
        }}
        with self.client.session_transaction() as browser_session:
            browser_session["google_oauth_nonce"] = "expected-test-nonce"
        with patch.dict(os.environ, {"FLASK_SECRET_KEY": "a-stable-test-secret"}), \
             patch.object(phishguard_app._google, "authorize_access_token", return_value=token):
            response = self.client.get("/auth/google/callback?state=mocked")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        session_response = self.client.get("/api/auth/session")
        self.assertTrue(session_response.get_json()["authenticated"])
        self.assertEqual(session_response.get_json()["user"]["email"], "route@example.org")


if __name__ == "__main__":
    unittest.main()
