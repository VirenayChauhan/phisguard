from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as phishguard_app  # noqa: E402
from engine import store  # noqa: E402


class MicrosoftOAuthRouteTests(unittest.TestCase):
    def setUp(self):
        self.old_path, self.old_url = store.DB_PATH, store.DATABASE_URL
        self.old_config = {
            key: phishguard_app.app.config.get(key)
            for key in (
                "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET",
                "MICROSOFT_REDIRECT_URI", "MICROSOFT_TENANT_ID",
            )
        }
        self.temp = tempfile.TemporaryDirectory(prefix="phisguard-microsoft-routes-")
        store.DB_PATH = os.path.join(self.temp.name, "isolated.sqlite3")
        store.DATABASE_URL = ""
        store.init()
        self.client = phishguard_app.app.test_client()

    def tearDown(self):
        store.DB_PATH, store.DATABASE_URL = self.old_path, self.old_url
        phishguard_app.app.config.update(self.old_config)
        self.temp.cleanup()

    def _configure_microsoft(self):
        phishguard_app.app.config.update({
            "MICROSOFT_CLIENT_ID": "client-id",
            "MICROSOFT_CLIENT_SECRET": "client-secret",
            "MICROSOFT_REDIRECT_URI": "https://example.test/auth/microsoft/callback",
            "MICROSOFT_TENANT_ID": "common",
        })

    def test_microsoft_start_redirects_to_login_when_not_configured(self):
        phishguard_app.app.config.update({
            "MICROSOFT_CLIENT_ID": "",
            "MICROSOFT_CLIENT_SECRET": "",
            "MICROSOFT_REDIRECT_URI": "",
        })
        with patch.dict(os.environ, {"FLASK_SECRET_KEY": ""}):
            response = self.client.get("/auth/microsoft/start")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login?microsoft_error=setup")

    def test_callback_rejects_missing_oauth_nonce(self):
        self._configure_microsoft()
        with patch.dict(os.environ, {"FLASK_SECRET_KEY": "a-stable-test-secret"}):
            response = self.client.get("/auth/microsoft/callback")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login?microsoft_error=state")

    def test_callback_creates_account_without_trusting_unverified_email(self):
        self._configure_microsoft()
        tenant_id = "12345678-1234-1234-1234-123456789abc"
        token = {"userinfo": {
            "sub": "microsoft-route-subject",
            "email": "route@example.org",
            "name": "Route Tester",
            "tid": tenant_id,
            "iss": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        }}
        with self.client.session_transaction() as browser_session:
            browser_session["microsoft_oauth_nonce"] = "expected-test-nonce"
        with patch.dict(os.environ, {"FLASK_SECRET_KEY": "a-stable-test-secret"}), \
             patch.object(phishguard_app._microsoft, "authorize_access_token", return_value=token):
            response = self.client.get("/auth/microsoft/callback?state=mocked")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        session_response = self.client.get("/api/auth/session")
        self.assertTrue(session_response.get_json()["authenticated"])
        self.assertEqual(session_response.get_json()["user"]["email"], "")
        self.assertFalse(session_response.get_json()["user"]["email_verified"])

    def test_callback_accepts_missing_email_claim(self):
        self._configure_microsoft()
        tenant_id = "12345678-1234-1234-1234-123456789abc"
        token = {"userinfo": {
            "sub": "microsoft-no-email", "name": "No Email", "tid": tenant_id,
            "iss": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        }}
        with self.client.session_transaction() as browser_session:
            browser_session["microsoft_oauth_nonce"] = "expected-test-nonce"
        with patch.dict(os.environ, {"FLASK_SECRET_KEY": "a-stable-test-secret"}), \
             patch.object(phishguard_app._microsoft, "authorize_access_token", return_value=token):
            response = self.client.get("/auth/microsoft/callback?state=mocked")

        self.assertEqual(response.headers["Location"], "/")
        user = self.client.get("/api/auth/session").get_json()["user"]
        self.assertEqual(user["email"], "")
        self.assertFalse(user["email_verified"])

    def test_callback_keeps_explicitly_verified_email(self):
        self._configure_microsoft()
        tenant_id = "12345678-1234-1234-1234-123456789abc"
        token = {"userinfo": {
            "sub": "microsoft-verified-email", "email": "verified@example.org",
            "email_verified": True, "name": "Verified User", "tid": tenant_id,
            "iss": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        }}
        with self.client.session_transaction() as browser_session:
            browser_session["microsoft_oauth_nonce"] = "expected-test-nonce"
        with patch.dict(os.environ, {"FLASK_SECRET_KEY": "a-stable-test-secret"}), \
             patch.object(phishguard_app._microsoft, "authorize_access_token", return_value=token):
            response = self.client.get("/auth/microsoft/callback?state=mocked")

        self.assertEqual(response.headers["Location"], "/")
        user = self.client.get("/api/auth/session").get_json()["user"]
        self.assertEqual(user["email"], "verified@example.org")
        self.assertTrue(user["email_verified"])

    def test_callback_rejects_tenant_issuer_mismatch(self):
        self._configure_microsoft()
        tenant_id = "12345678-1234-1234-1234-123456789abc"
        token = {"userinfo": {
            "sub": "microsoft-bad-issuer", "name": "Bad Issuer", "tid": tenant_id,
            "iss": "https://login.microsoftonline.com/attacker/v2.0",
        }}
        with self.client.session_transaction() as browser_session:
            browser_session["microsoft_oauth_nonce"] = "expected-test-nonce"
        with patch.dict(os.environ, {"FLASK_SECRET_KEY": "a-stable-test-secret"}), \
             patch.object(phishguard_app._microsoft, "authorize_access_token", return_value=token):
            response = self.client.get("/auth/microsoft/callback?state=mocked")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login?microsoft_error=account")
        self.assertFalse(self.client.get("/api/auth/session").get_json()["authenticated"])


if __name__ == "__main__":
    unittest.main()
