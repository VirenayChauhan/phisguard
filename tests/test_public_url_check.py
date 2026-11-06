from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as phishguard_app  # noqa: E402
from engine import urlscan  # noqa: E402


class PublicUrlCheckTests(unittest.TestCase):
    def setUp(self):
        self.client = phishguard_app.app.test_client()

    def test_public_endpoint_returns_structural_verdict_without_login_or_persistence(self):
        with patch.object(urlscan.store, "observe_domain", side_effect=AssertionError("must not persist")), \
             patch.object(urlscan.store, "save_receipt", side_effect=AssertionError("must not persist")), \
             patch.object(urlscan.store, "check_url_snapshot", side_effect=AssertionError("must not persist")):
            response = self.client.post(
                "/api/public/url-check",
                json={"url": "https://paypal.com.secure-login-verify.top/account"},
            )

        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result["speed"], "public_quick")
        self.assertTrue(result["signals"])
        self.assertEqual(result["facts"]["registrable_domain"], "secure-login-verify.top")
        self.assertFalse(result["intel_ok"])
        self.assertIsNone(result["receipt_id"])

    def test_homepage_exposes_the_no_account_link_form(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"public-url-check-form", response.data)
        self.assertIn(b"FREE QUICK SCREEN", response.data)
        response.close()

    def test_empty_and_oversized_urls_are_rejected(self):
        empty = self.client.post("/api/public/url-check", json={"url": "  "})
        too_long = self.client.post("/api/public/url-check", json={"url": "x" * 4001})
        self.assertEqual(empty.status_code, 400)
        self.assertEqual(too_long.status_code, 400)

    def test_public_screen_does_not_touch_network_or_store(self):
        with patch.object(urlscan.net, "dns_facts", side_effect=AssertionError("network disabled")), \
             patch.object(urlscan.store, "observe_domain", side_effect=AssertionError("storage disabled")):
            result = urlscan.analyze_public_quick("example.com/login")
        self.assertEqual(result["speed"], "public_quick")
        self.assertIn("public quick screen", result["intel_notes"][0])


if __name__ == "__main__":
    unittest.main()
