from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import intel  # noqa: E402


class ReputationProviderTests(unittest.TestCase):
    def setUp(self):
        with intel._CACHE_LOCK:
            intel._CACHE.clear()

    def test_safe_browsing_v5_decodes_json_match_and_cache_duration(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "threats": [{"url": "https://bad.example/", "threatTypes": ["SOCIAL_ENGINEERING"]}],
            "cacheDuration": "600s",
        }
        with patch.object(intel, "GSB_KEY", "test-key"), \
             patch.object(intel.requests, "get", return_value=response) as get:
            result = intel.safe_browsing("https://bad.example/")
        self.assertTrue(result["ok"])
        self.assertTrue(result["hit"])
        self.assertEqual(result["threats"], ["SOCIAL_ENGINEERING"])
        self.assertEqual(result["cache_seconds"], 600)
        self.assertEqual(get.call_args.kwargs["params"]["urls"], "https://bad.example/")
        get.assert_called_once()

    def test_safe_browsing_empty_result_is_not_a_hit(self):
        threats, cache_seconds = intel._decode_safe_browsing_v5({
            "threats": [], "cacheDuration": "3600s"
        })
        self.assertEqual(threats, [])
        self.assertEqual(cache_seconds, 3600)

    def test_virustotal_404_is_unknown_not_safe(self):
        response = Mock(status_code=404)
        with patch.object(intel, "VT_KEY", "test-key"), \
             patch.object(intel.requests, "get", return_value=response):
            result = intel.virustotal_url("https://not-indexed.example/")
        self.assertTrue(result["ok"])
        self.assertFalse(result["hit"])
        self.assertTrue(result["never_seen"])
        self.assertIn("not a safety verdict", result["note"])

    def test_urlhaus_known_url_becomes_evidence(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "query_status": "ok", "threat": "malware_download", "url_status": "online"
        }
        with patch.object(intel, "URLHAUS_KEY", "test-key"), \
             patch.object(intel.requests, "post", return_value=response) as post:
            result = intel.urlhaus_url("https://bad.example/dropper")
        self.assertTrue(result["ok"])
        self.assertTrue(result["hit"])
        self.assertIn("malware_download", result["note"])
        self.assertEqual(post.call_args.kwargs["headers"]["Auth-Key"], "test-key")

    def test_urlhaus_rejected_auth_key_has_actionable_safe_diagnostic(self):
        response = Mock(status_code=401)
        response.json.return_value = {"query_status": "auth_error"}
        with patch.object(intel, "URLHAUS_KEY", "test-secret"), \
             patch.object(intel.requests, "post", return_value=response):
            result = intel.urlhaus_url("https://example.com/")
        self.assertFalse(result["ok"])
        self.assertFalse(result["hit"])
        self.assertIn("HTTP 401", result["note"])
        self.assertIn("Preview URLHAUS_AUTH_KEY", result["note"])
        self.assertNotIn("test-secret", result["note"])

    def test_urlhaus_rate_limit_is_reported_without_treating_as_no_match(self):
        response = Mock(status_code=429)
        response.json.return_value = {}
        with patch.object(intel, "URLHAUS_KEY", "test-secret"), \
             patch.object(intel.requests, "post", return_value=response):
            result = intel.urlhaus_url("https://example.com/")
        self.assertFalse(result["ok"])
        self.assertFalse(result["hit"])
        self.assertIn("rate limit", result["note"])
        self.assertIn("HTTP 429", result["note"])

    def test_phishtank_requires_verified_match(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"results": {
            "in_database": True, "verified": True, "valid": True
        }}
        with patch.object(intel, "PHISHTANK_KEY", "test-key"), \
             patch.object(intel.requests, "post", return_value=response) as post:
            result = intel.phishtank_url("https://phish.example/login")
        self.assertTrue(result["hit"])
        self.assertEqual(post.call_args.kwargs["data"]["app_key"], "test-key")

    def test_missing_provider_key_does_not_call_out(self):
        with patch.object(intel, "URLHAUS_KEY", ""), \
             patch.object(intel.requests, "post") as post:
            result = intel.urlhaus_url("https://example.com/")
        self.assertFalse(result["configured"])
        self.assertFalse(result["ok"])
        post.assert_not_called()

    def test_phishtank_error_is_not_a_no_match(self):
        with patch.object(intel, "PHISHTANK_KEY", "test-key"), \
             patch.object(intel.requests, "post", side_effect=TimeoutError):
            result = intel.phishtank_url("https://example.com/")
        self.assertFalse(result["ok"])
        self.assertFalse(result["hit"])
        self.assertIn("unavailable", result["note"])


if __name__ == "__main__":
    unittest.main()
