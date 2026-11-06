from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import store, urlscan  # noqa: E402


class UrlReputationConsentTests(unittest.TestCase):
    def setUp(self):
        store.init()

    def _network_mocks(self):
        return (
            patch.object(urlscan.net, "dns_facts", return_value={"resolves": False}),
            patch.object(urlscan.net, "rdap_facts", return_value={"ok": False}),
            patch.object(urlscan.net, "tls_facts", return_value={"ok": False}),
        )

    def test_provider_calls_are_skipped_by_default(self):
        with self._network_mocks()[0] as dns, self._network_mocks()[1], self._network_mocks()[2], \
             patch.object(urlscan.intel, "safe_browsing") as gsb, \
             patch.object(urlscan.intel, "virustotal_url") as vt, \
             patch.object(urlscan.intel, "urlhaus_url") as urlhaus, \
             patch.object(urlscan.intel, "phishtank_url") as phishtank:
            result = urlscan.analyze_full("https://example.org/", do_preview=False)
        for provider in (gsb, vt, urlhaus, phishtank):
            provider.assert_not_called()
        self.assertFalse(result["intel_ok"])
        self.assertTrue(any("skipped for this scan" in note for note in result["intel_notes"]))

    def test_negative_provider_results_do_not_upgrade_intel_status(self):
        no_match = {"ok": True, "configured": True, "hit": False,
                    "note": "no provider match", "cache_seconds": 30}
        with self._network_mocks()[0], self._network_mocks()[1], self._network_mocks()[2], \
             patch.object(urlscan.intel, "safe_browsing", return_value=no_match), \
             patch.object(urlscan.intel, "virustotal_url", return_value=no_match), \
             patch.object(urlscan.intel, "urlhaus_url", return_value=no_match), \
             patch.object(urlscan.intel, "phishtank_url", return_value=no_match):
            result = urlscan.analyze_full(
                "https://example.org/", do_preview=False, include_reputation=True
            )
        self.assertFalse(result["intel_ok"])
        self.assertTrue(any("no provider match" in note for note in result["intel_notes"]))
        self.assertNotEqual(result["label"], "safe")


if __name__ == "__main__":
    unittest.main()
