from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import store  # noqa: E402
import app as phishguard_app  # noqa: E402


class RequestTimingTests(unittest.TestCase):
    def test_landing_has_server_timing_without_opening_database(self):
        client = phishguard_app.app.test_client()
        with patch.object(store, "init", side_effect=AssertionError("landing must not initialize DB")):
            response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertRegex(response.headers.get("Server-Timing", ""), r"^app;dur=\d+(\.\d+)?$")

    def test_public_api_response_includes_server_timing(self):
        old_path, old_url = store.DB_PATH, store.DATABASE_URL
        try:
            with tempfile.TemporaryDirectory(prefix="phisguard-request-timing-") as temp:
                store.DB_PATH = os.path.join(temp, "isolated.sqlite3")
                store.DATABASE_URL = ""
                store.init()
                response = phishguard_app.app.test_client().get("/api/public-check-count")
                self.assertEqual(response.status_code, 200)
                self.assertRegex(response.headers.get("Server-Timing", ""), r"^app;dur=\d+(\.\d+)?$")
        finally:
            store.DB_PATH, store.DATABASE_URL = old_path, old_url


if __name__ == "__main__":
    unittest.main()
