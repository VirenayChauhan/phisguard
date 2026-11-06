from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import store  # noqa: E402
import app as phishguard_app  # noqa: E402


class PublicCheckCountTests(unittest.TestCase):
    def setUp(self):
        self.old_path, self.old_url = store.DB_PATH, store.DATABASE_URL
        self.temp = tempfile.TemporaryDirectory(prefix="phisguard-public-count-")
        store.DB_PATH = os.path.join(self.temp.name, "isolated.sqlite3")
        store.DATABASE_URL = ""
        store.init()

    def tearDown(self):
        store.DB_PATH, store.DATABASE_URL = self.old_path, self.old_url
        self.temp.cleanup()

    def test_public_endpoint_exposes_only_aggregate_completed_check_count(self):
        client = phishguard_app.app.test_client()

        empty = client.get("/api/public-check-count")
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.get_json(), {"checks_completed": 0})

        store.save_receipt("example.test", {"private": "not returned by the count endpoint"})
        updated = client.get("/api/public-check-count")
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json(), {"checks_completed": 1})


if __name__ == "__main__":
    unittest.main()
