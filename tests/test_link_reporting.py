from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as phishguard_app  # noqa: E402
from engine import store  # noqa: E402


class LinkReportingTests(unittest.TestCase):
    def setUp(self):
        self.old_path, self.old_url = store.DB_PATH, store.DATABASE_URL
        self.temp = tempfile.TemporaryDirectory(prefix="phisguard-link-report-")
        store.DB_PATH = os.path.join(self.temp.name, "isolated.sqlite3")
        store.DATABASE_URL = ""
        store.init()
        self.client = phishguard_app.app.test_client()
        response = self.client.post(
            "/api/auth/register",
            json={
                "username": "link_reporter",
                "password": "StrongPass123",
                "mobile": "9876543210",
                "email": "",
                "recovery_question": "What is your favorite game?",
                "recovery_answer": "chess",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(response.status_code, 200, response.get_json())

    def tearDown(self):
        store.DB_PATH, store.DATABASE_URL = self.old_path, self.old_url
        self.temp.cleanup()

    def test_link_report_clusters_query_variants_without_storing_raw_url(self):
        first = self.client.post(
            "/api/report/url",
            json={
                "url": "https://Login.Example.invalid/account/verify?token=do-not-store#section",
                "clicked": True,
                "verdict": "malicious",
                "score": 91,
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(first.status_code, 200, first.get_json())
        first_json = first.get_json()
        self.assertTrue(first_json["cluster_key"].startswith("link:"))
        self.assertEqual(first_json["cluster"]["reports"], 1)
        self.assertEqual(first_json["cluster"]["clicked"], 1)

        second = self.client.post(
            "/api/report/url",
            json={
                "url": "https://login.example.invalid/account/verify?campaign=other",
                "clicked": False,
                "verdict": "suspicious",
                "score": 45,
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(second.status_code, 200, second.get_json())
        self.assertEqual(second.get_json()["cluster_key"], first_json["cluster_key"])
        self.assertEqual(second.get_json()["cluster"]["reports"], 2)
        self.assertEqual(second.get_json()["cluster"]["clicked"], 1)

        clusters = store.all_clusters()
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["sender"], "login.example.invalid")
        with store._LOCK, store._conn() as conn:
            row = conn.execute("SELECT * FROM reports LIMIT 1").fetchone()
        self.assertEqual(row["links"], "[]")
        self.assertNotIn("account/verify", str(dict(row)))
        self.assertNotIn("do-not-store", str(dict(row)))

    def test_link_report_rejects_non_web_schemes(self):
        response = self.client.post(
            "/api/report/url",
            json={"url": "javascript:alert(1)"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(store.stats()["reports"], 0)

    def test_link_report_requires_an_authenticated_workspace(self):
        client = phishguard_app.app.test_client()
        response = client.post(
            "/api/report/url",
            json={"url": "https://example.invalid/"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
