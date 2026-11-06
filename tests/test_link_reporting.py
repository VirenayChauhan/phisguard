from __future__ import annotations

import hashlib
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

    def test_link_report_can_only_be_undone_with_its_private_token(self):
        created = self.client.post(
            "/api/report/url",
            json={"url": "https://example.invalid/login"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        ).get_json()
        token = created["undo_token"]
        self.assertNotEqual(token, "")
        with store._LOCK, store._conn() as conn:
            row = conn.execute("SELECT * FROM reports WHERE id=?", (created["id"],)).fetchone()
        self.assertEqual(row["undo_token_hash"], hashlib.sha256(token.encode()).hexdigest())
        self.assertNotEqual(row["undo_token_hash"], token)

        wrong_owner = self.client.post(
            f"/api/report/{created['id']}/undo", json={"undo_token": "not-the-secret"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(wrong_owner.status_code, 404)
        self.assertEqual(store.cluster_stats(created["cluster_key"])["reports"], 1)

        undone = self.client.post(
            f"/api/report/{created['id']}/undo", json={"undo_token": token},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(undone.status_code, 200, undone.get_json())
        self.assertEqual(undone.get_json()["cluster"]["reports"], 0)
        self.assertEqual(store.stats()["reports"], 0)
        replay = self.client.post(
            f"/api/report/{created['id']}/undo", json={"undo_token": token},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(replay.status_code, 404)

    def test_email_report_undo_only_removes_that_report(self):
        headers = {"X-Requested-With": "XMLHttpRequest"}
        first = self.client.post(
            "/api/report",
            json={"cluster_key": "email-cluster", "subject": "Invoice", "reporter": "Analyst"},
            headers=headers,
        ).get_json()
        second = self.client.post(
            "/api/report",
            json={"cluster_key": "email-cluster", "subject": "Invoice", "reporter": "Teammate"},
            headers=headers,
        ).get_json()
        self.assertEqual(second["cluster"]["reports"], 2)

        response = self.client.post(
            f"/api/report/{first['id']}/undo", json={"undo_token": first["undo_token"]},
            headers=headers,
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["cluster"]["reports"], 1)
        self.assertEqual(store.stats()["reports"], 1)

    def test_report_undo_expires_after_five_minutes(self):
        created = self.client.post(
            "/api/report",
            json={"cluster_key": "expiring-cluster", "reporter": "Analyst"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        ).get_json()
        with store._LOCK, store._conn() as conn:
            conn.execute(
                "UPDATE reports SET undo_expires_at=? WHERE id=?",
                ("2000-01-01T00:00:00+00:00", created["id"]),
            )
        expired = self.client.post(
            f"/api/report/{created['id']}/undo", json={"undo_token": created["undo_token"]},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(expired.status_code, 410)
        self.assertEqual(store.stats()["reports"], 1)


if __name__ == "__main__":
    unittest.main()
