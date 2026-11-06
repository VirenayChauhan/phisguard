from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import store  # noqa: E402
import app as phishguard_app  # noqa: E402


class MonthlyScanSummaryTests(unittest.TestCase):
    def setUp(self):
        self.old_path, self.old_url = store.DB_PATH, store.DATABASE_URL
        self.temp = tempfile.TemporaryDirectory(prefix="phisguard-monthly-email-")
        store.DB_PATH = os.path.join(self.temp.name, "isolated.sqlite3")
        store.DATABASE_URL = ""
        store.init()
        now = datetime.now(timezone.utc)
        previous_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
        self.month_key = previous_month.strftime("%Y-%m")
        self.month_label = previous_month.strftime("%B %Y")
        self.user_id = "monthly-recipient"
        store.create_auth_account(
            self.user_id, "monthly_recipient", "unused", "9876543210",
            now.isoformat(), "monthly-recipient@gmail.com",
            notify_monthly_summary=True,
        )
        store.mark_auth_email_verified(self.user_id, now.isoformat())
        store.record_flagged_scan(
            self.user_id, f"{self.month_key}-12T14:00:00+00:00", "url",
            "bad.example", "malicious", 82,
        )

    def tearDown(self):
        store.DB_PATH, store.DATABASE_URL = self.old_path, self.old_url
        self.temp.cleanup()

    def test_sends_only_opted_in_previous_month_domain_summary_once(self):
        client = phishguard_app.app.test_client()
        with patch.dict(os.environ, {"CRON_SECRET": "cron-test-secret"}), \
                patch("app.mailer.configured", return_value=True), \
                patch("app.mailer.send_email") as send:
            response = client.get(
                "/api/cron/monthly-scan-summary",
                headers={"Authorization": "Bearer cron-test-secret"},
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["sent"], 1)
            send.assert_called_once()
            recipient, subject, body = send.call_args.args
            self.assertEqual(recipient, "monthly-recipient@gmail.com")
            self.assertIn(self.month_label, subject)
            self.assertIn("bad.example", body)
            self.assertIn("malicious", body)
            self.assertNotIn("https://", body)
            self.assertNotIn("raw email", body.lower())

            response = client.get(
                "/api/cron/monthly-scan-summary",
                headers={"Authorization": "Bearer cron-test-secret"},
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["sent"], 0)
            self.assertEqual(send.call_count, 1)

    def test_cron_endpoint_requires_secret(self):
        client = phishguard_app.app.test_client()
        with patch.dict(os.environ, {"CRON_SECRET": "cron-test-secret"}):
            response = client.get("/api/cron/monthly-scan-summary")
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
