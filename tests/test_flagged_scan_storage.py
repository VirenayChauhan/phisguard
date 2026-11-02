from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import store  # noqa: E402


class FlaggedScanStorageTests(unittest.TestCase):
    def setUp(self):
        self.old_path, self.old_url = store.DB_PATH, store.DATABASE_URL
        self.temp = tempfile.TemporaryDirectory(prefix="phisguard-flagged-scans-")
        store.DB_PATH = os.path.join(self.temp.name, "isolated.sqlite3")
        store.DATABASE_URL = ""
        store.init()
        store.create_auth_account(
            "user-monthly-1", "monthly_user", "not-used", "9876543210",
            "2026-10-01T00:00:00+00:00", "monthly@gmail.com",
            notify_monthly_summary=True,
        )
        store.create_auth_account(
            "user-monthly-2", "non_opted_user", "not-used", "9876543211",
            "2026-10-01T00:00:00+00:00", "not-opted@gmail.com",
        )

    def tearDown(self):
        store.DB_PATH, store.DATABASE_URL = self.old_path, self.old_url
        self.temp.cleanup()

    def test_records_only_opted_in_malicious_or_suspicious_domain_metadata(self):
        self.assertTrue(store.record_flagged_scan(
            "user-monthly-1", "2026-10-02T12:00:00+00:00", "url",
            "Evil.Example.", "suspicious", 34,
        ))
        self.assertFalse(store.record_flagged_scan(
            "user-monthly-2", "2026-10-02T12:00:00+00:00", "url",
            "evil.example", "suspicious", 34,
        ))
        self.assertFalse(store.record_flagged_scan(
            "user-monthly-1", "2026-10-02T12:00:00+00:00", "url",
            "safe.example", "likely_safe", 2,
        ))
        rows = store.list_monthly_flagged_scans("user-monthly-1", "2026-10")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "evil.example")
        self.assertEqual(rows[0]["verdict"], "suspicious")
        self.assertEqual(rows[0]["score"], 34)

    def test_repeated_domain_updates_one_monthly_row(self):
        for scanned_at, verdict, score in (
            ("2026-10-02T12:00:00+00:00", "suspicious", 35),
            ("2026-10-19T12:00:00+00:00", "malicious", 77),
        ):
            store.record_flagged_scan(
                "user-monthly-1", scanned_at, "url", "bad.example", verdict, score
            )
        rows = store.list_monthly_flagged_scans("user-monthly-1", "2026-10")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scan_count"], 2)
        self.assertEqual(rows[0]["verdict"], "malicious")
        self.assertEqual(rows[0]["score"], 77)
        self.assertEqual(rows[0]["last_scanned_at"], "2026-10-19T12:00:00+00:00")

    def test_opt_out_deletes_existing_monthly_records(self):
        store.record_flagged_scan(
            "user-monthly-1", "2026-10-02T12:00:00+00:00", "url",
            "bad.example", "malicious", 80,
        )
        store.update_auth_preferences("user-monthly-1", True, False, True, True)
        self.assertEqual(store.list_monthly_flagged_scans("user-monthly-1", "2026-10"), [])
        self.assertFalse(store.record_flagged_scan(
            "user-monthly-1", "2026-10-03T12:00:00+00:00", "url",
            "bad.example", "malicious", 80,
        ))

    def test_scan_month_and_domain_validation(self):
        self.assertFalse(store.record_flagged_scan(
            "user-monthly-1", "not-a-date", "url", "bad.example", "malicious", 80
        ))
        self.assertFalse(store.record_flagged_scan(
            "user-monthly-1", "2026-10-02T12:00:00+00:00", "url",
            "https://bad.example/path?token=secret", "malicious", 80,
        ))


if __name__ == "__main__":
    unittest.main()
