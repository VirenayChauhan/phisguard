from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import auth, store  # noqa: E402


class MicrosoftAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_path, cls.old_url = store.DB_PATH, store.DATABASE_URL
        cls.temp = tempfile.TemporaryDirectory(prefix="phisguard-microsoft-auth-")
        store.DB_PATH = os.path.join(cls.temp.name, "isolated.sqlite3")
        store.DATABASE_URL = ""
        store.init()

    @classmethod
    def tearDownClass(cls):
        store.DB_PATH, store.DATABASE_URL = cls.old_path, cls.old_url
        cls.temp.cleanup()

    def test_unverified_email_claim_is_not_stored_and_subject_reuses_account(self):
        user, token = auth.microsoft_login_account(
            "microsoft-sub-new", "new.person@example.org", "New Person",
            "127.0.0.1", "Unit Test Browser",
        )
        account = store.get_auth_account(user["username"])

        self.assertFalse(user["email_verified"])
        self.assertIsNone(account["email"])
        self.assertIsNone(account["email_verified_at"])
        self.assertEqual(auth.current_user(token)["username"], user["username"])
        identity = store.get_oauth_identity("microsoft", "microsoft-sub-new")
        self.assertEqual(identity["user_id"], account["user_id"])
        self.assertEqual(identity["email"], "")

        repeated, _ = auth.microsoft_login_account(
            "microsoft-sub-new", "new.person@example.org", "New Person"
        )
        self.assertEqual(repeated["username"], user["username"])

    def test_explicitly_verified_email_is_retained(self):
        user, _ = auth.microsoft_login_account(
            "microsoft-sub-verified", "verified@example.org", "Verified Person",
            email_verified=True,
        )
        account = store.get_auth_account(user["username"])
        self.assertEqual(account["email"], "verified@example.org")
        self.assertTrue(user["email_verified"])
        self.assertIsNotNone(account["email_verified_at"])

    def test_microsoft_email_never_auto_links_to_existing_account(self):
        existing, _ = auth.google_login_account(
            "google-existing-subject", "same@example.org", True, "Existing User"
        )
        microsoft_user, _ = auth.microsoft_login_account(
            "microsoft-sub-collision", "same@example.org", "Microsoft User",
            email_verified=True,
        )
        identity = store.get_oauth_identity("microsoft", "microsoft-sub-collision")
        microsoft_account = store.get_auth_account(microsoft_user["username"])

        self.assertNotEqual(microsoft_account["user_id"],
                            store.get_auth_account(existing["username"])["user_id"])
        self.assertEqual(identity["user_id"], microsoft_account["user_id"])
        self.assertIsNone(microsoft_account["email"])
        self.assertFalse(microsoft_user["email_verified"])

    def test_microsoft_sign_in_can_create_account_without_email_claim(self):
        user, _ = auth.microsoft_login_account(
            "microsoft-sub-no-email", "not-an-email", "Microsoft User"
        )
        self.assertEqual(user["email"], "")
        self.assertFalse(user["email_verified"])

    def test_empty_subject_is_rejected(self):
        with self.assertRaises(auth.AuthError):
            auth.microsoft_login_account("", "person@example.org", "Person")


if __name__ == "__main__":
    unittest.main()
