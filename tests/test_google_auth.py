from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import auth, store  # noqa: E402


class GoogleAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old_path, cls.old_url = store.DB_PATH, store.DATABASE_URL
        cls.temp = tempfile.TemporaryDirectory(prefix="phisguard-google-auth-")
        store.DB_PATH = os.path.join(cls.temp.name, "isolated.sqlite3")
        store.DATABASE_URL = ""
        store.init()

    @classmethod
    def tearDownClass(cls):
        store.DB_PATH, store.DATABASE_URL = cls.old_path, cls.old_url
        cls.temp.cleanup()

    def test_verified_google_email_links_existing_account_and_verifies_it(self):
        local_user, _ = auth.register_account(
            "google_linked", "StrongPass123", "9876543210", "link@gmail.com",
            "What is your favorite game?", "chess",
        )
        user, token = auth.google_login_account(
            "google-sub-linked", "LINK@gmail.com", True, "Google Person",
            "127.0.0.1", "Unit Test Browser",
        )

        self.assertEqual(user["username"], local_user["username"])
        self.assertTrue(user["email_verified"])
        self.assertEqual(auth.current_user(token)["username"], local_user["username"])
        identity = store.get_oauth_identity("google", "google-sub-linked")
        self.assertEqual(identity["user_id"], store.get_auth_account("google_linked")["user_id"])

    def test_google_identity_creates_account_with_verified_email(self):
        user, token = auth.google_login_account(
            "google-sub-new", "new.person@example.org", True, "New Person",
            "127.0.0.2", "Unit Test Browser",
        )
        account = store.get_auth_account(user["username"])

        self.assertTrue(user["email_verified"])
        self.assertEqual(account["email"], "new.person@example.org")
        self.assertEqual(account["mobile"], "")
        self.assertIsNone(account["recovery_question"])
        self.assertEqual(auth.current_user(token)["username"], user["username"])
        self.assertEqual(store.get_oauth_identity("google", "google-sub-new")["user_id"], account["user_id"])

    def test_repeated_google_sign_in_reuses_the_same_account(self):
        first, _ = auth.google_login_account(
            "google-sub-repeat", "repeat@example.org", True, "Repeat User"
        )
        second, _ = auth.google_login_account(
            "google-sub-repeat", "repeat@example.org", True, "Repeat User"
        )
        self.assertEqual(first["username"], second["username"])
        self.assertEqual(store.get_auth_account_by_email("repeat@example.org")["user_id"],
                         store.get_oauth_identity("google", "google-sub-repeat")["user_id"])

    def test_unverified_email_is_rejected(self):
        with self.assertRaises(auth.AuthError):
            auth.google_login_account(
                "google-sub-unverified", "unverified@example.org", False, "Unverified"
            )

    def test_google_identity_cannot_be_linked_to_a_second_account(self):
        auth.google_login_account("google-sub-first", "first@example.org", True, "First")
        auth.google_login_account("google-sub-second", "second@example.org", True, "Second")
        with self.assertRaises(auth.AuthError) as raised:
            auth.google_login_account("google-sub-third", "second@example.org", True, "Second")
        self.assertEqual(raised.exception.status, 409)

    def test_account_deletion_removes_google_identity(self):
        user, _ = auth.google_login_account(
            "google-sub-delete", "delete@example.org", True, "Delete Me"
        )
        account = store.get_auth_account(user["username"])
        store.delete_auth_account(account["user_id"], user["username"])
        self.assertIsNone(store.get_oauth_identity("google", "google-sub-delete"))


if __name__ == "__main__":
    unittest.main()
