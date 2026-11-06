from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import auth, store  # noqa: E402


class AuthOtpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._old_path, cls._old_url = store.DB_PATH, store.DATABASE_URL
        cls._temp = tempfile.TemporaryDirectory(prefix="phisguard-auth-otp-")
        store.DB_PATH = os.path.join(cls._temp.name, "isolated.sqlite3")
        store.DATABASE_URL = ""
        store.init()

    @classmethod
    def tearDownClass(cls):
        store.DB_PATH, store.DATABASE_URL = cls._old_path, cls._old_url
        cls._temp.cleanup()

    def test_email_code_is_one_time_and_purpose_scoped(self):
        email = "otp-test@gmail.com"
        _, reset_code = auth.issue_email_otp(email, "password_reset", "127.0.0.1")
        _, verify_code = auth.issue_email_otp(email, "verify_email", "127.0.0.1")
        self.assertEqual(auth.verify_email_otp(email, "password_reset", reset_code), email)
        with self.assertRaises(auth.AuthError):
            auth.verify_email_otp(email, "password_reset", reset_code)
        self.assertEqual(auth.verify_email_otp(email, "verify_email", verify_code), email)

    def test_invalid_guess_counts_toward_challenge_limit(self):
        email = "otp-guess@gmail.com"
        _, code = auth.issue_email_otp(email, "verify_email", "127.0.0.2")
        with self.assertRaises(auth.AuthError):
            auth.verify_email_otp(email, "verify_email", "000000" if code != "000000" else "000001")
        self.assertEqual(auth.verify_email_otp(email, "verify_email", code), email)

    def test_per_address_and_ip_request_limit(self):
        email = "otp-limit@gmail.com"
        for _ in range(auth.OTP_MAX_REQUESTS):
            auth.issue_email_otp(email, "password_reset", "127.0.0.3")
        with self.assertRaises(auth.AuthError) as raised:
            auth.issue_email_otp(email, "password_reset", "127.0.0.3")
        self.assertEqual(raised.exception.status, 429)

    def test_monthly_summary_opt_in_requires_a_gmail_address(self):
        with self.assertRaises(auth.AuthError):
            auth.register_account(
                "summary_no_email", "StrongPass123", "9876543210",
                recovery_question="What is your favorite game?",
                recovery_answer="Chess", monthly_summary=True,
            )

    def test_monthly_summary_registration_is_opt_in_and_persisted(self):
        user, _ = auth.register_account(
            "summary_optin", "StrongPass123", "9876543211",
            email="summary-optin@gmail.com",
            recovery_question="What is your favorite game?",
            recovery_answer="Chess", monthly_summary=True,
        )
        self.assertTrue(user["notifications"]["email"])
        account = store.get_auth_account("summary_optin")
        self.assertEqual(account["notify_monthly_summary"], 1)


if __name__ == "__main__":
    unittest.main()
