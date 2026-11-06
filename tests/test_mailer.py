from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import mailer  # noqa: E402


class MailjetMailerTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            "MAILJET_API_KEY": "test-api-key",
            "MAILJET_SECRET_KEY": "test-secret-key",
            "MAILJET_FROM_EMAIL": "verified@example.test",
            "MAILJET_FROM_NAME": "PhishGuard",
        }, clear=True)
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_missing_credentials_disable_delivery(self):
        os.environ.pop("MAILJET_SECRET_KEY")
        self.assertFalse(mailer.configured())
        with self.assertRaises(mailer.MailDeliveryError):
            mailer.send_email("person@example.test", "Subject", "Body")

    @patch("engine.mailer.requests.post")
    def test_sends_via_mailjet_api_with_server_side_auth(self, post):
        response = Mock(status_code=200)
        response.json.return_value = {"Messages": [{"Status": "success"}]}
        post.return_value = response

        self.assertTrue(mailer.configured())
        mailer.send_email("person@example.test", "Reset code", "Your code is 123456")

        post.assert_called_once()
        args, kwargs = post.call_args
        self.assertEqual(args[0], mailer.MAILJET_SEND_URL)
        self.assertEqual(kwargs["auth"], ("test-api-key", "test-secret-key"))
        self.assertEqual(kwargs["json"]["Messages"][0]["To"], [{"Email": "person@example.test"}])
        self.assertEqual(kwargs["json"]["Messages"][0]["From"]["Email"], "verified@example.test")
        self.assertEqual(kwargs["timeout"], 8)

    @patch("engine.mailer.requests.post")
    def test_provider_failure_shows_safe_reference_without_exposing_credentials_or_body(self, post):
        response = Mock(status_code=401)
        response.json.return_value = {
            "ErrorCode": "mj-0001",
            "ErrorIdentifier": "abc123-request-id",
            "ErrorMessage": "Do not expose this provider message",
        }
        post.return_value = response
        with self.assertRaises(mailer.MailDeliveryError) as raised:
            mailer.send_email("person@example.test", "Subject", "Sensitive body")
        message = str(raised.exception)
        self.assertIn("HTTP 401", message)
        self.assertIn("ErrorCode=mj-0001", message)
        self.assertIn("ErrorIdentifier=abc123-request-id", message)
        self.assertNotIn("Do not expose this provider message", message)
        self.assertNotIn("test-api-key", message)
        self.assertNotIn("test-secret-key", message)
        self.assertNotIn("Sensitive body", message)


if __name__ == "__main__":
    unittest.main()
