from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import assistant  # noqa: E402


class AssistantTests(unittest.TestCase):
    def test_public_login_help_uses_only_the_app_guide(self):
        result = assistant.answer_public("Why can't I log in to PhishGuard?")
        self.assertEqual(result["mode"], "offline")
        self.assertIn("PhishGuard login screen", result["answer"])
        self.assertEqual(result["sources"], [])

    def test_password_recovery_help_matches_current_otp_flow(self):
        result = assistant.answer_public("How do I reset my PhishGuard password?")
        self.assertIn("one-time code", result["answer"])
        self.assertIn("Gmail address has been added and verified", result["answer"])

    def test_off_topic_question_gets_a_scope_refusal(self):
        result = assistant.answer_public("What is the capital of France?")
        self.assertIn("only PhishGuard questions", result["answer"])
        self.assertTrue(result["suggestions"])

    def test_vague_login_wording_maps_to_the_login_answer(self):
        result = assistant.answer_public("I can't get into my account")
        self.assertIn("PhishGuard login screen", result["answer"])

    def test_synonyms_and_misspellings_are_understood(self):
        result = assistant.answer_public("I forgot my passwrod")
        self.assertIn("one-time code", result["answer"])

    def test_everyday_description_routes_to_the_right_check(self):
        result = assistant.answer_public("This email looks fake")
        self.assertIn("Check an email", result["answer"])

    def test_vague_request_returns_clickable_question_choices(self):
        result = assistant.answer_public("help me")
        self.assertIn("which part of PhishGuard", result["answer"])
        self.assertGreaterEqual(len(result["suggestions"]), 5)
        self.assertIn("How do I check a suspicious link?", result["suggestions"])

    def test_public_questions_are_not_saved_in_account_help_history(self):
        with patch.object(assistant.store, "record_assistant_request", side_effect=AssertionError):
            with patch.object(assistant.store, "count_recent_assistant_requests", side_effect=AssertionError):
                result = assistant.answer_public("How do I reset my PhishGuard password?")
        self.assertEqual(result["mode"], "offline")

    def test_public_question_validation(self):
        with self.assertRaises(assistant.AssistantError) as empty:
            assistant.answer_public("   ")
        self.assertEqual(empty.exception.status, 400)
        with self.assertRaises(assistant.AssistantError) as oversized:
            assistant.answer_public("x" * (assistant.MAX_QUESTION_LENGTH + 1))
        self.assertEqual(oversized.exception.status, 400)


if __name__ == "__main__":
    unittest.main()
