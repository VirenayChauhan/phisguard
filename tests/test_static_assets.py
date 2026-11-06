import unittest

from app import app


class TestStaticAssetServing(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_static_files_keep_the_existing_url_prefix(self):
        for path, content_type in (
            ("/static/style.css", "text/css"),
            ("/static/app.js", "javascript"),
            ("/static/phisguard-logo.png", "image/png"),
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(content_type, response.content_type)
                self.assertTrue(response.data)
                response.close()

    def test_login_screen_offers_google_and_microsoft(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Continue with Google", response.data)
        self.assertIn(b"Continue with Microsoft", response.data)
        self.assertIn(b'href="/auth/microsoft/start"', response.data)
        response.close()

    def test_service_worker_keeps_root_scope_headers(self):
        response = self.client.get("/sw.js")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Service-Worker-Allowed"), "/")
        self.assertIn("no-cache", response.headers.get("Cache-Control", ""))
        self.assertTrue(response.data)
        response.close()


if __name__ == "__main__":
    unittest.main()
