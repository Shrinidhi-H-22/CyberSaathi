
import unittest

from app import create_app


class URLApiTests(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_valid_url_returns_analysis(self):

        response = self.client.post(
            "/api/analyze-url",
            json={
                "url": "https://bit.ly/example"
            }
        )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["risk_level"], "Medium")

        self.assertIn(
            "shortened_url",
            [item["code"] for item in data["findings"]]
        )

    def test_empty_url_is_rejected(self):

        response = self.client.post(
            "/api/analyze-url",
            json={"url": "   "}
        )

        self.assertEqual(response.status_code, 400)

    def test_missing_url_is_rejected(self):

        response = self.client.post(
            "/api/analyze-url",
            json={}
        )

        self.assertEqual(response.status_code, 400)

    def test_non_json_request_is_rejected(self):

        response = self.client.post(
            "/api/analyze-url",
            data="https://example.com",
            content_type="text/plain"
        )

        self.assertEqual(response.status_code, 415)

    def test_non_string_url_is_rejected(self):

        response = self.client.post(
            "/api/analyze-url",
            json={"url": 123}
        )

        self.assertEqual(response.status_code, 400)

    def test_oversized_url_is_rejected(self):

        long_url = (
            "https://example.com/"
            + ("a" * 2048)
        )

        response = self.client.post(
            "/api/analyze-url",
            json={"url": long_url}
        )

        self.assertEqual(response.status_code, 400)

    def test_unsupported_url_scheme_is_rejected(self):

        response = self.client.post(
            "/api/analyze-url",
            json={"url": "ftp://example.com/file"}
        )

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
