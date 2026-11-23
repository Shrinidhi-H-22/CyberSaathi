
import unittest
from unittest.mock import patch

from app import create_app


class URLApiTests(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    @patch(
        "app.routes.main.lookup_urlhaus",
        return_value={
            "status": "not_found",
            "source": "URLhaus"
        }
    )
    def test_valid_url_returns_analysis(self, mock_urlhaus):

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

        self.assertEqual(
            data["urlhaus"]["status"],
            "not_found"
        )

        mock_urlhaus.assert_called_once_with(
            "https://bit.ly/example"
        )

    @patch(
        "app.routes.main.lookup_urlhaus",
        return_value={
            "status": "found",
            "source": "URLhaus",
            "threat": "malware_download"
        }
    )
    def test_urlhaus_detects_listed_url(self, mock_urlhaus):

        response = self.client.post(
            "/api/analyze-url",
            json={
                "url": "https://malicious.example/file"
            }
        )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)

        self.assertEqual(
            data["urlhaus"]["status"],
            "found"
        )

        self.assertEqual(
            data["urlhaus"]["source"],
            "URLhaus"
        )

    @patch(
        "app.routes.main.lookup_urlhaus",
        return_value={
            "status": "unavailable",
            "reason": "timeout"
        }
    )
    def test_url_analysis_continues_when_urlhaus_is_unavailable(
        self,
        mock_urlhaus
    ):

        response = self.client.post(
            "/api/analyze-url",
            json={
                "url": "https://example.com"
            }
        )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)

        self.assertIn("risk_level", data)

        self.assertEqual(
            data["urlhaus"]["status"],
            "unavailable"
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

    def test_malformed_url_is_rejected(self):

        response = self.client.post(
            "/api/analyze-url",
            json={"url": "https://-invalid-.com"}
        )

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
