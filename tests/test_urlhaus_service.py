
import os
import unittest
from unittest.mock import Mock, patch

import requests

from app.services.urlhaus_service import lookup_urlhaus


class URLhausServiceTests(unittest.TestCase):

    def setUp(self):
        self.url = "https://example.com/test"
        self.auth_key = "test-auth-key"

    @patch("app.services.urlhaus_service.requests.post")
    def test_url_found_in_urlhaus(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "date_added": "2026-01-01 10:00:00",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
        }
        mock_post.return_value = mock_response

        result = lookup_urlhaus(self.url, self.auth_key)

        self.assertEqual(result["status"], "found")
        self.assertEqual(result["source"], "URLhaus")
        self.assertEqual(result["threat"], "malware_download")

        mock_post.assert_called_once()

    @patch("app.services.urlhaus_service.requests.post")
    def test_url_not_found_in_urlhaus(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "no_results",
        }
        mock_post.return_value = mock_response

        result = lookup_urlhaus(self.url, self.auth_key)

        self.assertEqual(result["status"], "not_found")
        self.assertEqual(result["source"], "URLhaus")

    @patch.dict(os.environ, {"URLHAUS_AUTH_KEY": ""})
    @patch("app.services.urlhaus_service.requests.post")
    def test_missing_api_key_returns_unavailable(self, mock_post):
        result = lookup_urlhaus(self.url)

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "not_configured")
        mock_post.assert_not_called()

    @patch("app.services.urlhaus_service.requests.post")
    def test_invalid_url_is_rejected(self, mock_post):
        result = lookup_urlhaus("ftp://example.com", self.auth_key)

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "invalid_url")
        mock_post.assert_not_called()

    @patch("app.services.urlhaus_service.requests.post")
    def test_scheme_less_url_is_normalized_to_https(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "no_results",
        }
        mock_post.return_value = mock_response

        result = lookup_urlhaus("www.example.com", self.auth_key)

        self.assertEqual(result["status"], "not_found")
        self.assertEqual(
            mock_post.call_args.kwargs["data"]["url"],
            "https://www.example.com",
        )

    @patch("app.services.urlhaus_service.requests.post")
    def test_scheme_less_url_with_port_is_normalized(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "no_results",
        }
        mock_post.return_value = mock_response

        result = lookup_urlhaus(
            "example.com:8080/path",
            self.auth_key,
        )

        self.assertEqual(result["status"], "not_found")
        self.assertEqual(
            mock_post.call_args.kwargs["data"]["url"],
            "https://example.com:8080/path",
        )

    @patch("app.services.urlhaus_service.requests.post")
    def test_protocol_relative_url_is_normalized(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "no_results",
        }
        mock_post.return_value = mock_response

        result = lookup_urlhaus("//example.com/path", self.auth_key)

        self.assertEqual(result["status"], "not_found")
        self.assertEqual(
            mock_post.call_args.kwargs["data"]["url"],
            "https://example.com/path",
        )

    @patch("app.services.urlhaus_service.requests.post")
    def test_invalid_port_is_rejected(self, mock_post):
        result = lookup_urlhaus(
            "https://example.com:99999",
            self.auth_key,
        )

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "invalid_url")
        mock_post.assert_not_called()

    @patch("app.services.urlhaus_service.requests.post")
    def test_api_timeout_returns_unavailable(self, mock_post):
        mock_post.side_effect = requests.Timeout

        result = lookup_urlhaus(self.url, self.auth_key)

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "timeout")

    @patch("app.services.urlhaus_service.requests.post")
    def test_api_network_error_returns_unavailable(self, mock_post):
        mock_post.side_effect = requests.ConnectionError

        result = lookup_urlhaus(self.url, self.auth_key)

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "request_error")

    @patch("app.services.urlhaus_service.requests.post")
    def test_invalid_api_response_returns_unavailable(self, mock_post):
        mock_response = Mock()
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_post.return_value = mock_response

        result = lookup_urlhaus(self.url, self.auth_key)

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "invalid_response")

    @patch("app.services.urlhaus_service.requests.post")
    def test_unexpected_api_response_returns_unavailable(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {
            "query_status": "unexpected_status",
        }
        mock_post.return_value = mock_response

        result = lookup_urlhaus(self.url, self.auth_key)

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(
            result["reason"],
            "unexpected_api_response"
        )

    @patch("app.services.urlhaus_service.requests.post")
    def test_http_error_returns_unavailable(self, mock_post):
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError
        mock_post.return_value = mock_response

        result = lookup_urlhaus(self.url, self.auth_key)

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "request_error")


if __name__ == "__main__":
    unittest.main()
