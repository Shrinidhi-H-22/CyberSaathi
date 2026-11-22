
import unittest

from app.services.url_analyzer import analyze_url


class URLAnalyzerTests(unittest.TestCase):

    def test_empty_url_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("   ")

    def test_non_text_input_is_rejected(self):
        with self.assertRaises(TypeError):
            analyze_url(123)

    def test_url_over_length_limit_is_rejected(self):
        long_url = (
            "https://example.com/"
            + ("a" * 2048)
        )

        with self.assertRaises(ValueError):
            analyze_url(long_url)

    def test_url_with_spaces_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("https://example.com/my page")

    def test_unsupported_scheme_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("ftp://example.com/file")

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("https://example.com:99999")

    def test_normal_https_url_has_no_warning_indicators(self):
        result = analyze_url("https://example.com")

        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["indicator_score"], 0)
        self.assertEqual(result["findings"], [])

    def test_url_without_scheme_is_supported(self):
        result = analyze_url("www.example.com")

        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["hostname"], "www.example.com")

    def test_http_url_is_flagged(self):
        result = analyze_url("http://example.com")

        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["indicator_score"], 1)

        self.assertIn(
            "unencrypted_http",
            [item["code"] for item in result["findings"]]
        )

    def test_ip_address_over_http_is_high_risk(self):
        result = analyze_url("http://192.0.2.10/login")

        self.assertEqual(result["risk_level"], "High")
        self.assertEqual(result["indicator_score"], 5)

    def test_embedded_credentials_are_flagged(self):
        result = analyze_url(
            "https://paypal.com@evil.example/login"
        )

        self.assertEqual(result["risk_level"], "High")

        self.assertIn(
            "embedded_credentials",
            [item["code"] for item in result["findings"]]
        )

    def test_shortened_url_is_flagged(self):
        result = analyze_url("https://bit.ly/example")

        self.assertEqual(result["risk_level"], "Medium")

        self.assertIn(
            "shortened_url",
            [item["code"] for item in result["findings"]]
        )

    def test_punycode_domain_is_flagged(self):
        result = analyze_url(
            "https://xn--pple-43d.com"
        )

        self.assertEqual(result["risk_level"], "Medium")

        self.assertIn(
            "punycode_domain",
            [item["code"] for item in result["findings"]]
        )


if __name__ == "__main__":
    unittest.main()
