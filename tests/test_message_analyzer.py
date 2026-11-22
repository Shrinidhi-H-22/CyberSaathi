
import unittest

from app.services.message_analyzer import analyze_message


class MessageAnalyzerTests(unittest.TestCase):

    def test_empty_message_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_message("   ")

    def test_non_text_input_is_rejected(self):
        with self.assertRaises(TypeError):
            analyze_message(123)

    def test_message_over_limit_is_rejected(self):
        long_message = "a" * 5001

        with self.assertRaises(ValueError):
            analyze_message(long_message)

    def test_normal_message_has_low_indicators(self):
        message = "Hello, the meeting starts at 3 PM. See you there."

        result = analyze_message(message)

        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["indicator_score"], 0)
        self.assertEqual(result["findings"], [])

    def test_urgent_message_is_flagged(self):
        message = "Act immediately to read this notice."

        result = analyze_message(message)

        self.assertEqual(result["risk_level"], "Medium")
        self.assertEqual(result["indicator_score"], 2)

    def test_sensitive_information_request_is_flagged(self):
        message = "Please share your OTP to verify your account."

        result = analyze_message(message)

        self.assertEqual(result["risk_level"], "High")
        self.assertEqual(result["indicator_score"], 4)

    def test_multiple_warning_signs_are_flagged(self):
        message = (
            "URGENT! Your bank account will be blocked "
            "today. Share your OTP immediately."
        )

        result = analyze_message(message)

        self.assertEqual(result["risk_level"], "High")
        self.assertGreaterEqual(result["indicator_score"], 5)

    def test_safety_advice_is_not_flagged_as_sensitive_request(self):
        message = (
            "Never share your OTP with anyone. "
            "Contact your bank using its official app."
        )

        result = analyze_message(message)

        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["indicator_score"], 0)

    def test_link_is_reported(self):
        message = "Please review https://example.com for information."

        result = analyze_message(message)

        self.assertEqual(result["risk_level"], "Low")
        self.assertIn(
            "link_present",
            [item["code"] for item in result["findings"]]
        )

    # New combined message and URL tests

    def test_shortened_url_inside_message_is_analyzed(self):
        message = "Please check https://bit.ly/example"

        result = analyze_message(message)

        self.assertEqual(result["risk_level"], "Medium")
        self.assertEqual(result["url_indicator_score"], 2)
        self.assertEqual(result["link_count"], 1)

        self.assertEqual(
            result["link_analyses"][0]["hostname"],
            "bit.ly"
        )

    def test_ip_address_url_inside_message_is_flagged(self):
        message = "Please visit http://192.0.2.10/login"

        result = analyze_message(message)

        self.assertEqual(result["risk_level"], "High")
        self.assertEqual(result["url_indicator_score"], 5)

    def test_trailing_punctuation_is_removed_from_url(self):
        message = "Please review https://bit.ly/example."

        result = analyze_message(message)

        self.assertEqual(result["link_count"], 1)
        self.assertEqual(
            result["link_analyses"][0]["hostname"],
            "bit.ly"
        )

    def test_duplicate_urls_are_analyzed_once(self):
        message = (
            "Please check https://bit.ly/example "
            "and https://bit.ly/example"
        )

        result = analyze_message(message)

        self.assertEqual(result["link_count"], 1)
        self.assertEqual(result["links_analyzed"], 1)

    def test_only_ten_unique_urls_are_analyzed(self):
        links = [
            f"https://example{i}.com"
            for i in range(11)
        ]

        message = "Please review these links: " + " ".join(links)

        result = analyze_message(message)

        self.assertEqual(result["link_count"], 11)
        self.assertEqual(result["links_analyzed"], 10)
        self.assertEqual(result["links_not_analyzed"], 1)


if __name__ == "__main__":
    unittest.main()
