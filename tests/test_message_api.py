
import unittest

from app import create_app


class MessageApiTests(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_homepage_loads(self):

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)

    def test_valid_message_returns_analysis(self):

        response = self.client.post(
            "/api/analyze-message",
            json={
                "message": (
                    "URGENT! Your bank account will be blocked "
                    "today. Share your OTP immediately."
                )
            }
        )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["risk_level"], "High")
        self.assertTrue(data["findings"])

    def test_empty_message_is_rejected(self):

        response = self.client.post(
            "/api/analyze-message",
            json={"message": "   "}
        )

        self.assertEqual(response.status_code, 400)

    def test_missing_message_is_rejected(self):

        response = self.client.post(
            "/api/analyze-message",
            json={}
        )

        self.assertEqual(response.status_code, 400)

    def test_non_json_request_is_rejected(self):

        response = self.client.post(
            "/api/analyze-message",
            data="Some message",
            content_type="text/plain"
        )

        self.assertEqual(response.status_code, 415)

    def test_oversized_message_is_rejected(self):

        response = self.client.post(
            "/api/analyze-message",
            json={"message": "A" * 5001}
        )

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
