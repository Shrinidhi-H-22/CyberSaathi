
import os
import tempfile
import unittest

from app import create_app


class HistoryApiTests(unittest.TestCase):

    def setUp(self):

        self.temp_directory = tempfile.TemporaryDirectory()

        database_path = os.path.join(
            self.temp_directory.name,
            "history_api_test.sqlite3"
        )

        self.app = create_app({
            "TESTING": True,
            "DATABASE": database_path,
            "HISTORY_LIMIT": 100
        })

        self.client = self.app.test_client()

    def tearDown(self):

        self.temp_directory.cleanup()

    def create_message_scan(self, message):

        return self.client.post(
            "/api/analyze-message",
            json={"message": message}
        )

    def test_history_starts_empty(self):

        response = self.client.get("/api/history")

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["scans"], [])

    def test_history_returns_saved_scan_metadata(self):

        self.create_message_scan(
            "Please share your OTP immediately."
        )

        response = self.client.get("/api/history")

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["count"], 1)

        scan = data["scans"][0]

        self.assertEqual(scan["scan_type"], "message")
        self.assertEqual(scan["risk_level"], "High")

        # Original user content must not be returned.
        self.assertNotIn("original_message", scan)

    def test_history_respects_requested_limit(self):

        self.create_message_scan("First ordinary message.")
        self.create_message_scan("Second ordinary message.")
        self.create_message_scan("Third ordinary message.")

        response = self.client.get("/api/history?limit=2")

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["count"], 2)
        self.assertEqual(len(data["scans"]), 2)

    def test_invalid_history_limit_is_rejected(self):

        response = self.client.get("/api/history?limit=abc")

        self.assertEqual(response.status_code, 400)

    def test_history_limit_above_allowed_range_is_rejected(self):

        response = self.client.get("/api/history?limit=101")

        self.assertEqual(response.status_code, 400)

    def test_delete_history_clears_all_records(self):

        self.create_message_scan("First ordinary message.")
        self.create_message_scan("Second ordinary message.")

        response = self.client.delete("/api/history")

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(data["success"])
        self.assertEqual(data["deleted_count"], 2)

        history_response = self.client.get("/api/history")

        history_data = history_response.get_json()

        self.assertEqual(history_data["count"], 0)
        self.assertEqual(history_data["scans"], [])


if __name__ == "__main__":
    unittest.main()
