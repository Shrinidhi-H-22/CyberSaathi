
import os
import tempfile
import unittest

from app import create_app
from app.services.history_service import get_recent_scans


class ScanHistoryIntegrationTests(unittest.TestCase):

    def setUp(self):

        self.temp_directory = tempfile.TemporaryDirectory()

        database_path = os.path.join(
            self.temp_directory.name,
            "integration_test.sqlite3"
        )

        self.app = create_app({
            "TESTING": True,
            "DATABASE": database_path,
            "HISTORY_LIMIT": 100
        })

        self.client = self.app.test_client()


    def tearDown(self):

        self.temp_directory.cleanup()


    def test_message_scan_is_saved_automatically(self):

        response = self.client.post(
            "/api/analyze-message",
            json={
                "message": "Please share your OTP immediately."
            }
        )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)

        self.assertTrue(data["history_saved"])

        self.assertIsNotNone(data["history_id"])

        with self.app.app_context():

            records = get_recent_scans()

        self.assertEqual(len(records), 1)

        self.assertEqual(
            records[0]["scan_type"],
            "message"
        )

        self.assertEqual(
            records[0]["risk_level"],
            "High"
        )

        # Original message content must not be stored.
        self.assertNotIn("original_message", records[0])


    def test_url_scan_is_saved_automatically(self):

        response = self.client.post(
            "/api/analyze-url",
            json={
                "url": "https://bit.ly/example"
            }
        )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)

        self.assertTrue(data["history_saved"])

        self.assertIsNotNone(data["history_id"])

        with self.app.app_context():

            records = get_recent_scans()

        self.assertEqual(len(records), 1)

        self.assertEqual(
            records[0]["scan_type"],
            "url"
        )

        self.assertEqual(
            records[0]["risk_level"],
            "Medium"
        )

        self.assertEqual(
            records[0]["link_count"],
            1
        )

        # Original URL must not be stored.
        self.assertNotIn("url", records[0])


if __name__ == "__main__":
    unittest.main()
