
import os
import tempfile
import unittest

from app import create_app

from app.services.history_service import (
    clear_scan_history,
    get_recent_scans,
    save_scan
)


class HistoryServiceTests(unittest.TestCase):

    def setUp(self):

        self.temp_directory = tempfile.TemporaryDirectory()

        database_path = os.path.join(
            self.temp_directory.name,
            "test_history.sqlite3"
        )

        # Each test gets its own temporary database.
        self.app = create_app({
            "TESTING": True,
            "DATABASE": database_path,
            "HISTORY_LIMIT": 2
        })

        self.app_context = self.app.app_context()

        self.app_context.push()


    def tearDown(self):

        self.app_context.pop()

        self.temp_directory.cleanup()


    def test_history_starts_empty(self):

        records = get_recent_scans()

        self.assertEqual(records, [])


    def test_save_message_scan(self):

        result = {
            "risk_level": "High",
            "indicator_score": 8,
            "findings": [{}, {}],
            "link_count": 1,
            "summary": "Several warning indicators detected."
        }

        scan_id = save_scan("message", result)

        records = get_recent_scans()

        self.assertIsNotNone(scan_id)

        self.assertEqual(len(records), 1)

        self.assertEqual(records[0]["scan_type"], "message")

        self.assertEqual(records[0]["risk_level"], "High")

        self.assertEqual(records[0]["indicator_score"], 8)

        self.assertEqual(records[0]["finding_count"], 2)

        self.assertEqual(records[0]["link_count"], 1)

        # Original message content must not be stored.
        self.assertNotIn("message", records[0].get("source", ""))


    def test_url_scan_defaults_to_one_link(self):

        result = {
            "risk_level": "Medium",
            "indicator_score": 2,
            "findings": [{}],
            "summary": "A shortened URL was detected."
        }

        save_scan("url", result)

        records = get_recent_scans()

        self.assertEqual(records[0]["scan_type"], "url")

        self.assertEqual(records[0]["link_count"], 1)


    def test_clear_history(self):

        result = {
            "risk_level": "Low",
            "indicator_score": 0,
            "findings": [],
            "summary": "No configured warning patterns detected."
        }

        save_scan("message", result)

        deleted = clear_scan_history()

        self.assertEqual(deleted, 1)

        self.assertEqual(get_recent_scans(), [])


    def test_invalid_scan_type_is_rejected(self):

        with self.assertRaises(ValueError):

            save_scan(
                "unknown",
                {
                    "risk_level": "Low",
                    "indicator_score": 0,
                    "findings": []
                }
            )


    def test_invalid_risk_level_is_rejected(self):

        with self.assertRaises(ValueError):

            save_scan(
                "message",
                {
                    "risk_level": "Unknown",
                    "indicator_score": 0,
                    "findings": []
                }
            )


    def test_negative_indicator_score_is_rejected(self):

        with self.assertRaises(ValueError):

            save_scan(
                "message",
                {
                    "risk_level": "Low",
                    "indicator_score": -1,
                    "findings": []
                }
            )


    def test_history_retention_limit(self):

        for number in range(3):

            save_scan(
                "message",
                {
                    "risk_level": "Low",
                    "indicator_score": 0,
                    "findings": [],
                    "summary": f"Scan {number}"
                }
            )

        records = get_recent_scans()

        self.assertEqual(len(records), 2)

        self.assertEqual(records[0]["summary"], "Scan 2")

        self.assertEqual(records[1]["summary"], "Scan 1")


if __name__ == "__main__":
    unittest.main()
