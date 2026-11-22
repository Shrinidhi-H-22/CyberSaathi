
import os
import tempfile
import unittest

from app import create_app


class HistoryPageTests(unittest.TestCase):

    def setUp(self):

        self.temp_directory = tempfile.TemporaryDirectory()

        database_path = os.path.join(
            self.temp_directory.name,
            "history_page_test.sqlite3"
        )

        self.app = create_app({
            "TESTING": True,
            "DATABASE": database_path,
            "HISTORY_LIMIT": 100
        })

        self.client = self.app.test_client()


    def tearDown(self):

        self.temp_directory.cleanup()


    def test_history_page_loads(self):

        response = self.client.get("/history")

        self.assertEqual(response.status_code, 200)

        page = response.get_data(as_text=True)

        self.assertIn("Your scan activity", page)

        self.assertIn("Recent activity", page)


    def test_history_page_loads_history_javascript(self):

        response = self.client.get("/history")

        page = response.get_data(as_text=True)

        self.assertIn("history.js", page)

        # Scanner JavaScript should not load on the history page.
        self.assertNotIn("js/scanner.js", page)


if __name__ == "__main__":
    unittest.main()
