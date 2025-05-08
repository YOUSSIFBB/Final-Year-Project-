import unittest
import os
from utils.dashboard_ui import create_db, log_scan, get_scan_summary, get_recent_scans


class TestDashboard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Use a temporary test database for dashboard tests
        os.environ["TEST_DB_PATH"] = "tests/test_scan_logs.db"
        create_db()  # Ensure the test database is set up

    @classmethod
    def tearDownClass(cls):
        # Remove the test database after tests are done
        if os.path.exists("tests/test_scan_logs.db"):
            os.remove("tests/test_scan_logs.db")

    def test_log_scan(self):
        log_scan("test_user", "File", "example.txt", "Safe")
        summary = get_scan_summary("test_user")
        self.assertIn("File", summary)
        self.assertEqual(summary["File"], 1, "Should have 1 file scan logged.")

    def test_multiple_scans(self):
        log_scan("test_user", "URL", "https://example.com", "Safe")
        log_scan("test_user", "Email", "test_email.pdf", "Suspicious")
        summary = get_scan_summary("test_user")
        self.assertEqual(summary["URL"], 1)
        self.assertEqual(summary["Email"], 1)

    def test_recent_scans(self):
        log_scan("test_user", "Traffic", "localhost", "Monitored")
        log_scan("test_user", "Port", "localhost:80", "Open")
        recent = get_recent_scans("test_user", limit=2)
        self.assertEqual(len(recent), 2)
        self.assertEqual(recent[0][1], "Port")
        self.assertEqual(recent[1][1], "Traffic")


if __name__ == "__main__":
    unittest.main()
