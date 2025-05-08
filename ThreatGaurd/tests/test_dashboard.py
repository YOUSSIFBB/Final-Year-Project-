import unittest
import os
from utils.dashboard_ui import log_scan, get_scan_summary, get_recent_scans


class TestDashboard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Use the test database for dashboard tests
        os.environ["TEST_DB_PATH"] = "tests/test_scan_logs.db"

    def test_log_scan(self):
        initial_summary = get_scan_summary("test_user")
        initial_count = initial_summary.get("File", 0)

        log_scan("test_user", "File", "example.txt", "Safe")
        summary = get_scan_summary("test_user")
        new_count = summary.get("File", 0)

        # The new count should be 1 more than the initial count
        self.assertEqual(
            new_count, initial_count + 1, "File scan count should increase by 1."
        )

    def test_multiple_scans(self):
        initial_summary = get_scan_summary("test_user")
        initial_url_count = initial_summary.get("URL", 0)
        initial_email_count = initial_summary.get("Email", 0)

        log_scan("test_user", "URL", "https://example.com", "Safe")
        log_scan("test_user", "Email", "test_email.pdf", "Suspicious")
        summary = get_scan_summary("test_user")

        # The new counts should be 1 more than the initial counts
        self.assertEqual(summary.get("URL", 0), initial_url_count + 1)
        self.assertEqual(summary.get("Email", 0), initial_email_count + 1)

    def test_recent_scans(self):
        initial_scans = get_recent_scans("test_user")
        initial_count = len(initial_scans)

        log_scan("test_user", "Traffic", "localhost", "Monitored")
        log_scan("test_user", "Port", "localhost:80", "Open")
        recent = get_recent_scans("test_user", limit=initial_count + 2)

        # The count should increase by 2
        self.assertEqual(len(recent), initial_count + 2)

        # Verify that the two new scans are in the recent scans
        scan_types = [scan[1] for scan in recent]
        self.assertIn("Traffic", scan_types)
        self.assertIn("Port", scan_types)


if __name__ == "__main__":
    unittest.main()
