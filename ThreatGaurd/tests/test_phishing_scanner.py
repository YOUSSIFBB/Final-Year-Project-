import unittest
from unittest.mock import patch, MagicMock
from utils.phishing_scanner import PhishingScanner


class TestPhishingScanner(unittest.TestCase):

    @patch("utils.phishing_scanner.PhishingScanner.extract_text")
    @patch("utils.phishing_scanner.PhishingScanner.scan_url_with_virustotal")
    def test_phishing_scanner_safe_email(self, mock_scan_url, mock_extract_text):
        mock_extract_text.return_value = (
            "This is a safe email with no suspicious content."
        )
        mock_scan_url.return_value = (None, None)

        scanner = PhishingScanner()
        result, error = scanner.scan_email("dummy_file_path")

        self.assertEqual(result["verdict"], "✅ Safe")
        self.assertEqual(len(result["matched_patterns"]), 0)
        self.assertEqual(len(result["links"]), 0)

    @patch("utils.phishing_scanner.PhishingScanner.extract_text")
    @patch("utils.phishing_scanner.PhishingScanner.scan_url_with_virustotal")
    def test_phishing_scanner_suspicious_email(self, mock_scan_url, mock_extract_text):
        mock_extract_text.return_value = (
            "Urgent action required. Click here to verify your account."
        )
        mock_scan_url.return_value = (None, None)

        scanner = PhishingScanner()
        result, error = scanner.scan_email("dummy_file_path")

        self.assertEqual(result["verdict"], "⚠️ Suspicious: Multiple phishing signs")
        self.assertGreater(len(result["matched_patterns"]), 1)

    @patch("utils.phishing_scanner.PhishingScanner.extract_text")
    @patch("utils.phishing_scanner.PhishingScanner.scan_url_with_virustotal")
    def test_phishing_scanner_phishing_email(self, mock_scan_url, mock_extract_text):
        mock_extract_text.return_value = "Your account has been suspended. Click here: http://malicious.link. Verify your account now. Urgent action required. Password reset needed."
        mock_scan_url.return_value = (
            {"malicious": 1, "suspicious": 0, "harmless": 0},
            None,
        )

        scanner = PhishingScanner()
        result, error = scanner.scan_email("dummy_file_path")

        self.assertEqual(result["verdict"], "🛑 High Risk: Likely phishing")
        self.assertGreater(len(result["matched_patterns"]), 0)
        self.assertEqual(len(result["links"]), 1)


if __name__ == "__main__":
    unittest.main()
