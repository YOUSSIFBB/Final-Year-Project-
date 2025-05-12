import unittest
from utils.url_scanner import URLScanner
import os


class TestURLScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = URLScanner()  # scanner object

    def test_url_scanner_safe_url(self):
        # Test with a known safe URL
        result, error = self.scanner.scan("https://www.example.com")

        self.assertIsNotNone(result)
        self.assertIsNone(error)
        stats = result.get("data", {}).get("attributes", {}).get("stats", {})
        self.assertGreaterEqual(stats.get("harmless", 0), 1)

    def test_url_scanner_malicious_url(self):
        # Test with a known malicious URL (VirusTotal Test URL)
        result, error = self.scanner.scan("https://www.testmalicious.com")

        self.assertIsNotNone(result)
        self.assertIsNone(error)
        stats = result.get("data", {}).get("attributes", {}).get("stats", {})
        self.assertGreater(stats.get("malicious", 0), 0)

    def test_url_scanner_invalid_url(self):
        # Test with an invalid URL
        result, error = self.scanner.scan("URL")

        self.assertIsNone(result)
        self.assertIsNotNone(error)


if __name__ == "__main__":
    unittest.main()
