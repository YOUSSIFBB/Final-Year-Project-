import unittest
from unittest.mock import patch, MagicMock
from utils.url_scanner import URLScanner


class TestURLScanner(unittest.TestCase):

    @patch("requests.post")
    @patch("requests.get")
    def test_url_scanner_safe_url(self, mock_get, mock_post):
        # Mock API response for URL submission
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"data": {"id": "mock_scan_id"}}

        # Mock API response for URL scan result
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "harmless": 5,
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 10,
                    },
                    "results": {},
                }
            }
        }

        scanner = URLScanner()
        result, error = scanner.scan("https://safe-url.com")

        self.assertIsNotNone(result)
        self.assertIsNone(error)
        self.assertEqual(result["data"]["attributes"]["stats"]["malicious"], 0)

    @patch("requests.post")
    @patch("requests.get")
    def test_url_scanner_malicious_url(self, mock_get, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"data": {"id": "mock_scan_id"}}

        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "harmless": 0,
                        "malicious": 5,
                        "suspicious": 0,
                        "undetected": 5,
                    },
                    "results": {"Engine1": {"category": "malicious"}},
                }
            }
        }

        scanner = URLScanner()
        result, error = scanner.scan("https://malicious-url.com")

        self.assertIsNotNone(result)
        self.assertIsNone(error)
        self.assertEqual(result["data"]["attributes"]["stats"]["malicious"], 5)

    @patch("requests.post")
    @patch("requests.get")
    def test_url_scanner_api_error(self, mock_get, mock_post):
        mock_post.return_value.status_code = 500

        scanner = URLScanner()
        result, error = scanner.scan("https://broken-url.com")

        self.assertIsNone(result)
        self.assertIn("URL submission failed", error)


if __name__ == "__main__":
    unittest.main()
