import unittest
from unittest.mock import patch, mock_open
from utils.file_scanner import FileScanner


class TestFileScanner(unittest.TestCase):

    @patch(
        "utils.virus_total.open",
        new_callable=mock_open,
        read_data=b"dummy file content",
    )
    @patch("utils.virus_total.scan_file")
    @patch("utils.virus_total.get_file_hashes")
    def test_scan_safe_file(self, mock_get_hashes, mock_scan_file, mock_file):
        mock_scan_file.return_value = (
            {
                "data": {
                    "attributes": {
                        "stats": {
                            "harmless": 61,
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 0,
                        },
                        "results": {},
                    }
                }
            },
            None,
        )
        mock_get_hashes.return_value = {
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }

        scanner = FileScanner()
        result, error = scanner.scan("dummy_path")

        self.assertIn("Scan Result: Safe", result)
        self.assertIsNone(error)


if __name__ == "__main__":
    unittest.main()
