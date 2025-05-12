import unittest
import os
from utils.file_scanner import FileScanner


class TestFileScanner(
    unittest.TestCase
):  # Please carfeful when running this tests, its fragile

    def setUp(self):
        # Ensure the assets directory exists
        os.makedirs("assets", exist_ok=True)

        # Create a test file for uploading
        self.test_file_path = "assets/test_file.txt"
        with open(self.test_file_path, "w") as f:
            f.write("This is a test file for scanning.")

        self.scanner = FileScanner()  # Initialize the real FileScanner

    def tearDown(self):
        # Clean up test file after testing
        if os.path.exists(self.test_file_path):
            os.remove(self.test_file_path)

    def test_file_upload(self):
        # Test if the FileScanner can upload and scan the file
        result, error = self.scanner.scan(self.test_file_path)

        self.assertIsNotNone(result)
        self.assertIsNone(error)
        self.assertIn("Scan Result:", result)


if __name__ == "__main__":
    unittest.main()
