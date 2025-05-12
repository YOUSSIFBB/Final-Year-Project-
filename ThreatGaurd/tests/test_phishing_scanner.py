import unittest
from utils.phishing_scanner import PhishingScanner
from PIL import Image, ImageDraw
import os


class TestPhishingScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = PhishingScanner()

        # Ensure the assets directory exists
        os.makedirs("assets", exist_ok=True)

        # Automatically create test images with visible text
        self.create_test_image(
            "assets/sample_safe_email.png", "This is a safe email with no threats."
        )
        self.create_test_image(
            "assets/sample_suspicious_email.png", "Urgent action required. Click here."
        )
        self.create_test_image(
            "assets/sample_phishing_email.png",
            "Your account has been suspended. Click here to verify your account.",
        )

    def create_test_image(self, file_path, text):
        if not os.path.exists(file_path):
            img = Image.new("RGB", (500, 300), color="white")
            d = ImageDraw.Draw(img)
            d.text((10, 10), text, fill=(0, 0, 0))
            img.save(file_path)

    def test_phishing_scanner_safe_email(self):
        result, error = self.scanner.scan_email("assets/sample_safe_email.png")

        self.assertIsNotNone(result)
        self.assertIsNone(error)
        self.assertIn("✅ Safe", result["verdict"], "Expected a safe email.")

    def test_phishing_scanner_suspicious_email(self):
        result, error = self.scanner.scan_email("assets/sample_suspicious_email.png")

        self.assertIsNotNone(result)
        self.assertIsNone(error)
        self.assertIn("⚠️ Suspicious", result["verdict"])

    def test_phishing_scanner_phishing_email(self):
        result, error = self.scanner.scan_email("assets/sample_phishing_email.png")

        self.assertIsNotNone(result)
        self.assertIsNone(error)
        self.assertIn("🛑 High Risk", result["verdict"])

    def test_phishing_scanner_invalid_file(self):
        # Using a non-existent file path
        result, error = self.scanner.scan_email("assets/non_existent_file.png")

        self.assertIsNone(result)
        self.assertIsNotNone(error)


if __name__ == "__main__":
    unittest.main()
