import pytesseract
from PIL import Image
from pdf2image import convert_from_path
import os
import re
import requests
from datetime import datetime

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

VT_API_KEY = ""


class PhishingScanner:

    def __init__(
        self,
    ):  # Reference:https://github.com/simplerhacking/Phishing-Keyword-List
        self.keyword_patterns = [
            r"click\s+(here|this\s+link)",
            r"verify\s+(your\s+)?account",
            r"(update|reset|confirm).{0,20}(account|password|info)",
            r"(password).{0,10}(will|is).{0,10}(expire|expiring)",
            r"follow\s+the\s+link",
            r"security\s+(alert|notice|warning)",
            r"your\s+account\s+(has\s+)?(been\s+)?(suspended|deactivated)",
            r"login\s+(required|now)",
            r"urgent\s+(action|update)",
            r"renew\s+(your\s+)?(password|account)",
            r"limited\s+time\s+(access|offer)",
            r"http[s]?://[^\s]+",
        ]
        self.friendly_terms = {
            self.keyword_patterns[0]: "click here",
            self.keyword_patterns[1]: "verify account",
            self.keyword_patterns[2]: "account or password update",
            self.keyword_patterns[3]: "password will expire",
            self.keyword_patterns[4]: "follow the link",
            self.keyword_patterns[5]: "security alert",
            self.keyword_patterns[6]: "account suspended",
            self.keyword_patterns[7]: "login required",
            self.keyword_patterns[8]: "urgent request",
            self.keyword_patterns[9]: "renew password",
            self.keyword_patterns[10]: "limited time offer",
            self.keyword_patterns[11]: "external link",
        }

    def extract_text(self, file_path):
        ext = os.path.splitext(file_path)[1].lower()
        if ext in [".png", ".jpg", ".jpeg"]:
            return pytesseract.image_to_string(Image.open(file_path))
        elif ext == ".pdf":
            pages = convert_from_path(file_path)
            return "\n".join(pytesseract.image_to_string(p) for p in pages)
        return None

    def scan_url_with_virustotal(self, url):
        headers = {"x-apikey": VT_API_KEY}
        try:
            res = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
            )
            if res.status_code != 200:
                return None, f"Submit error {res.status_code}"
            scan_id = res.json()["data"]["id"]
            result = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers
            )
            if result.status_code != 200:
                return None, f"Fetch error {result.status_code}"
            stats = result.json()["data"]["attributes"]["stats"]
            return stats, None
        except Exception as e:
            return None, str(e)

    def scan_email(self, file_path):
        text = self.extract_text(file_path)
        if not text:
            return None, "Unsupported file type or OCR failed."

        matched = []
        for pattern in self.keyword_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matched.append(pattern)

        links = re.findall(r"https?://[^\s]+", text)
        vt_result, vt_error = (None, None)
        if links:
            vt_result, vt_error = self.scan_url_with_virustotal(links[0])

        score = len(matched)
        verdict = (
            "🛑 High Risk: Likely phishing"
            if score >= 5
            else (
                "⚠️ Suspicious: Multiple phishing signs"
                if score >= 3
                else "⚠️ Low Risk" if score > 0 else "✅ Safe"
            )
        )

        return {
            "verdict": verdict,
            "matched_patterns": matched,
            "preview": text[:800].strip(),
            "links": links,
            "vt_result": vt_result,
            "vt_error": vt_error,
        }, None

    def format_result(self, result):
        lines = []
        lines.append(f"📅 Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"\n🛡️ Verdict: {result['verdict']}\n")

        if result["matched_patterns"]:
            lines.append("🚨 Suspicious Phrases Detected:")
            for pattern in result["matched_patterns"]:
                label = self.friendly_terms.get(pattern, pattern)
                lines.append(f"  - {label}")
        else:
            lines.append("✅ No suspicious patterns found.")

        if result["links"]:
            lines.append(f"\n🔗 Link Found:")
            lines.append(f"  - {result['links'][0]}")
            if result["vt_result"]:
                vt = result["vt_result"]
                lines.append(
                    f"   🧪 VirusTotal — Malicious: {vt.get('malicious',0)}, Suspicious: {vt.get('suspicious',0)}, Harmless: {vt.get('harmless',0)}"
                )
            elif result["vt_error"]:
                lines.append(f"   ⚠️ VT Error: {result['vt_error']}")

        lines.append("\n📄 Email Text Preview:")
        lines.append(result["preview"])
        lines.append(
            "\n Analysis based on OCR and regex (please note this tool provides recommendations and is not 100% accurate)"
        )
        return "\n".join(lines)
