import requests
import time
from utils.virus_total import API_KEY  # or update if it's somewhere else


class URLScanner:
    def __init__(self):
        self.headers = {"x-apikey": API_KEY}

    def scan(self, url):
        try:
            response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=self.headers,
                data={"url": url},
            )
            if response.status_code != 200:
                return None, f"URL submission failed: {response.status_code}"

            scan_id = response.json()["data"]["id"]
        except Exception as e:
            return None, f"Submission error: {str(e)}"

        for _ in range(20):
            time.sleep(3)
            try:
                result_response = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                    headers=self.headers,
                )
                if result_response.status_code != 200:
                    continue

                result = result_response.json()
                if result["data"]["attributes"]["status"] == "completed":
                    return result, None
            except Exception as e:
                return None, f"Polling error: {str(e)}"

        return None, "Scan timed out after 60 seconds."
