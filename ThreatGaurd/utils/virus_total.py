import requests
import time
import os
import hashlib

API_KEY = "56c33f60080c531466befc122e765ca92677231af7aae620af3e2642b4a3f936"


def get_file_hashes(filepath):
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hashes.items()}


def scan_file(filepath):
    headers = {"x-apikey": API_KEY}

    with open(filepath, "rb") as file:
        upload_response = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files={"file": file},
        )

    if upload_response.status_code != 200:
        try:
            error_message = (
                upload_response.json().get("error", {}).get("message", "No details")
            )
        except:
            error_message = upload_response.text
        return None, f"Upload failed ({upload_response.status_code}): {error_message}"

    scan_id = upload_response.json()["data"]["id"]

    # Poll for results
    for attempt in range(20):  # up to 20 tries
        time.sleep(3)  # wait between polls
        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
            headers=headers,
        )
        if analysis_response.status_code != 200:
            continue

        result = analysis_response.json()
        status = result["data"]["attributes"]["status"]

        if status == "completed":
            return result, None
        elif status == "queued":
            print(f"Attempt {attempt+1}: still queued...")
        elif status == "in-progress":
            print(f"Attempt {attempt+1}: still scanning...")

    return None, "Scan timed out after waiting for VirusTotal analysis."
