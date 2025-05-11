import os
from utils.virus_total import scan_file, get_file_hashes


class FileScanner:
    def scan(self, file_path):
        result, error = scan_file(file_path)
        if error:
            return None, error

        stats = result["data"]["attributes"]["stats"]
        hashes = get_file_hashes(file_path)
        verdict = "Safe"
        if stats["malicious"] > 0:
            verdict = "Malicious"
        elif stats["suspicious"] > 0:
            verdict = "Suspicious"

        vendors = result["data"]["attributes"]["results"]
        top_detections = []
        for engine, info in vendors.items():
            category = info.get("category")
            result_name = info.get("result")
            if category in ("malicious", "suspicious") and result_name:
                top_detections.append(f"{engine}: {result_name}")
        top_detections = top_detections[:5]

        vendor_output = (
            "\n".join([f"- {v}" for v in top_detections])
            if top_detections
            else "- No malicious detections reported by vendors."
        )

        total_engines = (
            stats["harmless"]
            + stats["malicious"]
            + stats["suspicious"]
            + stats["undetected"]
        )

        if stats["malicious"] > 0:
            threat_summary = "⚠️ Detected as MALICIOUS by multiple engines. Immediate attention recommended."
        elif stats["suspicious"] > 0:
            threat_summary = (
                "⚠️ Marked as SUSPICIOUS by some engines. Proceed with caution."
            )
        elif stats["harmless"] > 0:
            threat_summary = "✅ Verified as harmless by some antivirus engines."
        else:
            threat_summary = (
                "🟢 No threats reported. Most engines returned 'undetected'."
            )
        # Leave this like this because the indentation is effected in the UI
        result_output = f"""
Scan Result: {verdict}

Detection Insights:
{threat_summary}

📄 Stats Breakdown (from {total_engines} engines):
- Harmless:    {stats['harmless']}
- Malicious:   {stats['malicious']}
- Suspicious:  {stats['suspicious']}
- Undetected:  {stats['undetected']}

File Hashes:
- MD5:    {hashes['md5']}
- SHA1:   {hashes['sha1']}
- SHA256: {hashes['sha256']}

Detected by:
{vendor_output}
"""
        return result_output, None
