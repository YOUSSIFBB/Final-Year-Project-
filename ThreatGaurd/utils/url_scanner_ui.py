import threading
import customtkinter as ctk
from utils.url_scanner import URLScanner
from utils.web_screenshot import get_screenshot_image
from PIL import Image, ImageTk
import io


def render_url_scanner_ui(parent_frame):
    scanner = URLScanner()

    ctk.CTkLabel(parent_frame, text="🔗 URL Scanner", font=("Arial", 20)).pack(pady=10)

    url_entry = ctk.CTkEntry(
        parent_frame, placeholder_text="Enter a URL to scan", width=600
    )
    url_entry.pack(pady=10)

    result_text = ctk.CTkTextbox(
        parent_frame,
        width=750,
        height=350,
        font=("Consolas", 11),
        wrap="word",
        bg_color="#111111",
        fg_color="#111111",
        text_color="white",
    )
    result_text.pack(pady=10)
    result_text.tag_config("warn", foreground="red")

    def run_scan():
        url = url_entry.get().strip()
        result_text.delete("1.0", "end")

        if not url.startswith("http://") and not url.startswith("https://"):
            result_text.insert(
                "end",
                "⚠ Please enter a valid URL starting with http:// or https://\n",
                "warn",
            )
            return

        result_text.insert("end", f"🔎 Submitting URL to VirusTotal...\n")
        result_text.update()

        result, error = scanner.scan(url)
        if error:
            result_text.insert("end", f"❌ Error: {error}\n", "warn")
            return

        stats = result["data"]["attributes"]["stats"]
        vendors = result["data"]["attributes"]["results"]

        harmless = stats.get("harmless", 0)
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)

        # Verdict summary
        if malicious >= 5:
            verdict = "🛑 High Risk: This link is likely unsafe!"
        elif malicious >= 2 or suspicious >= 2:
            verdict = "⚠️ Moderate Risk: This link may be suspicious."
        elif malicious > 0 or suspicious > 0:
            verdict = "⚠️ Low Risk: Some vendors flagged this link."
        else:
            verdict = (
                "✅ Safe: No vendors reported this link as malicious or suspicious."
            )

        result_text.insert("end", f"\n🔍 Scan Summary:\n")
        result_text.insert("end", f"✅ Harmless: {harmless}\n")
        result_text.insert("end", f"🚫 Malicious: {malicious}\n")
        result_text.insert("end", f"⚠ Suspicious: {suspicious}\n")
        result_text.insert("end", f"❓ Undetected: {undetected}\n\n")

        result_text.insert("end", f"{verdict}\n\n", "verdict")
        result_text.tag_config(
            "verdict", foreground="red" if "Risk" in verdict else "green"
        )

        # Group vendors
        malicious_vendors = []
        suspicious_vendors = []
        for vendor, details in vendors.items():
            category = details.get("category", "undetected")
            if category == "malicious":
                malicious_vendors.append((vendor, category))
            elif category == "suspicious":
                suspicious_vendors.append((vendor, category))

        if malicious_vendors or suspicious_vendors:
            result_text.insert("end", "🚨 Vendors Flagging This URL:\n")
            for vendor, category in malicious_vendors + suspicious_vendors:
                result_text.insert("end", f"  - {vendor}: {category.upper()}\n", "warn")
            result_text.insert("end", "\n")

        result_text.tag_config("warn", foreground="red")

        # Full vendor breakdown
        result_text.insert("end", "📋 Full Vendor Report:\n")
        for vendor, details in vendors.items():
            category = details.get("category", "undetected")
            result_text.insert("end", f"  - {vendor}: {category}\n")

        # Info about sources
        result_text.insert(
            "end",
            "\n🧪 This report is based on analysis by over 90 trusted security vendors.\n",
        )

    def show_screenshot():
        url = url_entry.get().strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            result_text.insert("end", "⚠ Invalid URL for screenshot\n", "warn")
            return

        result_text.insert("end", "📸 Fetching screenshot from ScrapFly...\n")
        result_text.update()

        def fetch_and_show():
            img_data, err = get_screenshot_image(url)
            if err:
                result_text.insert("end", f"❌ Error: {err}\n", "warn")
                return

            img = Image.open(io.BytesIO(img_data))
            img = img.resize((600, 400))  # Resize for visibility
            from customtkinter import CTkImage

            img_tk = CTkImage(light_image=img, size=(600, 400))

            top = ctk.CTkToplevel()
            top.title("🌐 Webpage Screenshot")
            label = ctk.CTkLabel(top, image=img_tk, text="")
            label.image = img_tk  # Prevent garbage collection
            label.pack(padx=10, pady=10)

        threading.Thread(target=fetch_and_show, daemon=True).start()

    # Buttons
    button_frame = ctk.CTkFrame(parent_frame)
    button_frame.pack(pady=10)

    ctk.CTkButton(
        button_frame,
        text="Scan URL",
        command=lambda: threading.Thread(target=run_scan, daemon=True).start(),
    ).grid(row=0, column=0, padx=10)

    ctk.CTkButton(
        button_frame,
        text="📸 View Webpage Screenshot",
        command=show_screenshot,
    ).grid(row=0, column=1, padx=10)
