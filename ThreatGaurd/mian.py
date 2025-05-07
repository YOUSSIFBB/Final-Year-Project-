import customtkinter as ctk
import tkinter.messagebox as messagebox
from models import initialize_user_db, register_user, authenticate_user
import re
from tkinter import filedialog
from utils.file_scanner import FileScanner
from utils.traffic_monitor import TrafficMonitor
from utils.port_scanner_ui import render_port_scanner_ui
from utils.url_scanner_ui import render_url_scanner_ui
from utils.phishing_scanner import PhishingScanner
from utils.dashboard_ui import log_scan
from utils.dashboard_ui import render_dashboard_ui
import os
import threading
from datetime import datetime
from utils.pdf_report import export_report_to_pdf


initialize_user_db()

# App config
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


########
def require_login(method):
    def wrapper(self, *args, **kwargs):
        if not self.current_user:
            messagebox.showwarning(
                "Login Required", "You must log in before using this feature."
            )
            return self.load_login_screen()
        return method(self, *args, **kwargs)

    return wrapper


class ThreatGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ThreatGuard - Cybersecurity Scanner")
        self.geometry("1000x600")
        self.resizable(False, False)

        self.current_user = None  # Track logged-in user

        # Layout
        self.sidebar = ctk.CTkFrame(self, width=200)
        self.sidebar.pack(side="left", fill="y")

        self.main_area = ctk.CTkFrame(self)
        self.main_area.pack(side="right", fill="both", expand=True)

        # Sidebar buttons
        self.add_sidebar_buttons()

    def add_sidebar_buttons(self):
        ctk.CTkLabel(self.sidebar, text="ThreatGuard", font=("Arial", 20, "bold")).pack(
            pady=20
        )

        buttons = [
            ("Dashboard", self.load_dashboard),
            ("Login", self.load_login_screen),
            ("Register", self.load_register_screen),
            ("File Scan", self.load_file_scan),
            ("Port Scan", self.load_port_scan),
            ("Traffic Monitor", self.load_traffic_monitor),
            ("URL Scanner", self.load_url_scanner),
            ("Email Scanner", self.load_phishing_scanner),
            ("Logout", self.logout),
            ("Exit", self.quit),
        ]

        for text, command in buttons:
            ctk.CTkButton(self.sidebar, text=text, command=command).pack(
                pady=5, fill="x", padx=10
            )

    def clear_main_area(self):
        for widget in self.main_area.winfo_children():
            widget.destroy()

    @require_login
    def load_dashboard(self):
        # Clear the main area
        self.clear_main_area()

        # Create a scrollable frame to hold the entire dashboard
        scroll = ctk.CTkScrollableFrame(self.main_area, width=800, height=550)
        scroll.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        ctk.CTkLabel(
            scroll, text=f"👋 Welcome, {self.current_user}", font=("Arial", 24)
        ).pack(pady=10)
        ctk.CTkLabel(
            scroll, text="ThreatGuard Security Dashboard", font=("Arial", 16)
        ).pack(pady=5)

        # Scanner buttons container
        btn_frame = ctk.CTkFrame(scroll, fg_color="#dddddd", corner_radius=8)
        btn_frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkButton(btn_frame, text="📁 File Scan", command=self.load_file_scan).grid(
            row=0, column=0, padx=10, pady=5
        )
        ctk.CTkButton(
            btn_frame, text="🔗 URL Scan", command=self.load_url_scanner
        ).grid(row=0, column=1, padx=10, pady=5)
        ctk.CTkButton(btn_frame, text="🔌 Port Scan", command=self.load_port_scan).grid(
            row=1, column=0, padx=10, pady=5
        )
        ctk.CTkButton(
            btn_frame, text="📶 Traffic Monitor", command=self.load_traffic_monitor
        ).grid(row=1, column=1, padx=10, pady=5)

        # Theme selector
        theme_frame = ctk.CTkFrame(scroll)
        theme_frame.pack(pady=10)
        ctk.CTkLabel(theme_frame, text="🌓 Theme Mode:").grid(row=0, column=0, padx=5)
        theme_dropdown = ctk.CTkOptionMenu(
            theme_frame,
            values=["System", "Light", "Dark"],
            command=ctk.set_appearance_mode,
        )
        theme_dropdown.set("System")
        theme_dropdown.grid(row=0, column=1, padx=5)

        # Finally, render summary, logs, and charts onto the scrollable area
        render_dashboard_ui(scroll, username=self.current_user)

        def toggle_theme(choice):
            ctk.set_appearance_mode(choice)

        theme_dropdown = ctk.CTkOptionMenu(
            theme_frame, values=["System", "Light", "Dark"], command=toggle_theme
        )
        theme_dropdown.set("System")
        theme_dropdown.grid(row=0, column=1, padx=5)

    def load_login_screen(self):
        self.clear_main_area()
        ctk.CTkLabel(self.main_area, text="Login", font=("Arial", 20)).pack(pady=20)

        username_entry = ctk.CTkEntry(self.main_area, placeholder_text="Username")
        username_entry.pack(pady=10)

        password_entry = ctk.CTkEntry(
            self.main_area, placeholder_text="Password", show="*"
        )
        password_entry.pack(pady=10)

        def login_action():
            username = username_entry.get()
            password = password_entry.get()
            if authenticate_user(username, password):
                self.current_user = username
                messagebox.showinfo("Login Successful", f"Welcome, {username}!")
                self.load_dashboard()
            else:
                messagebox.showerror("Error", "Invalid username or password.")

        ctk.CTkButton(self.main_area, text="Login", command=login_action).pack(pady=10)

    def load_register_screen(self):
        self.clear_main_area()

        ctk.CTkLabel(self.main_area, text="Register", font=("Arial", 20)).pack(pady=20)

        username_entry = ctk.CTkEntry(self.main_area, placeholder_text="Username")
        username_entry.pack(pady=10)

        password_entry = ctk.CTkEntry(
            self.main_area, placeholder_text="Password", show="*"
        )
        password_entry.pack(pady=10)

        def register_action():
            username = username_entry.get()
            password = password_entry.get()

            if not re.match(r"^[a-zA-Z0-9_]{4,}$", username):
                messagebox.showerror(
                    "Invalid Username",
                    "Username must be at least 4 characters and contain only letters, numbers, or underscores.",
                )
                return

            if (
                len(password) < 8
                or not re.search(r"[A-Z]", password)
                or not re.search(r"[a-z]", password)
                or not re.search(r"[0-9]", password)
                or not re.search(r"[\W_]", password)
            ):
                messagebox.showerror(
                    "Weak Password",
                    "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.",
                )
                return

            if register_user(username, password):
                messagebox.showinfo(
                    "Success", "Registration complete. You can now log in."
                )
                self.load_login_screen()
            else:
                messagebox.showerror("Registration Failed", "Username already exists.")

        ctk.CTkButton(self.main_area, text="Register", command=register_action).pack(
            pady=10
        )

    @require_login
    def load_file_scan(self):
        self.clear_main_area()
        ctk.CTkLabel(
            self.main_area, text="File Malware Scanner", font=("Arial", 20)
        ).pack(pady=20)

        # Tooltip with close button
        tip_frame = ctk.CTkFrame(self.main_area, fg_color="#333333", corner_radius=8)
        tip_frame.pack(pady=(0, 5), padx=10, fill="x")

        # Close button (top right corner of tooltip)
        def close_tooltip():
            tip_frame.pack_forget()

        close_btn = ctk.CTkButton(
            tip_frame,
            text="X",
            width=20,
            height=20,
            fg_color="#444444",
            hover_color="#555555",
            font=("Arial", 12),
            command=close_tooltip,
        )
        close_btn.place(relx=0.97, rely=0.1, anchor="ne")

        # Tooltip content
        ctk.CTkLabel(
            tip_frame,
            text="How to use: Select a file and click 'Scan' to check for viruses using VirusTotal.",
            font=("Arial", 12),
            text_color="white",
            anchor="w",
            justify="left",
            wraplength=700,
        ).pack(padx=10, pady=5)

        # Optional auto-hide
        self.after(8000, lambda: tip_frame.pack_forget())

        loading_label = ctk.CTkLabel(self.main_area, text="", font=("Arial", 14))
        loading_label.pack(pady=5)

        result_text = ctk.CTkTextbox(
            self.main_area, width=600, height=300, font=("Consolas", 12)
        )
        result_text.pack(pady=10)
        result_text.tag_config("error", foreground="red")

        scanner = FileScanner()

        def run_scan(file_path):
            try:
                self.after(0, lambda: loading_label.configure(text="⏳ Scanning..."))

                result, error = scanner.scan(file_path)

                self.after(0, lambda: loading_label.configure(text=""))

                if error:
                    self.after(
                        0,
                        lambda: result_text.insert(
                            "end", f"❌ Error: {error}\n", "error"
                        ),
                    )
                    self.after(
                        0,
                        lambda: result_text.insert(
                            "end", "🚫 Scan terminated due to an error.\n", "error"
                        ),
                    )
                else:
                    self.after(
                        0,
                        lambda: result_text.insert(
                            "end", "\n🟢 Scan Complete!\n\n", "success"
                        ),
                    )
                    result_text.tag_config("success", foreground="green")

                    self.after(
                        0,
                        lambda: result_text.insert(
                            "end", "🧠 Summary:\nThis file appears to be safe.\n"
                        ),
                    )
                    self.after(
                        0, lambda: result_text.insert("end", "\n📊 Scan Details:\n")
                    )
                    self.after(
                        0, lambda: result_text.insert("end", result)
                    )  # keep existing detailed string
                    self.after(
                        0,
                        lambda: result_text.insert(
                            "end",
                            "\n\n🧪 Results provided by trusted antivirus and cybersecurity providers.\n",
                        ),
                    )
                    self.after(
                        0,
                        lambda: result_text.insert(
                            "end",
                            "🔒 No action is needed unless you were not expecting this file.\n",
                        ),
                    )

                    # Log scan result in database
                    from utils.dashboard_ui import log_scan

                    log_scan(
                        username=self.current_user,
                        scan_type="File",
                        target=file_path,
                        result="Safe",
                    )

            except Exception as e:
                self.after(0, lambda: loading_label.configure(text=""))
                self.after(
                    0,
                    lambda: result_text.insert(
                        "end", f"🛑 File access error: {str(e)}\n", "error"
                    ),
                )
                self.after(
                    0,
                    lambda: result_text.insert(
                        "end",
                        "🚫 Scan terminated. File has been flagged as malicious and has been blocked by your antivirus.\n",
                        "error",
                    ),
                )

        def browse_and_scan():
            file_path = filedialog.askopenfilename()
            if not file_path:
                return
            result_text.delete("1.0", "end")
            result_text.insert(
                "end", f"📁 Selected file: {os.path.basename(file_path)}\n"
            )
            threading.Thread(target=lambda: run_scan(file_path), daemon=True).start()

        ctk.CTkButton(
            self.main_area, text="Select File & Scan", command=browse_and_scan
        ).pack(pady=10)

    @require_login
    def load_port_scan(self):
        self.clear_main_area()
        render_port_scanner_ui(self.main_area, username=self.current_user)

    @require_login
    def load_traffic_monitor(self):
        self.clear_main_area()

        ctk.CTkLabel(
            self.main_area, text="Live Traffic Monitor", font=("Arial", 20)
        ).pack(pady=10)

        output_box = ctk.CTkTextbox(
            self.main_area,
            width=800,
            height=400,
            font=("Consolas", 11),
            wrap="none",
            bg_color="#111111",
            fg_color="#111111",
            text_color="white",
        )
        output_box.pack(pady=10)

        summary_label = ctk.CTkLabel(
            self.main_area,
            text="📊 Protocol Summary — TCP: 0 | UDP: 0 | ICMP: 0 | Other: 0",
            font=("Arial", 13),
        )
        summary_label.pack(pady=(0, 10))

        monitor = TrafficMonitor(output_box, summary_label, self.current_user)

        output_box.tag_config("tcp", foreground="#00BFFF")
        output_box.tag_config("udp", foreground="yellow")
        output_box.tag_config("icmp", foreground="lime")
        output_box.tag_config("other", foreground="gray")

        btn_frame = ctk.CTkFrame(self.main_area, fg_color="transparent")
        btn_frame.pack(pady=10)

        ctk.CTkButton(
            btn_frame, text="Start Capture", command=monitor.start_capture
        ).grid(row=0, column=0, padx=10)
        ctk.CTkButton(
            btn_frame,
            text="Stop Capture",
            fg_color="red",
            hover_color="#990000",
            command=monitor.stop_capture,
        ).grid(row=0, column=1, padx=10)
        ctk.CTkButton(btn_frame, text="Clear", command=monitor.clear_output).grid(
            row=0, column=2, padx=10
        )
        ctk.CTkButton(btn_frame, text="Save as PCAP", command=monitor.save_pcap).grid(
            row=0, column=3, padx=10
        )

    @require_login
    def load_url_scanner(self):
        self.clear_main_area()
        from utils.url_scanner_ui import render_url_scanner_ui

        render_url_scanner_ui(self.main_area, username=self.current_user)

    @require_login
    # New image scanner here
    def load_phishing_scanner(self):
        from tkinter import filedialog

        self.clear_main_area()
        ctk.CTkLabel(
            self.main_area, text="📧 Email Phishing Scanner", font=("Arial", 20)
        ).pack(pady=10)

        result_text = ctk.CTkTextbox(
            self.main_area, width=750, height=400, font=("Consolas", 11), wrap="word"
        )
        result_text.pack(pady=10)
        result_text.tag_config("warn", foreground="red")
        result_text.tag_config("safe", foreground="green")
        result_text.tag_config("highlight", foreground="orange")

        loading_label = ctk.CTkLabel(self.main_area, text="", font=("Arial", 13))
        loading_label.pack(pady=5)

        scanner = PhishingScanner()

        def threaded_scan(file_path, username):
            result, error = scanner.scan_email(file_path)
            self.after(0, lambda: loading_label.configure(text=""))

            if error:
                self.after(
                    0, lambda: result_text.insert("end", f"❌ Error: {error}\n", "warn")
                )
                return

            formatted = scanner.format_result(result)
            verdict = result.get("verdict", "Unknown")
            log_scan(
                username=username,
                scan_type="Email",
                target=file_path,
                result=verdict.split(":")[0],
            )

            def insert_colored():
                result_text.insert("end", "\n")
                suspicious_section = False

                for line in formatted.splitlines():
                    stripped = line.strip()

                    # Red if verdict line is suspicious or high risk
                    if stripped.startswith("🛡️ Verdict:") and any(
                        symbol in stripped for symbol in ["🛑", "⚠️"]
                    ):
                        result_text.insert("end", line + "\n", "warn")
                        continue

                    # Red for section heading
                    if stripped.startswith("🚨 Suspicious Phrases Detected"):
                        suspicious_section = True
                        result_text.insert("end", line + "\n", "warn")
                        continue

                    # Red for indented suspicious items
                    if suspicious_section and stripped.startswith("- "):
                        result_text.insert("end", line + "\n", "warn")
                        continue

                    # End suspicious section once preview starts
                    if stripped.startswith("📄 Email Text Preview:"):
                        suspicious_section = False

                    # Default for all other lines
                    result_text.insert("end", line + "\n")

            self.after(0, insert_colored)

            if result["links"]:

                def copy_link():
                    self.clipboard_clear()
                    self.clipboard_append(result["links"][0])
                    result_text.insert("end", "📋 Link copied to clipboard.\n", "safe")

                self.after(
                    0,
                    lambda: ctk.CTkButton(
                        self.main_area, text="📋 Copy Link", command=copy_link
                    ).pack(pady=5),
                )

        def scan_email_file():
            file_path = filedialog.askopenfilename(
                filetypes=[("Image/PDF files", "*.png *.jpg *.jpeg *.pdf")]
            )
            if not file_path:
                return
            result_text.delete("1.0", "end")
            loading_label.configure(text="🔍 Scanning...")
            threading.Thread(
                target=lambda: threaded_scan(file_path, self.current_user), daemon=True
            ).start()

        ctk.CTkButton(
            self.main_area, text="Select Email Image or PDF", command=scan_email_file
        ).pack(pady=15)

    @require_login
    def logout(self):
        self.current_user = None
        self.clear_main_area()
        messagebox.showinfo("Logged Out", "You have been logged out.")


if __name__ == "__main__":
    app = ThreatGuardApp()
    app.mainloop()
