import customtkinter as ctk
import socket
import threading
from datetime import datetime
from utils.dashboard_ui import log_scan


def render_port_scanner_ui(parent_frame, username="Guest"):
    ctk.CTkLabel(parent_frame, text="Local Port Scanner", font=("Arial", 20)).pack(
        pady=10
    )

    # Port Range Dropdown
    ctk.CTkLabel(parent_frame, text="Select Port Range:", font=("Arial", 14)).pack()
    range_var = ctk.StringVar(value="0–600")
    port_ranges = {
        "0–600": (0, 600),
        "601–1000": (601, 1000),
        "1001–5000": (1001, 5000),
    }
    ctk.CTkOptionMenu(
        parent_frame, variable=range_var, values=list(port_ranges.keys())
    ).pack(pady=5)

    # Result Text
    result_text = ctk.CTkTextbox(
        parent_frame,
        width=650,
        height=350,
        font=("Consolas", 12),
        bg_color="#1e1e1e",
        fg_color="#1e1e1e",
        text_color="white",
    )
    result_text.pack(pady=10)

    # Status + Progress
    status_label = ctk.CTkLabel(parent_frame, text="", font=("Arial", 14))
    status_label.pack(pady=(0, 5))

    progress_bar = ctk.CTkProgressBar(parent_frame, width=400)
    progress_bar.set(0)
    progress_bar.pack(pady=5)

    cancel_flag = {"stop": False}

    port_info = {
        21: ("FTP", "File Transfer Protocol", "TCP", "Medium"),
        22: ("SSH", "Secure Shell", "TCP", "Medium"),
        23: ("Telnet", "Remote login (insecure)", "TCP", "High"),
        25: ("SMTP", "Email Sending", "TCP", "Medium"),
        53: ("DNS", "Domain Name System", "TCP/UDP", "Low"),
        80: ("HTTP", "Web traffic", "TCP", "Medium"),
        110: ("POP3", "Email Receiving", "TCP", "Medium"),
        135: ("RPC", "Remote Procedure Call", "TCP", "Medium"),
        139: ("NetBIOS", "Windows File Sharing", "TCP", "High"),
        143: ("IMAP", "Email Receiving (IMAP)", "TCP", "Medium"),
        443: ("HTTPS", "Secure Web", "TCP", "Low"),
        445: ("SMB", "Windows File Sharing", "TCP", "High"),
        3306: ("MySQL", "Database service", "TCP", "High"),
        3389: ("RDP", "Remote Desktop", "TCP", "High"),
        5900: ("VNC", "Remote GUI access", "TCP", "High"),
    }

    def scan_ports():
        result_text.delete("1.0", "end")
        result_text.insert(
            "end", f"🕒 Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        selected_range = port_ranges[range_var.get()]
        result_text.insert(
            "end",
            f"Scanning localhost ports {selected_range[0]}–{selected_range[1]}...\n\n",
        )
        progress_bar.set(0)
        open_ports = []
        total_ports = selected_range[1] - selected_range[0] + 1

        for i, port in enumerate(
            range(selected_range[0], selected_range[1] + 1), start=1
        ):
            if cancel_flag["stop"]:
                status_label.configure(text="❌ Scan cancelled.")
                return

            status_label.configure(
                text=f"🔄 Scanning port {port} of {selected_range[1]}..."
            )
            progress_bar.set(i / total_ports)

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.3)
                    result = s.connect_ex(("127.0.0.1", port))
                    if result == 0:
                        service, desc, proto, risk = port_info.get(
                            port, ("Unknown", "Unknown service", "TCP", "Unknown")
                        )

                        open_ports.append(port)

                        # Color-coded output
                        if risk == "High":
                            color = "red"
                        elif risk == "Medium":
                            color = "orange"
                        elif risk == "Low":
                            color = "lightgreen"
                        else:
                            color = "white"

                        result_text.insert(
                            "end", f"🟢 Port {port} ({service}) - {desc}\n", color
                        )
                        result_text.insert(
                            "end", f"   ↳ Protocol: {proto}, Risk: {risk}\n\n", color
                        )
                        result_text.tag_config(color, foreground=color)
            except:
                continue

        status_label.configure(text="✅ Scan complete.")
        progress_bar.set(1.0)

        if not open_ports:
            result_text.insert("end", "\n❌ No open ports detected on localhost.\n")
        else:
            result_text.insert(
                "end", f"\n✅ Scan complete: {len(open_ports)} open ports detected.\n"
            )
            # Save scan to database
            log_scan(
                username=username,
                scan_type="Port",
                target="localhost",
                result="Scan Complete",
            )

    # Button Frame
    button_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
    button_frame.pack(pady=10)

    ctk.CTkButton(
        button_frame,
        text="Start Local Scan",
        command=lambda: [
            cancel_flag.update({"stop": False}),
            threading.Thread(target=scan_ports).start(),
        ],
    ).grid(row=0, column=0, padx=10)

    ctk.CTkButton(
        button_frame,
        text="Cancel Scan",
        fg_color="red",
        hover_color="#990000",
        command=lambda: cancel_flag.update({"stop": True}),
    ).grid(row=0, column=1, padx=10)
