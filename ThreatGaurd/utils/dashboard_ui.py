import customtkinter as ctk
import sqlite3
from datetime import datetime
import os

# Optional: Matplotlib imports for charts
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    _HAVE_MATPLOTLIB = True
except ImportError:
    _HAVE_MATPLOTLIB = False

DB_PATH = "database/scan_logs.db"

################## Test database#######################
# DB_PATH = os.getenv("TEST_DB_PATH", "database/scan_logs.db")  # Test database
#############################################


def create_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            scan_type TEXT,
            target TEXT,
            result TEXT,
            timestamp TEXT
        )
        """
    )
    conn.commit()
    conn.close()


create_db()


def log_scan(username, scan_type, target, result):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scans (username, scan_type, target, result, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, scan_type, target, result, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def get_scan_summary(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT scan_type, COUNT(*) FROM scans
        WHERE username = ?
        GROUP BY scan_type
        """,
        (username,),
    )
    rows = cursor.fetchall()
    conn.close()
    return dict(rows)


def get_recent_scans(username, limit=5):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT timestamp, scan_type, target, result
        FROM scans
        WHERE username = ?
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (username, limit),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def render_dashboard_ui(frame, username="Guest"):
    # Fetch summary and recent scans
    summary = get_scan_summary(username)
    recent = get_recent_scans(username)

    # === Charts Strip ===
    if _HAVE_MATPLOTLIB and summary:
        charts_frame = ctk.CTkFrame(frame, fg_color="#f0f0f0", corner_radius=8)
        charts_frame.pack(fill="x", padx=20, pady=(10, 5))

        # Pie Chart
        pie_card = ctk.CTkFrame(charts_frame, fg_color="white", corner_radius=6)
        pie_card.pack(side="left", expand=True, fill="both", padx=10, pady=10)
        labels = list(summary.keys())
        sizes = list(summary.values())
        pie_fig = plt.Figure(figsize=(4, 3.5))
        pie_ax = pie_fig.add_subplot(111)
        pie_ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=90)
        pie_ax.legend(labels, loc="upper right", fontsize="small")
        pie_ax.set_title("Scan Distribution")
        pie_fig.tight_layout()
        pie_canvas = FigureCanvasTkAgg(pie_fig, master=pie_card)
        pie_canvas.draw()
        pie_canvas.get_tk_widget().pack(expand=True, fill="both")

        # Line Chart Card
        line_card = ctk.CTkFrame(charts_frame, fg_color="white", corner_radius=6)
        line_card.pack(side="left", expand=True, fill="both", padx=10, pady=10)

        # Build date_counts for the trend
        date_counts = {}
        for timestamp, *_ in recent:
            date = timestamp.split("T")[0]
            date_counts[date] = date_counts.get(date, 0) + 1
        dates = list(date_counts.keys())
        counts = list(date_counts.values())
        x_pos = list(range(len(dates)))

        line_fig = plt.Figure(figsize=(4, 3.5))
        line_ax = line_fig.add_subplot(111)
        # Plot as a line with markers
        line_ax.plot(x_pos, counts, marker="o", linewidth=2)

        # Titles and labels
        line_fig.suptitle("ThreatGuard Daily Scan Trend", fontsize=14, y=0.95)
        line_ax.set_title("Scans per Day", pad=12)
        line_ax.set_xlabel("Date", labelpad=8)
        line_ax.set_ylabel("Number of Scans", labelpad=8)

        # Ticks and grid
        line_ax.set_xticks(x_pos)
        line_ax.set_xticklabels(dates, rotation=45, ha="right")
        line_ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.7)

        line_fig.tight_layout(rect=[0, 0, 1, 0.9])
        line_canvas = FigureCanvasTkAgg(line_fig, master=line_card)
        line_canvas.draw()
        line_canvas.get_tk_widget().pack(expand=True, fill="both")

    elif not _HAVE_MATPLOTLIB:
        ctk.CTkLabel(
            frame,
            text="Install matplotlib to enable charts.",
            font=("Arial", 12, "italic"),
        ).pack(pady=10)

    # Scan Summary & Recent Logs
    stats_container = ctk.CTkFrame(frame)
    stats_container.pack(pady=20, padx=10, fill="x")

    # Summary Column
    summary_frame = ctk.CTkFrame(stats_container, width=350)
    summary_frame.pack(side="left", padx=10, pady=5, anchor="n")
    ctk.CTkLabel(summary_frame, text="Scan Summary", font=("Arial", 16)).pack(
        pady=(5, 10)
    )
    if not summary:
        ctk.CTkLabel(summary_frame, text="No scans found", font=("Arial", 12)).pack()
    else:
        for scan_type, count in summary.items():
            ctk.CTkLabel(
                summary_frame,
                text=f"{scan_type} Scans: {count}",
                font=("Arial", 14),
                anchor="w",
                justify="left",
            ).pack(anchor="w", padx=10, pady=2)

    # Recent Logs Column
    logs_frame = ctk.CTkFrame(stats_container, width=600)
    logs_frame.pack(side="right", padx=10, pady=5, anchor="n")
    ctk.CTkLabel(logs_frame, text="Recent Scans", font=("Arial", 16)).pack(pady=(5, 5))
    scrollable_logs = ctk.CTkScrollableFrame(logs_frame, width=580, height=200)
    scrollable_logs.pack(padx=5, pady=5)
    if not recent:
        ctk.CTkLabel(scrollable_logs, text="No scans yet!", font=("Arial", 12)).pack()
    else:
        for timestamp, scan_type, target, result in recent:
            entry = f"[{timestamp[:19]}] — {scan_type.upper()} — {target} — {result}"
            ctk.CTkLabel(
                scrollable_logs,
                text=entry,
                font=("Consolas", 11),
                anchor="w",
                justify="left",
                wraplength=550,
            ).pack(anchor="w", padx=10, pady=2)
