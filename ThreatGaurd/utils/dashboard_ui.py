import customtkinter as ctk
import sqlite3
from datetime import datetime

DB_PATH = "database/scan_logs.db"  # Now using the new location


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
    # 🧱 Create horizontal container frame
    stats_container = ctk.CTkFrame(frame)
    stats_container.pack(pady=20, padx=10, fill="x")

    # 📊 Scan Summary Column (Left)
    summary_frame = ctk.CTkFrame(stats_container, width=350)
    summary_frame.pack(side="left", padx=10, pady=5, anchor="n")

    ctk.CTkLabel(summary_frame, text="📊 Scan Summary", font=("Arial", 16)).pack(
        pady=(5, 10)
    )

    summary = get_scan_summary(username)
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

    # 🕒 Recent Scans Column (Right)
    logs_frame = ctk.CTkFrame(stats_container, width=600)
    logs_frame.pack(side="right", padx=10, pady=5, anchor="n")

    ctk.CTkLabel(logs_frame, text="🕒 Recent Scans", font=("Arial", 16)).pack(
        pady=(5, 5)
    )

    scrollable_logs = ctk.CTkScrollableFrame(logs_frame, width=580, height=200)
    scrollable_logs.pack(padx=5, pady=5)

    recent = get_recent_scans(username)
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
