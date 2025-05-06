# utils/dashboard_ui.py

import customtkinter as ctk
import sqlite3
from datetime import datetime

DB_PATH = "database/scan_logs.db"


def ensure_db():
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


def log_scan(username, scan_type, target, result):
    ensure_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scans (username, scan_type, target, result, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """,
        (username or "Guest", scan_type, target, result, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()


def get_scan_summary():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type")
    rows = cursor.fetchall()
    conn.close()
    return dict(rows)


def get_recent_scans(limit=5):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, scan_type, target, result FROM scans ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def render_dashboard_ui(frame, username="Guest"):
    ensure_db()

    ctk.CTkLabel(frame, text=f"👋 Welcome, {username}", font=("Arial", 22)).pack(
        pady=10
    )
    ctk.CTkLabel(frame, text="📊 ThreatGuard Scan Summary", font=("Arial", 16)).pack(
        pady=5
    )

    summary = get_scan_summary()
    summary_frame = ctk.CTkFrame(frame)
    summary_frame.pack(pady=10)

    for label, icon in [("File", "📁"), ("URL", "🔗"), ("Email", "📧"), ("Port", "🔌")]:
        count = summary.get(label, 0)
        ctk.CTkLabel(
            summary_frame, text=f"{icon} {label} Scans: {count}", font=("Arial", 14)
        ).pack(anchor="w", padx=20)

    ctk.CTkLabel(frame, text="🕒 Recent Scans", font=("Arial", 15)).pack(pady=(20, 5))

    recent_frame = ctk.CTkFrame(frame)
    recent_frame.pack(pady=5, padx=10, fill="x")

    for ts, stype, target, result in get_recent_scans():
        ctk.CTkLabel(
            recent_frame,
            text=f"[{ts.split('T')[0]}] — {stype.upper()} — {target} — {result}",
            font=("Consolas", 11),
            anchor="w",
        ).pack(anchor="w", padx=10, pady=2)
