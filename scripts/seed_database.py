"""
CyberTrace AI — Database seeder.

Run from the repo root:
    python scripts/seed_database.py

Seeds three distinct scenarios into mock_logs.db:
  - Laptop A / user_alice  → NORMAL baseline          → expected: LOW_RISK
  - Laptop B / user_bob    → Late-night travel login   → expected: LOW_RISK
  - Laptop C / user_carol  → Brute-force + exfiltration→ expected: HIGH_RISK
"""
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Allow running from repo root or from scripts/
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.db.connection import init_db, get_connection


def _ts(hours_ago: float, minutes_ago: float = 0) -> str:
    """Return an ISO-8601 UTC timestamp offset from now."""
    delta = timedelta(hours=hours_ago, minutes=minutes_ago)
    return (datetime.now(timezone.utc) - delta).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# Scenario A — Normal baseline (Laptop A / user_alice)
# ─────────────────────────────────────────────────────────────────────────────
AUTH_A = [
    ("user_alice", "192.168.1.10", _ts(8),    "success", "Office - HQ",       "LAPTOP-A"),
    ("user_alice", "192.168.1.10", _ts(7),    "success", "Office - HQ",       "LAPTOP-A"),
    ("user_alice", "192.168.1.10", _ts(6),    "success", "Office - HQ",       "LAPTOP-A"),
    ("user_alice", "192.168.1.10", _ts(5),    "success", "Office - HQ",       "LAPTOP-A"),
    ("user_alice", "192.168.1.10", _ts(4),    "success", "Office - HQ",       "LAPTOP-A"),
    ("user_alice", "192.168.1.10", _ts(3),    "success", "Office - HQ",       "LAPTOP-A"),
    ("user_alice", "192.168.1.10", _ts(2),    "success", "Office - HQ",       "LAPTOP-A"),
    ("user_alice", "192.168.1.10", _ts(1),    "success", "Office - HQ",       "LAPTOP-A"),
]

ACTIVITY_A = [
    ("user_alice", "LAPTOP-A", _ts(7, 45), "FILE_READ",     "report_q3.xlsx",    6_200_000),
    ("user_alice", "LAPTOP-A", _ts(6, 30), "FILE_DOWNLOAD", "handbook.pdf",      4_100_000),
    ("user_alice", "LAPTOP-A", _ts(5, 15), "FILE_READ",     "budget_2026.xlsx",  5_800_000),
    ("user_alice", "LAPTOP-A", _ts(4, 0),  "FILE_UPLOAD",   "presentation.pptx", 8_300_000),
    ("user_alice", "LAPTOP-A", _ts(3, 20), "FILE_READ",     "notes.docx",        1_200_000),
    ("user_alice", "LAPTOP-A", _ts(2, 10), "FILE_DOWNLOAD", "policy_v2.pdf",     3_700_000),
    ("user_alice", "LAPTOP-A", _ts(1, 5),  "FILE_READ",     "roadmap.pptx",      7_500_000),
    ("user_alice", "LAPTOP-A", _ts(0, 30), "FILE_DOWNLOAD", "summary.pdf",       4_900_000),
]

# ─────────────────────────────────────────────────────────────────────────────
# Scenario B — Late-night travel login (Laptop B / user_bob)
# 1 success from unusual IP, modest download → FALSE ALARM / LOW_RISK
# ─────────────────────────────────────────────────────────────────────────────
AUTH_B = [
    ("user_bob", "203.0.113.45", _ts(10), "success", "Singapore - Hotel WiFi", "LAPTOP-B"),
]

ACTIVITY_B = [
    ("user_bob", "LAPTOP-B", _ts(9, 50), "FILE_DOWNLOAD", "itinerary.pdf",    2_500_000),
    ("user_bob", "LAPTOP-B", _ts(9, 40), "FILE_READ",     "contact_list.xlsx", 4_100_000),
    ("user_bob", "LAPTOP-B", _ts(9, 30), "FILE_DOWNLOAD", "slides_deck.pptx",  5_700_000),
]

# ─────────────────────────────────────────────────────────────────────────────
# Scenario C — Brute-force + data exfiltration (Laptop C / user_carol)
# 12 failed logins, 1 success, 620 MB downloaded in 8 min → HIGH_RISK
# ─────────────────────────────────────────────────────────────────────────────
AUTH_C = [
    # 12 consecutive failed attempts over 20 minutes
    ("user_carol", "198.51.100.99", _ts(6, 20), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    ("user_carol", "198.51.100.99", _ts(6, 18), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    ("user_carol", "198.51.100.99", _ts(6, 16), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    ("user_carol", "198.51.100.99", _ts(6, 14), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    ("user_carol", "198.51.100.99", _ts(6, 12), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    ("user_carol", "198.51.100.99", _ts(6, 10), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    ("user_carol", "198.51.100.99", _ts(6,  8), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    ("user_carol", "198.51.100.99", _ts(6,  6), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    ("user_carol", "198.51.100.99", _ts(6,  4), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    ("user_carol", "198.51.100.99", _ts(6,  2), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    ("user_carol", "198.51.100.99", _ts(6,  1), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    ("user_carol", "198.51.100.99", _ts(6,  0), "failed",  "Unknown - TOR Exit", "LAPTOP-C"),
    # Successful brute-force entry
    ("user_carol", "198.51.100.99", _ts(5, 55), "success", "Unknown - TOR Exit", "LAPTOP-C"),
]

ACTIVITY_C = [
    # Rapid mass-download after successful brute-force: 620 MB in 8 minutes
    ("user_carol", "LAPTOP-C", _ts(5, 52), "FILE_DOWNLOAD", "employee_db_full.sql",     210_000_000),
    ("user_carol", "LAPTOP-C", _ts(5, 50), "FILE_DOWNLOAD", "financial_records_2026.zip",180_000_000),
    ("user_carol", "LAPTOP-C", _ts(5, 48), "FILE_DOWNLOAD", "customer_pii_export.csv",  150_000_000),
    ("user_carol", "LAPTOP-C", _ts(5, 46), "FILE_DOWNLOAD", "ip_source_code.tar.gz",     80_000_000),
]


def seed(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()

    # Clear existing seed data (idempotent re-runs)
    for user in ("user_alice", "user_bob", "user_carol"):
        cur.execute("DELETE FROM auth_logs     WHERE user_id = ?", (user,))
        cur.execute("DELETE FROM activity_logs WHERE user_id = ?", (user,))

    # Insert auth logs
    cur.executemany(
        "INSERT INTO auth_logs (user_id, ip_address, timestamp, status, location, device_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        AUTH_A + AUTH_B + AUTH_C,
    )

    # Insert activity logs
    cur.executemany(
        "INSERT INTO activity_logs (user_id, device_id, timestamp, action_type, file_name, bytes_transferred) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ACTIVITY_A + ACTIVITY_B + ACTIVITY_C,
    )

    conn.commit()


def main() -> None:
    print("🔧  Initialising database schema…")
    init_db()

    conn = get_connection()
    print("🌱  Seeding scenarios A, B, C…")
    seed(conn)
    conn.close()

    # Summary
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT user_id, COUNT(*) as c FROM auth_logs GROUP BY user_id")
    auth_counts = {r["user_id"]: r["c"] for r in cur.fetchall()}
    cur.execute("SELECT user_id, COUNT(*) as c, SUM(bytes_transferred) as b FROM activity_logs GROUP BY user_id")
    act_counts  = cur.fetchall()
    conn.close()

    print("\n✅  Seeding complete!\n")
    print(f"{'User':<15} {'Auth Events':>12} {'Activity Events':>16} {'Total Bytes':>14}")
    print("-" * 62)
    for row in act_counts:
        uid = row["user_id"]
        print(f"{uid:<15} {auth_counts.get(uid, 0):>12} {row['c']:>16} {row['b']:>14,}")
    print()


if __name__ == "__main__":
    main()
