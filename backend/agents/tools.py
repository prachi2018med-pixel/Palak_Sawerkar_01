"""
CyberTrace AI — SQL query tools used by the Retrieval node.

Each function is a pure, deterministic database query that returns
plain Python dicts — no LLM calls, no side effects.
"""
from datetime import datetime, timedelta, timezone

from backend.db.connection import get_connection


def _utc_since(hours_back: int) -> str:
    """Return an ISO-8601 UTC timestamp `hours_back` hours in the past."""
    return (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()


def query_auth_logs(
    user_id: str,
    ip_address: str | None = None,
    hours_back: int = 48,
) -> list[dict]:
    """
    Fetch authentication events for *user_id* within the last *hours_back* hours.
    Optionally filter to a specific *ip_address*.
    """
    conn = get_connection()
    cur  = conn.cursor()
    since = _utc_since(hours_back)

    if ip_address:
        cur.execute(
            """
            SELECT * FROM auth_logs
            WHERE user_id = ? AND ip_address = ? AND timestamp >= ?
            ORDER BY timestamp DESC
            """,
            (user_id, ip_address, since),
        )
    else:
        cur.execute(
            """
            SELECT * FROM auth_logs
            WHERE user_id = ? AND timestamp >= ?
            ORDER BY timestamp DESC
            """,
            (user_id, since),
        )

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def query_activity_logs(
    user_id: str,
    hours_back: int = 48,
) -> list[dict]:
    """
    Fetch file-activity events for *user_id* within the last *hours_back* hours.
    """
    conn = get_connection()
    cur  = conn.cursor()
    since = _utc_since(hours_back)

    cur.execute(
        """
        SELECT * FROM activity_logs
        WHERE user_id = ? AND timestamp >= ?
        ORDER BY timestamp DESC
        """,
        (user_id, since),
    )

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
