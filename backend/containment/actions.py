"""
CyberTrace AI — Containment actions.

In a production environment these would call:
  - block_ip()    → firewall API / iptables / cloud security group
  - revoke_token()→ IAM / SSO revoke endpoint

For the hackathon demo they are fully simulated: actions are logged to
`data/containment_audit.log` and the suspended_users table is updated.
"""
import json
from datetime import datetime, timezone

from backend.config import AUDIT_LOG_PATH
from backend.db.connection import get_connection


def _audit(action_type: str, target: str, detail: dict) -> None:
    """Append a structured JSON line to the audit log."""
    entry = {
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "action_type": action_type,
        "target":      target,
        "detail":      detail,
    }
    with open(AUDIT_LOG_PATH, "a") as fh:
        fh.write(json.dumps(entry) + "\n")

    # Persist to DB as well
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO containment_actions (timestamp, action_type, target, status)
        VALUES (?, ?, ?, 'executed')
        """,
        (entry["timestamp"], action_type, target),
    )
    conn.commit()
    conn.close()


def block_ip(ip_address: str) -> dict:
    """
    Simulate blocking an IP address.
    Returns a confirmation dict that the API echoes back to the UI.
    """
    _audit("BLOCK_IP", ip_address, {"rule": f"DROP src={ip_address}"})
    return {
        "action":     "BLOCK_IP",
        "target":     ip_address,
        "status":     "executed",
        "message":    f"IP {ip_address} has been added to the block-list.",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    }


def revoke_token(user_id: str) -> dict:
    """
    Simulate revoking all active tokens for *user_id* and suspending the account.
    """
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO suspended_users (user_id, suspended_at, reason)
        VALUES (?, ?, 'HIGH_RISK investigation — analyst action')
        ON CONFLICT(user_id) DO UPDATE SET suspended_at=excluded.suspended_at
        """,
        (user_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()

    _audit("REVOKE_TOKEN", user_id, {"action": "account suspended"})
    return {
        "action":    "REVOKE_TOKEN",
        "target":    user_id,
        "status":    "executed",
        "message":   f"All tokens revoked and account '{user_id}' suspended.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
