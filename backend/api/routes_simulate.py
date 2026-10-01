"""
CyberTrace AI — POST /simulate_attack
Injects fresh Laptop C (brute-force + exfiltration) telemetry rows
with current timestamps so the next /investigate call returns HIGH_RISK.
"""
import random
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter
from pydantic import BaseModel

from backend.db.connection import get_connection

router = APIRouter(prefix="/simulate_attack", tags=["simulate"])

ATTACK_USER_ID   = "user_carol"
ATTACK_DEVICE_ID = "LAPTOP-C"


def _ts(minutes_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


def _random_ip() -> str:
    """Generate a random non-private IP to simulate a new attacker source."""
    return f"{random.randint(1,223)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


class SimulateResponse(BaseModel):
    message:       str
    user_id:       str
    ip_address:    str
    injected_auth: int
    injected_activity: int
    hint:          str


@router.post("", response_model=SimulateResponse)
def simulate_attack() -> SimulateResponse:
    """
    Inject a live brute-force + data-exfiltration scenario into the DB.

    Call this endpoint during a demo, then immediately call
    POST /investigate with the returned user_id + ip_address.
    """
    attack_ip = _random_ip()

    auth_rows = [
        (ATTACK_USER_ID, attack_ip, _ts(20 - i * 2), "failed", "Unknown - TOR Exit", ATTACK_DEVICE_ID)
        for i in range(12)
    ] + [
        (ATTACK_USER_ID, attack_ip, _ts(5), "success", "Unknown - TOR Exit", ATTACK_DEVICE_ID)
    ]

    activity_rows = [
        (ATTACK_USER_ID, ATTACK_DEVICE_ID, _ts(4),   "FILE_DOWNLOAD", "employee_db_full.sql",       210_000_000),
        (ATTACK_USER_ID, ATTACK_DEVICE_ID, _ts(3, 5),"FILE_DOWNLOAD", "financial_records_live.zip", 180_000_000),
        (ATTACK_USER_ID, ATTACK_DEVICE_ID, _ts(2),   "FILE_DOWNLOAD", "customer_pii_export.csv",    150_000_000),
        (ATTACK_USER_ID, ATTACK_DEVICE_ID, _ts(1),   "FILE_DOWNLOAD", "ip_source_code.tar.gz",       80_000_000),
    ]

    conn = get_connection()
    conn.executemany(
        "INSERT INTO auth_logs (user_id, ip_address, timestamp, status, location, device_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        auth_rows,
    )
    conn.executemany(
        "INSERT INTO activity_logs (user_id, device_id, timestamp, action_type, file_name, bytes_transferred) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        activity_rows,
    )
    conn.commit()
    conn.close()

    return SimulateResponse(
        message        = "Attack telemetry injected successfully.",
        user_id        = ATTACK_USER_ID,
        ip_address     = attack_ip,
        injected_auth  = len(auth_rows),
        injected_activity = len(activity_rows),
        hint           = f"Now call POST /investigate with user_id='{ATTACK_USER_ID}' and ip_address='{attack_ip}'",
    )
