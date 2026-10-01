"""
CyberTrace AI — Containment action API routes.

POST /containment/block_ip      → Simulate blocking an IP
POST /containment/revoke_token  → Simulate revoking user tokens
GET  /containment/audit_log     → Return recent containment actions
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.containment.actions import block_ip, revoke_token
from backend.db.connection import get_connection

router = APIRouter(prefix="/containment", tags=["containment"])


class BlockIPRequest(BaseModel):
    ip_address: str


class RevokeTokenRequest(BaseModel):
    user_id: str


@router.post("/block_ip")
def api_block_ip(body: BlockIPRequest) -> dict:
    """Block a source IP address (simulated)."""
    if not body.ip_address:
        raise HTTPException(status_code=400, detail="ip_address is required")
    return block_ip(body.ip_address)


@router.post("/revoke_token")
def api_revoke_token(body: RevokeTokenRequest) -> dict:
    """Revoke all tokens and suspend a user account (simulated)."""
    if not body.user_id:
        raise HTTPException(status_code=400, detail="user_id is required")
    return revoke_token(body.user_id)


@router.get("/audit_log")
def get_audit_log(limit: int = 20) -> dict:
    """Return the most recent containment actions from the DB."""
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM containment_actions ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"actions": rows, "count": len(rows)}
