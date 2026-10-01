"""
CyberTrace AI — HTTP client for Streamlit → FastAPI communication.
"""
import httpx

BASE_URL = "http://localhost:8000"
TIMEOUT  = 30.0   # seconds


def investigate(user_id: str, ip_address: str) -> dict:
    """Call POST /investigate and return the parsed JSON response."""
    resp = httpx.post(
        f"{BASE_URL}/investigate",
        json    = {"user_id": user_id, "ip_address": ip_address},
        timeout = TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def simulate_attack() -> dict:
    """Call POST /simulate_attack and return injected telemetry metadata."""
    resp = httpx.post(f"{BASE_URL}/simulate_attack", timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def block_ip(ip_address: str) -> dict:
    resp = httpx.post(
        f"{BASE_URL}/containment/block_ip",
        json    = {"ip_address": ip_address},
        timeout = TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def revoke_token(user_id: str) -> dict:
    resp = httpx.post(
        f"{BASE_URL}/containment/revoke_token",
        json    = {"user_id": user_id},
        timeout = TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def get_audit_log() -> dict:
    resp = httpx.get(f"{BASE_URL}/containment/audit_log", timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()
