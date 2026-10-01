"""
CyberTrace AI (Netraksh AI) — HTTP client for Streamlit → FastAPI communication.
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


def get_monitored_hosts() -> dict:
    """Fetch active endpoint hosts streaming telemetry."""
    try:
        resp = httpx.get(f"{BASE_URL}/api/agent/hosts", timeout=5.0)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {"total_hosts": 0, "hosts": {}}


def get_soc_alerts() -> dict:
    """Fetch live AI triaged alert feed."""
    try:
        resp = httpx.get(f"{BASE_URL}/api/agent/alerts", timeout=5.0)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {"total_alerts": 0, "alerts": []}


def set_host_directive(host_id: str, trigger_emergency_alert: bool = False, alert_message: str = "", isolate_host: bool = False) -> dict:
    """Send SOC directive (Emergency popup or Isolation) for a host."""
    resp = httpx.post(
        f"{BASE_URL}/api/agent/directive/{host_id}",
        params={
            "trigger_emergency_alert": trigger_emergency_alert,
            "alert_message": alert_message,
            "isolate_host": isolate_host
        },
        timeout=5.0
    )
    resp.raise_for_status()
    return resp.json()


def broadcast_sos_alert(message: str) -> dict:
    """🚨 Broadcast Emergency SOS banner to ALL company computers simultaneously."""
    resp = httpx.post(
        f"{BASE_URL}/api/agent/broadcast_sos",
        params={"message": message},
        timeout=5.0
    )
    resp.raise_for_status()
    return resp.json()


def cut_off_host(host_id: str) -> dict:
    """🔒 Cut off infected host from company network."""
    resp = httpx.post(
        f"{BASE_URL}/api/agent/cut_off_host/{host_id}",
        timeout=5.0
    )
    resp.raise_for_status()
    return resp.json()
