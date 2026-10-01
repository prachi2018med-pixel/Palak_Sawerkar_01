"""
CyberTrace AI (Netraksh AI) — Endpoint Agent Ingestion & Directive Routes
Handles telemetry ingest from endpoint agent daemons running on employee hosts,
triggers AI Triage Analysis for incident detection, and manages SOS broadcasts.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import logging

from backend.agents.ai_triage import AITriageEngine

router = APIRouter(prefix="/api/agent", tags=["agent"])

# Central memory stores for active telemetry, directives, and triaged alerts
HOST_TELEMETRY_STORE = {}
HOST_DIRECTIVES_STORE = {}
GLOBAL_SOS_BROADCAST = {"active": False, "message": ""}
SOC_ALERTS_STORE = []

ai_engine = AITriageEngine()

class SystemInfo(BaseModel):
    host_id: str
    hostname: str
    os: str
    os_release: str | None = None
    cpu_usage_percent: float | None = 0.0
    memory_usage_percent: float | None = 0.0
    timestamp: str

class TransferSpeeds(BaseModel):
    upload_speed_mbps: float = 0.0
    download_speed_mbps: float = 0.0
    is_high_speed_exfiltration: bool = False

class LoginMetrics(BaseModel):
    failed_login_attempts: int = 0
    exceeds_max_login_threshold: bool = False
    max_allowed_attempts: int = 3

class ProcessInfo(BaseModel):
    pid: int
    ppid: int
    name: str
    exe: str | None = "unknown"
    cmdline: str | None = ""
    username: str | None = "N/A"
    is_flagged: bool = False
    created_at: str | None = None

class SocketInfo(BaseModel):
    pid: int | None = None
    process_name: str | None = "unknown"
    local_ip: str | None = "N/A"
    local_port: int | None = 0
    remote_ip: str
    remote_port: int
    status: str | None = "ESTABLISHED"
    timestamp: str | None = None

class SecuritySummary(BaseModel):
    flagged_process_count: int = 0
    active_socket_count: int = 0
    has_threat_indicators: bool = False

class TelemetryPayload(BaseModel):
    system_info: SystemInfo
    transfer_speeds: TransferSpeeds | None = Field(default_factory=TransferSpeeds)
    login_metrics: LoginMetrics | None = Field(default_factory=LoginMetrics)
    total_running_processes: int
    flagged_processes: list[ProcessInfo] = []
    active_sockets: list[SocketInfo] = []
    security_summary: SecuritySummary

@router.post("/telemetry")
def receive_telemetry(payload: TelemetryPayload) -> dict:
    """Receive sanitized endpoint telemetry, run AI Triage, and return host/global directives."""
    host_id = payload.system_info.host_id
    telemetry_dict = payload.model_dump()

    # Store latest raw telemetry for host
    HOST_TELEMETRY_STORE[host_id] = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "data": telemetry_dict
    }

    # ── AI Triage Engine Evaluation ─────────────────────────────────────────
    triage_result = ai_engine.evaluate_telemetry(telemetry_dict)

    # Save triaged alert to central SOC alert feed if risk >= MEDIUM (40+)
    if triage_result["risk_score"] >= 40:
        SOC_ALERTS_STORE.insert(0, triage_result)
        # Cap alert store to latest 100 alerts
        if len(SOC_ALERTS_STORE) > 100:
            SOC_ALERTS_STORE.pop()
        logging.warning(
            f"🚨 SOC ALERT [{triage_result['risk_level']}]: "
            f"Host={triage_result['hostname']}, Score={triage_result['risk_score']}"
        )

    # Fetch host-specific directives
    host_directive = HOST_DIRECTIVES_STORE.get(host_id, {
        "trigger_emergency_alert": False,
        "alert_message": "",
        "isolate_host": False
    })

    # Merge with Global SOS Broadcast if active
    if GLOBAL_SOS_BROADCAST["active"]:
        host_directive["trigger_emergency_alert"] = True
        host_directive["alert_message"] = GLOBAL_SOS_BROADCAST["message"]

    return {
        "status": "success",
        "host_id": host_id,
        "triage": triage_result,
        "directives": host_directive
    }

@router.get("/hosts")
def list_monitored_hosts() -> dict:
    """List all active endpoint hosts currently streaming telemetry."""
    return {
        "total_hosts": len(HOST_TELEMETRY_STORE),
        "hosts": HOST_TELEMETRY_STORE
    }

@router.get("/alerts")
def list_soc_alerts() -> dict:
    """Fetch live AI triaged alert feed for the SOC Dashboard."""
    return {
        "total_alerts": len(SOC_ALERTS_STORE),
        "alerts": SOC_ALERTS_STORE
    }

@router.post("/directive/{host_id}")
def set_host_directive(
    host_id: str, 
    trigger_emergency_alert: bool = False, 
    alert_message: str = "", 
    isolate_host: bool = False
) -> dict:
    """Set SOC directive for a specific host (Emergency alert or Isolation)."""
    HOST_DIRECTIVES_STORE[host_id] = {
        "trigger_emergency_alert": trigger_emergency_alert,
        "alert_message": alert_message,
        "isolate_host": isolate_host
    }
    return {
        "status": "updated",
        "host_id": host_id,
        "directives": HOST_DIRECTIVES_STORE[host_id]
    }

@router.post("/broadcast_sos")
def broadcast_sos_alert(message: str) -> dict:
    """
    🚨 SOS Emergency Broadcast: Sends high-priority red alert banner
    to ALL connected employee computers simultaneously.
    """
    GLOBAL_SOS_BROADCAST["active"] = True
    GLOBAL_SOS_BROADCAST["message"] = message or "🚨 CRITICAL SOS BROADCAST: Ransomware / Hacker Intrusion Confirmed! Stop Work Immediately!"

    # Also apply to all existing host directive entries
    for hid in HOST_TELEMETRY_STORE:
        d = HOST_DIRECTIVES_STORE.get(hid, {})
        d["trigger_emergency_alert"] = True
        d["alert_message"] = GLOBAL_SOS_BROADCAST["message"]
        HOST_DIRECTIVES_STORE[hid] = d

    return {
        "status": "SOS_BROADCAST_ACTIVE",
        "total_hosts_notified": len(HOST_TELEMETRY_STORE),
        "message": GLOBAL_SOS_BROADCAST["message"]
    }

@router.post("/cut_off_host/{host_id}")
def cut_off_host(host_id: str) -> dict:
    """
    🔒 Cut off infected host from company network (Network Isolation).
    """
    d = HOST_DIRECTIVES_STORE.get(host_id, {})
    d["isolate_host"] = True
    HOST_DIRECTIVES_STORE[host_id] = d
    return {
        "status": "HOST_CUT_OFF_SUCCESS",
        "host_id": host_id,
        "isolated": True
    }
