"""
CyberTrace AI — Endpoint Agent Ingestion Routes
Handles telemetry ingest from endpoint agent daemons running on employee hosts
and triggers AI Triage Analysis for incident detection.
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
    total_running_processes: int
    flagged_processes: list[ProcessInfo] = []
    active_sockets: list[SocketInfo] = []
    security_summary: SecuritySummary

@router.post("/telemetry")
def receive_telemetry(payload: TelemetryPayload) -> dict:
    """Receive sanitized endpoint telemetry, run AI Triage, and check directives."""
    host_id = payload.system_info.host_id
    telemetry_dict = payload.model_dump()

    # Store latest raw telemetry for host
    HOST_TELEMETRY_STORE[host_id] = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "data": telemetry_dict
    }

    # ── Phase 2: Run AI Triage Engine ───────────────────────────────────────
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

    # Fetch any pending directives for this host (e.g. emergency alert / isolation)
    directives = HOST_DIRECTIVES_STORE.get(host_id, {
        "trigger_emergency_alert": False,
        "alert_message": "",
        "isolate_host": False
    })

    return {
        "status": "success",
        "host_id": host_id,
        "triage": triage_result,
        "directives": directives
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
