"""
CyberTrace AI — Endpoint Agent Ingestion Routes
Handles telemetry ingest from endpoint agent daemons running on employee hosts.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import logging

router = APIRouter(prefix="/api/agent", tags=["agent"])

# In-memory store for active host telemetry & directives
HOST_TELEMETRY_STORE = {}
HOST_DIRECTIVES_STORE = {}

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
    """Receive sanitized endpoint telemetry from client daemon."""
    host_id = payload.system_info.host_id
    HOST_TELEMETRY_STORE[host_id] = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "data": payload.model_dump()
    }

    # Fetch any pending directives for this host (e.g. emergency alert / isolation)
    directives = HOST_DIRECTIVES_STORE.get(host_id, {
        "trigger_emergency_alert": False,
        "alert_message": "",
        "isolate_host": False
    })

    # Auto-flag if high risk process detected
    if payload.security_summary.has_threat_indicators:
        logging.warning(f"🚨 Threat indicators detected from host {payload.system_info.hostname}!")

    return {
        "status": "success",
        "host_id": host_id,
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "directives": directives
    }

@router.get("/hosts")
def list_monitored_hosts() -> dict:
    """List all active endpoint hosts currently streaming telemetry."""
    return {
        "total_hosts": len(HOST_TELEMETRY_STORE),
        "hosts": HOST_TELEMETRY_STORE
    }

@router.post("/directive/{host_id}")
def set_host_directive(host_id: str, trigger_emergency_alert: bool = False, alert_message: str = "", isolate_host: bool = False) -> dict:
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
