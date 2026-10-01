"""
CyberTrace AI (Netraksh AI) — Endpoint Telemetry Collector
Collects system telemetry (Processes, Network Sockets, Login Attempts, Upload/Download Transfer Speeds)
while strictly adhering to privacy-preserving guardrails.
"""
import os
import platform
import socket
import sys
import time
from datetime import datetime, timezone
import psutil

# Suspicious CLI keywords to flag during process collection
SUSPICIOUS_CLI_PATTERNS = [
    "powershell", "vssadmin", "whoami", "netsh", "net user",
    "mimikatz", "encodedcommand", "base64", "nc", "ncat",
    "chmod +x", "curl", "wget", "certutil", "schtasks"
]

class EndpointCollector:
    """Collects security telemetry & behavioral baselines from host OS."""

    def __init__(self, host_id: str | None = None):
        self.hostname = socket.gethostname()
        self.host_id = host_id or f"{self.hostname}-{platform.system().lower()}"
        self.os_type = platform.system()
        
        # Track initial network I/O counters for speed calculation
        self._last_net_io = psutil.net_io_counters()
        self._last_time = time.time()
        self.failed_login_attempts = 0 # Tracked login failures

    def get_system_info(self) -> dict:
        """Return basic system info without personal user file data."""
        return {
            "host_id": self.host_id,
            "hostname": self.hostname,
            "os": self.os_type,
            "os_release": platform.release(),
            "cpu_usage_percent": psutil.cpu_percent(interval=0.1),
            "memory_usage_percent": psutil.virtual_memory().percent,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def measure_transfer_speeds(self) -> dict:
        """
        Measure real-time network fetching (download) & uploading speed in MB/s.
        Flags anomalous data fetching or high-speed exfiltration (>50 MB/s).
        """
        now = time.time()
        net_io = psutil.net_io_counters()
        dt = max(now - self._last_time, 0.001)

        bytes_sent = net_io.bytes_sent - self._last_net_io.bytes_sent
        bytes_recv = net_io.bytes_recv - self._last_net_io.bytes_recv

        self._last_net_io = net_io
        self._last_time = now

        upload_speed_mbps = round((bytes_sent / (1024 * 1024)) / dt, 2)
        download_speed_mbps = round((bytes_recv / (1024 * 1024)) / dt, 2)

        # Flag if uploading speed exceeds suspicious threshold (e.g. exfiltration)
        is_exfiltrating = upload_speed_mbps > 50.0

        return {
            "upload_speed_mbps": upload_speed_mbps,
            "download_speed_mbps": download_speed_mbps,
            "is_high_speed_exfiltration": is_exfiltrating
        }

    def collect_processes(self) -> list[dict]:
        """
        Scan running processes and return security-relevant metadata.
        Privacy Guardrail: Arguments with passwords/tokens are scrubbed.
        """
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid', 'username', 'create_time']):
            try:
                info = proc.info
                cmdline_list = info.get('cmdline') or []
                cmdline_str = " ".join(cmdline_list)

                # Check if process is marked suspicious or high-interest
                is_suspicious = any(pat in cmdline_str.lower() for pat in SUSPICIOUS_CLI_PATTERNS)

                # Privacy Scrubbing: Mask sensitive arguments if any
                clean_cmdline = self._scrub_cmdline(cmdline_str)

                processes.append({
                    "pid": info['pid'],
                    "ppid": info['ppid'],
                    "name": info['name'],
                    "exe": info['exe'] or "unknown",
                    "cmdline": clean_cmdline,
                    "username": info['username'] or "N/A",
                    "is_flagged": is_suspicious,
                    "created_at": datetime.fromtimestamp(info['create_time'], tz=timezone.utc).isoformat()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return processes

    def collect_network_sockets(self) -> list[dict]:
        """
        Collect active outbound network connections.
        Privacy Guardrail: Ignore internal loopback traffic (127.0.0.1).
        """
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port

                    # Skip loopback & internal localhost
                    if remote_ip in ("127.0.0.1", "::1", "0.0.0.0"):
                        continue

                    proc_name = "unknown"
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    connections.append({
                        "pid": conn.pid,
                        "process_name": proc_name,
                        "local_ip": conn.laddr.ip if conn.laddr else "N/A",
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "status": conn.status,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
        except (psutil.AccessDenied, PermissionError):
            pass
        return connections

    def _scrub_cmdline(self, cmdline: str) -> str:
        """Strip passwords or sensitive token parameters from process CLI."""
        keywords = ["-p ", "-password", "secret", "token", "api_key"]
        lower = cmdline.lower()
        for kw in keywords:
            if kw in lower:
                return f"[PRIVACY RESTRICTED: Sensitive CLI Parameters Redacted]"
        return cmdline

    def build_telemetry_payload(self, failed_logins: int = 0) -> dict:
        """Package sanitized endpoint telemetry into a payload."""
        sys_info = self.get_system_info()
        transfer_speeds = self.measure_transfer_speeds()
        processes = self.collect_processes()
        flagged_processes = [p for p in processes if p["is_flagged"]]
        sockets = self.collect_network_sockets()

        failed_login_count = failed_logins or self.failed_login_attempts
        exceeds_login_threshold = failed_login_count > 3 # Rule: > 3 attempts flagged!

        return {
            "system_info": sys_info,
            "transfer_speeds": transfer_speeds,
            "login_metrics": {
                "failed_login_attempts": failed_login_count,
                "exceeds_max_login_threshold": exceeds_login_threshold,
                "max_allowed_attempts": 3
            },
            "total_running_processes": len(processes),
            "flagged_processes": flagged_processes,
            "active_sockets": sockets,
            "security_summary": {
                "flagged_process_count": len(flagged_processes),
                "active_socket_count": len(sockets),
                "has_threat_indicators": len(flagged_processes) > 0 or exceeds_login_threshold or transfer_speeds["is_high_speed_exfiltration"]
            }
        }
