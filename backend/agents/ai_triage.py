"""
CyberTrace AI (Netraksh AI) — Central AI Triage & Analysis Engine
Evaluates endpoint telemetry (Processes, Password Attempt Thresholds,
Upload/Download Speeds) to distinguish valid users from malicious threats.
"""
import re
from datetime import datetime, timezone

# MITRE ATT&CK Rule Signature Definitions
MITRE_ATTACK_PATTERNS = [
    {
        "technique_id": "T1490",
        "name": "Inhibit System Recovery (Ransomware Indicator)",
        "pattern": r"(vssadmin.*delete.*shadows|wbadmin.*delete|bcdedit.*ignoreallfailures)",
        "severity": "CRITICAL",
        "score": 90,
    },
    {
        "technique_id": "T1003",
        "name": "OS Credential Dumping",
        "pattern": r"(mimikatz|lsass.*dump|procdump.*lsass|comsvcs\.dll.*minidump)",
        "severity": "CRITICAL",
        "score": 95,
    },
    {
        "technique_id": "T1059",
        "name": "Obfuscated / Encoded Command Line Execution",
        "pattern": r"(powershell.*-e(ncodedcommand)?|powershell.*-nop|cmd\.exe.*/c.*powershell|base64.*-d)",
        "severity": "HIGH",
        "score": 75,
    },
    {
        "technique_id": "T1071",
        "name": "Ingress Tool Transfer / Suspension",
        "pattern": r"(certutil.*-urlcache|bitsadmin.*/transfer|curl.*\|.*sh|wget.*-O)",
        "severity": "HIGH",
        "score": 70,
    },
    {
        "technique_id": "T1136",
        "name": "Local Account Creation",
        "pattern": r"(net.*user.*/add|useradd.*-m|net.*localgroup.*administrators.*/add)",
        "severity": "MEDIUM",
        "score": 50,
    },
]

class AITriageEngine:
    """Central AI Triage Engine for evaluating host endpoint telemetry."""

    def __init__(self):
        pass

    def evaluate_telemetry(self, telemetry_data: dict) -> dict:
        """
        Main Triage Pipeline:
        1. Evaluate Password Attempt Threshold (>3 attempts flagged as brute-force / unauthorized)
        2. Evaluate Network Transfer Speeds (High-speed data exfiltration / rapid fetching)
        3. Run Rule-Based Pattern Matching (MITRE ATT&CK) & Process Hierarchy Checks
        4. Recommend SOS Emergency Broadcast & Host Isolation
        """
        system_info = telemetry_data.get("system_info", {})
        host_id = system_info.get("host_id", "unknown-host")
        hostname = system_info.get("hostname", "unknown")
        flagged_processes = telemetry_data.get("flagged_processes", [])
        active_sockets = telemetry_data.get("active_sockets", [])
        transfer_speeds = telemetry_data.get("transfer_speeds", {}) or {}
        login_metrics = telemetry_data.get("login_metrics", {}) or {}

        matched_rules = []
        highest_score = 0
        reasons = []

        # ── Step 1: Login Attempt Rule (>3 attempts flagged) ─────────────────
        failed_logins = login_metrics.get("failed_login_attempts", 0)
        max_allowed = login_metrics.get("max_allowed_attempts", 3)
        if failed_logins > max_allowed:
            score_add = 70
            highest_score = max(highest_score, score_add)
            matched_rules.append({
                "process": "Authentication Subsystem",
                "pid": 0,
                "technique_id": "T1110",
                "technique_name": "Brute-Force Password Attempt Exceeded",
                "severity": "HIGH",
                "score": score_add,
                "cmdline": f"{failed_logins} failed password attempts (Company Limit: {max_allowed})"
            })
            reasons.append(f"Security Policy Violation: {failed_logins} failed login attempts (Limit is {max_allowed})")

        # ── Step 2: Data Transfer Speed Rule (High speed upload / exfiltration) 
        upload_speed = transfer_speeds.get("upload_speed_mbps", 0.0)
        download_speed = transfer_speeds.get("download_speed_mbps", 0.0)
        if transfer_speeds.get("is_high_speed_exfiltration") or upload_speed > 50.0:
            score_add = 85
            highest_score = max(highest_score, score_add)
            matched_rules.append({
                "process": "Network I/O Subsystem",
                "pid": 0,
                "technique_id": "T1041",
                "technique_name": "Exfiltration Over C2 Channel / High-Speed Transfer",
                "severity": "CRITICAL",
                "score": score_add,
                "cmdline": f"Uploading speed {upload_speed} MB/s | Fetching speed {download_speed} MB/s"
            })
            reasons.append(f"Anomalous Data Transfer: Upload speed spiked to {upload_speed} MB/s (Suspected Data Exfiltration)")

        # ── Step 3: Process CLI & MITRE ATT&CK Pattern Matching ────────────
        for proc in flagged_processes:
            cmdline = proc.get("cmdline", "")
            exe = proc.get("exe", "").lower()

            # Parent-Child Process Hierarchy check
            if ("winword" in exe or "excel" in exe or "outlook" in exe) and ("powershell" in cmdline.lower() or "cmd" in cmdline.lower()):
                highest_score = max(highest_score, 85)
                matched_rules.append({
                    "process": proc.get("name"),
                    "pid": proc.get("pid"),
                    "technique_id": "T1204",
                    "technique_name": "Phishing/Macro Execution (Office spawned CLI)",
                    "severity": "CRITICAL",
                    "score": 85,
                    "cmdline": cmdline
                })
                reasons.append(f"Phishing/Macro Anomaly: Office application spawned CLI process (PID: {proc.get('pid')})")

            for rule in MITRE_ATTACK_PATTERNS:
                if re.search(rule["pattern"], cmdline, re.IGNORECASE):
                    matched_rules.append({
                        "process": proc.get("name"),
                        "pid": proc.get("pid"),
                        "technique_id": rule["technique_id"],
                        "technique_name": rule["name"],
                        "severity": rule["severity"],
                        "score": rule["score"],
                        "cmdline": cmdline
                    })
                    if rule["score"] > highest_score:
                        highest_score = rule["score"]
                    reasons.append(f"Detected {rule['name']} (PID: {proc.get('pid')}, CLI: {cmdline[:60]})")

        # ── Step 4: Determine User Validity & Emergency SOS Trigger ─────────
        if highest_score >= 85:
            risk_level = "CRITICAL"
            category = "CONFIRMED_MALICIOUS_ACTIVITY"
            user_valid = False
            false_positive_prob = 0.05
            recommended_action = "BROADCAST_SOS_AND_ISOLATE_HOST"
        elif highest_score >= 65:
            risk_level = "HIGH"
            category = "SUSPICIOUS_UNAUTHORIZED_ACTIVITY"
            user_valid = False
            false_positive_prob = 0.15
            recommended_action = "ALERT_SOC_TEAM"
        elif highest_score >= 40:
            risk_level = "MEDIUM"
            category = "ELEVATED_METRIC_ANOMALY"
            user_valid = True
            false_positive_prob = 0.40
            recommended_action = "PASSIVE_MONITORING"
        else:
            risk_level = "LOW"
            category = "VALID_COMPANY_USER"
            user_valid = True
            false_positive_prob = 0.90
            recommended_action = "NO_ACTION"

        # ── Step 5: Final Package ────────────────────────────────────────────
        return {
            "triage_id": f"TRG-{host_id}-{int(datetime.now(timezone.utc).timestamp())}",
            "host_id": host_id,
            "hostname": hostname,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_valid": user_valid,
            "risk_score": highest_score,
            "risk_level": risk_level,
            "category": category,
            "failed_logins": failed_logins,
            "upload_speed_mbps": upload_speed,
            "download_speed_mbps": download_speed,
            "false_positive_probability": false_positive_prob,
            "matched_rules_count": len(matched_rules),
            "matched_rules": matched_rules,
            "reasons": reasons,
            "recommended_action": recommended_action,
            "ai_summary": self._generate_ai_summary(hostname, user_valid, risk_level, category, reasons)
        }

    def _generate_ai_summary(self, hostname: str, user_valid: bool, risk_level: str, category: str, reasons: list) -> str:
        """Generate human-readable AI analysis synthesis for SOC analysts."""
        valid_status = "VALID COMPANY USER" if user_valid else "UNAUTHORIZED / MALICIOUS ACTIVITY CONFIRMED"
        if not reasons:
            return f"Host '{hostname}': Verified [{valid_status}]. All login attempts & transfer speeds are within normal parameters."

        reasons_str = "; ".join(reasons)
        return (
            f"Netraksh AI Triage for '{hostname}': Status [{valid_status}] — Risk Level [{risk_level}]. "
            f"Anomalies detected: {reasons_str}. "
            f"Emergency SOS Broadcast and Host Isolation recommended."
        )
