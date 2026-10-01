"""
Tests for Phase 1 Endpoint Agent Telemetry Collector & Ingestion
"""
import pytest
from endpoint_agent.collector import EndpointCollector

def test_system_info_collection():
    collector = EndpointCollector()
    sys_info = collector.get_system_info()

    assert "host_id" in sys_info
    assert "hostname" in sys_info
    assert "os" in sys_info
    assert sys_info["cpu_usage_percent"] >= 0.0

def test_process_collection_and_privacy_scrubbing():
    collector = EndpointCollector()
    processes = collector.collect_processes()

    assert isinstance(processes, list)
    assert len(processes) > 0

    # Test privacy scrubber helper directly
    dirty_cmd = "cmd.exe /c connect.exe -user admin -password Secret123Password!"
    clean_cmd = collector._scrub_cmdline(dirty_cmd)
    assert "Secret123Password!" not in clean_cmd
    assert "[PRIVACY RESTRICTED" in clean_cmd

def test_telemetry_payload_building():
    collector = EndpointCollector()
    payload = collector.build_telemetry_payload()

    assert "system_info" in payload
    assert "flagged_processes" in payload
    assert "active_sockets" in payload
    assert "security_summary" in payload
