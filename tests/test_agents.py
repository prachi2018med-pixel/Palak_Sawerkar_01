"""
CyberTrace AI — Agent pipeline unit tests.

Tests all three scenarios end-to-end through the LangGraph graph:
  - user_alice  → LOW_RISK
  - user_bob    → LOW_RISK
  - user_carol  → HIGH_RISK
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from backend.db.connection import init_db, get_connection
from backend.agents.graph  import investigation_graph
from backend.config        import RISK_HIGH, RISK_LOW
from scripts.seed_database import seed


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    """Initialise and seed the test database once for all tests."""
    init_db()
    conn = get_connection()
    seed(conn)
    conn.close()


def _run(user_id: str, ip_address: str) -> dict:
    """Helper: run the graph and return the final_verdict."""
    initial = {
        "user_id":             user_id,
        "ip_address":          ip_address,
        "alert_type":          "",
        "auth_events":         [],
        "activity_events":     [],
        "risk_score":          0,
        "risk_level":          "",
        "failed_login_count":  0,
        "total_bytes":         0,
        "containment_plan":    "",
        "investigation_steps": [],
        "final_verdict":       {},
    }
    result = investigation_graph.invoke(initial)
    return result["final_verdict"]


class TestLaptopA:
    """Normal baseline user — should always resolve as LOW_RISK."""

    def test_risk_level(self):
        verdict = _run("user_alice", "192.168.1.10")
        assert verdict["risk_level"] == RISK_LOW, (
            f"Expected LOW_RISK for user_alice, got {verdict['risk_level']}"
        )

    def test_zero_failed_logins(self):
        verdict = _run("user_alice", "192.168.1.10")
        assert verdict["failed_login_count"] == 0

    def test_low_data_volume(self):
        verdict = _run("user_alice", "192.168.1.10")
        assert verdict["total_bytes_mb"] < 100, (
            f"Expected < 100 MB for normal user, got {verdict['total_bytes_mb']}"
        )

    def test_containment_plan_mentions_false_positive(self):
        verdict = _run("user_alice", "192.168.1.10")
        assert "FALSE POSITIVE" in verdict["containment_plan"].upper()


class TestLaptopB:
    """Late-night travel login — should resolve as LOW_RISK (false alarm)."""

    def test_risk_level(self):
        verdict = _run("user_bob", "203.0.113.45")
        assert verdict["risk_level"] == RISK_LOW, (
            f"Expected LOW_RISK for user_bob, got {verdict['risk_level']}"
        )

    def test_zero_failed_logins(self):
        verdict = _run("user_bob", "203.0.113.45")
        assert verdict["failed_login_count"] == 0

    def test_risk_score_below_threshold(self):
        verdict = _run("user_bob", "203.0.113.45")
        assert verdict["risk_score"] < 30


class TestLaptopC:
    """Brute-force + exfiltration — MUST resolve as HIGH_RISK."""

    def test_risk_level_is_high(self):
        verdict = _run("user_carol", "198.51.100.99")
        assert verdict["risk_level"] == RISK_HIGH, (
            f"Expected HIGH_RISK for user_carol, got {verdict['risk_level']}"
        )

    def test_failed_login_count_above_threshold(self):
        verdict = _run("user_carol", "198.51.100.99")
        assert verdict["failed_login_count"] >= 10, (
            f"Expected >= 10 failed logins, got {verdict['failed_login_count']}"
        )

    def test_data_volume_above_500mb(self):
        verdict = _run("user_carol", "198.51.100.99")
        assert verdict["total_bytes_mb"] >= 500, (
            f"Expected >= 500 MB, got {verdict['total_bytes_mb']}"
        )

    def test_risk_score_is_100(self):
        verdict = _run("user_carol", "198.51.100.99")
        assert verdict["risk_score"] == 100

    def test_containment_plan_mentions_block(self):
        verdict = _run("user_carol", "198.51.100.99")
        plan = verdict["containment_plan"].upper()
        assert "BLOCK" in plan or "REVOKE" in plan

    def test_investigation_steps_present(self):
        initial = {
            "user_id": "user_carol", "ip_address": "198.51.100.99",
            "alert_type": "", "auth_events": [], "activity_events": [],
            "risk_score": 0, "risk_level": "", "failed_login_count": 0,
            "total_bytes": 0, "containment_plan": "",
            "investigation_steps": [], "final_verdict": {},
        }
        result = investigation_graph.invoke(initial)
        assert len(result["investigation_steps"]) >= 4, "Expected at least one step per node"
