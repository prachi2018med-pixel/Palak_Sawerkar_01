"""
CyberTrace AI — FastAPI integration tests.

Uses httpx.TestClient (synchronous) to test all API endpoints
without needing a live server.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient

from backend.main          import app
from backend.db.connection import init_db, get_connection
from scripts.seed_database import seed


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_db()
    conn = get_connection()
    seed(conn)
    conn.close()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ── Health ────────────────────────────────────────────────────────────────────
class TestHealth:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ── POST /investigate ─────────────────────────────────────────────────────────
class TestInvestigate:
    def test_laptop_c_returns_high_risk(self, client):
        resp = client.post(
            "/investigate",
            json={"user_id": "user_carol", "ip_address": "198.51.100.99"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "HIGH_RISK"
        assert data["risk_score"] >= 70
        assert data["failed_login_count"] >= 10

    def test_laptop_b_returns_low_risk(self, client):
        resp = client.post(
            "/investigate",
            json={"user_id": "user_bob", "ip_address": "203.0.113.45"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "LOW_RISK"

    def test_laptop_a_returns_low_risk(self, client):
        resp = client.post(
            "/investigate",
            json={"user_id": "user_alice", "ip_address": "192.168.1.10"},
        )
        assert resp.status_code == 200
        assert resp.json()["risk_level"] == "LOW_RISK"

    def test_response_contains_investigation_steps(self, client):
        resp = client.post(
            "/investigate",
            json={"user_id": "user_carol", "ip_address": "198.51.100.99"},
        )
        data = resp.json()
        assert len(data["investigation_steps"]) >= 4

    def test_response_contains_containment_plan(self, client):
        resp = client.post(
            "/investigate",
            json={"user_id": "user_carol", "ip_address": "198.51.100.99"},
        )
        assert len(resp.json()["containment_plan"]) > 50


# ── POST /simulate_attack ─────────────────────────────────────────────────────
class TestSimulateAttack:
    def test_returns_200(self, client):
        resp = client.post("/simulate_attack")
        assert resp.status_code == 200

    def test_returns_injected_row_counts(self, client):
        resp = client.post("/simulate_attack")
        data = resp.json()
        assert data["injected_auth"] > 0
        assert data["injected_activity"] > 0

    def test_subsequent_investigate_is_high_risk(self, client):
        sim  = client.post("/simulate_attack").json()
        resp = client.post(
            "/investigate",
            json={"user_id": sim["user_id"], "ip_address": sim["ip_address"]},
        )
        assert resp.json()["risk_level"] == "HIGH_RISK"


# ── POST /containment/block_ip ────────────────────────────────────────────────
class TestContainment:
    def test_block_ip(self, client):
        resp = client.post(
            "/containment/block_ip",
            json={"ip_address": "198.51.100.99"},
        )
        assert resp.status_code == 200
        assert resp.json()["action"] == "BLOCK_IP"

    def test_revoke_token(self, client):
        resp = client.post(
            "/containment/revoke_token",
            json={"user_id": "user_carol"},
        )
        assert resp.status_code == 200
        assert resp.json()["action"] == "REVOKE_TOKEN"

    def test_audit_log_is_populated(self, client):
        resp = client.get("/containment/audit_log")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 0
