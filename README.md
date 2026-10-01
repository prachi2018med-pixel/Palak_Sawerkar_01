# 🛡️ CyberTrace AI

**Autonomous Multi-Agent SOC Investigation Platform**  
Stack: Python · FastAPI · LangGraph · SQLite · Streamlit

---

## Architecture

```
Alert Input
    ↓
FastAPI  POST /investigate
    ↓
LangGraph Pipeline
    ① Triage Node      — classify alert type
    ② Retrieval Node   — query SQLite auth + activity logs
    ③ Validation Node  — deterministic risk scoring (0–100)
    ④ Response Node    — generate evidence-backed containment plan
    ↓
JSON Verdict → Streamlit Dashboard
    ↓
Human-in-the-Loop: Block IP · Revoke Token · Full Containment
```

---

## Quick Start

### 1. Clone & install
```powershell
cd cybertrace-ai
pip install -r requirements.txt
```

### 2. Seed the database
```powershell
python scripts/seed_database.py
```

### 3. Start backend
```powershell
uvicorn backend.main:app --reload --port 8000
```

### 4. Start dashboard (new terminal)
```powershell
streamlit run frontend/app.py
```

### One-command launch (Windows)
```powershell
.\scripts\run_dev.ps1
```

---

## Demo Scenarios

| User | Scenario | Expected Verdict |
|---|---|---|
| `user_alice` / `192.168.1.10` | Normal office activity | ✅ LOW_RISK |
| `user_bob` / `203.0.113.45` | Late-night travel login | ✅ LOW_RISK |
| `user_carol` / `198.51.100.99` | Brute-force + 620MB exfil | 🚨 HIGH_RISK |

### Live Attack Demo
```powershell
# Inject fresh telemetry then investigate
python scripts/simulate_attack.py
# Use the returned user_id + ip_address in the dashboard
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/investigate` | Run autonomous investigation |
| `POST` | `/simulate_attack` | Inject attack telemetry |
| `POST` | `/containment/block_ip` | Block a source IP |
| `POST` | `/containment/revoke_token` | Revoke user tokens |
| `GET` | `/containment/audit_log` | View containment history |

Interactive docs: **http://localhost:8000/docs**

---

## Risk Scoring Logic

| Condition | Score Added |
|---|---|
| ≥ 10 failed logins | +60 |
| ≥ 3 failed logins | +30 |
| ≥ 500 MB transferred | +40 |
| ≥ 100 MB transferred | +20 |
| **Score ≥ 70** | → **HIGH_RISK** |
| **Score 30–69** | → **MEDIUM_RISK** |
| **Score < 30** | → **LOW_RISK** |

---

## Running Tests
```powershell
pytest tests/ -v
```

---

## Project Structure

```
cybertrace-ai/
├── backend/
│   ├── main.py                    # FastAPI entrypoint
│   ├── config.py                  # All constants & thresholds
│   ├── agents/
│   │   ├── state.py               # AgentState TypedDict
│   │   ├── tools.py               # SQL query tools
│   │   ├── nodes.py               # 4 LangGraph node functions
│   │   └── graph.py               # StateGraph compilation
│   ├── api/
│   │   ├── routes_investigate.py
│   │   ├── routes_simulate.py
│   │   └── routes_containment.py
│   ├── db/connection.py
│   └── containment/actions.py
├── frontend/
│   ├── app.py                     # Streamlit dashboard
│   ├── components/
│   │   ├── input_panel.py
│   │   ├── status_feed.py
│   │   ├── verdict_card.py
│   │   └── containment_box.py
│   └── utils/api_client.py
├── data/
│   ├── mock_logs.db               # SQLite (auto-created)
│   ├── schema.sql                 # Reference DDL
│   └── containment_audit.log      # Auto-created on first action
├── scripts/
│   ├── seed_database.py
│   ├── simulate_attack.py
│   ├── run_dev.ps1
│   └── run_dev.sh
└── tests/
    ├── test_agents.py
    └── test_api.py
```
