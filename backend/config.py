"""
CyberTrace AI — Centralised configuration.
All tuneable constants live here; never hard-code paths or thresholds elsewhere.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR       = Path(__file__).parent.parent          # repo root
DATA_DIR       = BASE_DIR / "data"
DB_PATH        = str(DATA_DIR / "mock_logs.db")
AUDIT_LOG_PATH = str(DATA_DIR / "containment_audit.log")

# ── Server ────────────────────────────────────────────────────────────────────
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:8501").split(",")
API_HOST     = os.getenv("API_HOST", "0.0.0.0")
API_PORT     = int(os.getenv("API_PORT", "8000"))

# ── Risk-scoring thresholds ───────────────────────────────────────────────────
FAILED_LOGIN_HIGH_THRESHOLD   = 10
FAILED_LOGIN_MEDIUM_THRESHOLD = 3
BYTES_HIGH_THRESHOLD          = 500_000_000   # 500 MB
BYTES_MEDIUM_THRESHOLD        = 100_000_000   # 100 MB

# Risk labels
RISK_HIGH   = "HIGH_RISK"
RISK_MEDIUM = "MEDIUM_RISK"
RISK_LOW    = "LOW_RISK"

# Score weights
SCORE_FAILED_HIGH   = 60
SCORE_FAILED_MEDIUM = 30
SCORE_BYTES_HIGH    = 40
SCORE_BYTES_MEDIUM  = 20
