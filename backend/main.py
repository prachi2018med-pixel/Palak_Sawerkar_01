"""
CyberTrace AI — FastAPI application entrypoint.

Run with:
    uvicorn backend.main:app --reload --port 8000
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import CORS_ORIGINS
from backend.db.connection import init_db
from backend.api.routes_investigate import router as investigate_router
from backend.api.routes_simulate    import router as simulate_router
from backend.api.routes_containment import router as containment_router

# ── App instance ──────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "CyberTrace AI",
    description = "Autonomous multi-agent SOC investigation platform",
    version     = "1.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

# ── CORS (allow Streamlit dashboard) ─────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins     = CORS_ORIGINS,
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Startup: ensure DB + tables exist ────────────────────────────────────────
@app.on_event("startup")
def startup() -> None:
    init_db()


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(investigate_router)
app.include_router(simulate_router)
app.include_router(containment_router)


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["health"])
def health() -> dict:
    return {"status": "ok", "service": "CyberTrace AI"}
