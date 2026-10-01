"""
CyberTrace AI — Shared AgentState schema.

Every LangGraph node reads from and writes to this TypedDict.
Fields are additive: each node fills in its own slice without
touching fields owned by other nodes.
"""
from typing import TypedDict


class AgentState(TypedDict):
    # ── Input (set before graph starts) ──────────────────────────────────────
    user_id:    str
    ip_address: str

    # ── Triage node ──────────────────────────────────────────────────────────
    alert_type: str         # e.g. SUSPICIOUS_LOGIN | BRUTE_FORCE | NORMAL

    # ── Retrieval node ───────────────────────────────────────────────────────
    auth_events:     list   # rows from auth_logs
    activity_events: list   # rows from activity_logs

    # ── Validation node ──────────────────────────────────────────────────────
    failed_login_count: int
    total_bytes:        int
    risk_score:         int   # 0–100
    risk_level:         str   # HIGH_RISK | MEDIUM_RISK | LOW_RISK

    # ── Response node ────────────────────────────────────────────────────────
    containment_plan: str   # human-readable plan text

    # ── Shared audit trail (every node appends) ───────────────────────────────
    investigation_steps: list   # list[str] — running log shown in the UI

    # ── Final output (set by response node) ──────────────────────────────────
    final_verdict: dict
