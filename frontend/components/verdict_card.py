"""
CyberTrace AI — Verdict Card component.

Renders a RED (HIGH_RISK) or GREEN (LOW_RISK/MEDIUM_RISK) verdict card
with key evidence metrics and the full containment plan.
"""
import streamlit as st


def render_verdict_card(verdict: dict) -> None:
    """Render the risk verdict card from a /investigate response dict."""
    if not verdict:
        return

    risk_level = verdict.get("risk_level", "")
    risk_score = verdict.get("risk_score", 0)

    # ── Colour scheme ─────────────────────────────────────────────────────────
    if risk_level == "HIGH_RISK":
        bg_colour   = "#7f1d1d"
        border      = "#ef4444"
        badge_bg    = "#ef4444"
        emoji       = "🚨"
        label       = "HIGH RISK — CONFIRMED THREAT"
    elif risk_level == "MEDIUM_RISK":
        bg_colour   = "#78350f"
        border      = "#f59e0b"
        badge_bg    = "#f59e0b"
        emoji       = "⚠️"
        label       = "MEDIUM RISK — INVESTIGATION REQUIRED"
    else:
        bg_colour   = "#14532d"
        border      = "#22c55e"
        badge_bg    = "#22c55e"
        emoji       = "✅"
        label       = "LOW RISK — FALSE POSITIVE"

    # ── Header card ───────────────────────────────────────────────────────────
    st.markdown(
        f"""
        <div style="
            background:    {bg_colour};
            border:        2px solid {border};
            border-radius: 8px;
            padding:       20px 24px;
            margin-bottom: 16px;
        ">
            <h2 style="color:{border}; margin:0 0 8px 0;">{emoji} {label}</h2>
            <div style="display:flex; gap:32px; flex-wrap:wrap; color:#e2e8f0;">
                <div><strong>User:</strong> {verdict.get('user_id', 'N/A')}</div>
                <div><strong>IP:</strong> {verdict.get('ip_address', 'N/A')}</div>
                <div><strong>Alert Type:</strong> {verdict.get('alert_type', 'N/A')}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Metric columns ────────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk Score",        f"{risk_score} / 100")
    c2.metric("Failed Logins",     verdict.get("failed_login_count", 0))
    c3.metric("Data Transferred",  f"{verdict.get('total_bytes_mb', 0):.1f} MB")
    c4.metric("Auth Events",       verdict.get("auth_event_count", 0))

    # ── Containment plan ─────────────────────────────────────────────────────
    st.markdown("#### 📄 Containment Plan")
    st.code(verdict.get("containment_plan", "No plan generated."), language="text")

    st.caption(f"Investigated at: {verdict.get('investigated_at', 'N/A')}")
