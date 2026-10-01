"""
CyberTrace AI — Streamlit Dashboard.

Run with:
    streamlit run frontend/app.py

Layout:
  ┌─────────────────────────────────────────────────────┐
  │  HEADER                                             │
  ├────────────────────┬────────────────────────────────┤
  │  LEFT COLUMN       │  RIGHT COLUMN                  │
  │  • Input Panel     │  • Verdict Card                │
  │  • Status Feed     │  • Containment Box             │
  └────────────────────┴────────────────────────────────┘
"""
import sys
from pathlib import Path

# Allow running from repo root: streamlit run frontend/app.py
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from frontend.components.input_panel    import render_input_panel
from frontend.components.status_feed    import render_status_feed
from frontend.components.verdict_card   import render_verdict_card
from frontend.components.containment_box import render_containment_box
from frontend.utils.api_client          import investigate, simulate_attack

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title      = "CyberTrace AI",
    page_icon       = "🛡️",
    layout          = "wide",
    initial_sidebar_state = "collapsed",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Dark background matching a SOC terminal */
    .stApp { background-color: #0f172a; color: #e2e8f0; }
    .stTextInput > div > div > input {
        background: #1e293b; color: #e2e8f0; border: 1px solid #334155;
    }
    .stButton > button { border-radius: 6px; font-weight: 600; }
    div[data-testid="metric-container"] {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 12px;
    }
    .stExpander { background: #1e293b; border: 1px solid #334155; border-radius: 8px; }
</style>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="
        background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
        padding: 24px 32px;
        border-radius: 12px;
        border-bottom: 2px solid #3b82f6;
        margin-bottom: 24px;
    ">
        <h1 style="color:#60a5fa; margin:0;">🛡️ CyberTrace AI</h1>
        <p style="color:#94a3b8; margin:4px 0 0 0;">
            Autonomous Multi-Agent SOC Investigation Platform
            &nbsp;|&nbsp; <code style="color:#34d399;">4-Agent Pipeline</code>
            &nbsp;|&nbsp; <code style="color:#34d399;">Human-in-the-Loop Containment</code>
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Session state ─────────────────────────────────────────────────────────────
if "verdict"   not in st.session_state: st.session_state.verdict   = None
if "steps"     not in st.session_state: st.session_state.steps     = []
if "sim_result"not in st.session_state: st.session_state.sim_result= None
if "error"     not in st.session_state: st.session_state.error     = None

# ── Layout: two columns ───────────────────────────────────────────────────────
left_col, right_col = st.columns([1, 1], gap="large")

with left_col:
    action = render_input_panel()

    # Handle form submission
    if action is not None:
        st.session_state.error = None

        if action["action"] == "simulate":
            with st.spinner("💥 Injecting attack telemetry…"):
                try:
                    sim = simulate_attack()
                    st.session_state.sim_result = sim
                    st.success(
                        f"✅ Attack injected! Use  `user_id={sim['user_id']}`  "
                        f"and  `ip_address={sim['ip_address']}`  to investigate."
                    )
                    # Auto-fill the fields with the injected data (shown in info box)
                    st.info(f"📌 Hint: {sim['hint']}")
                except Exception as e:
                    st.error(f"Simulation failed: {e}")

        elif action["action"] == "investigate":
            user_id    = action["user_id"]
            ip_address = action["ip_address"]

            if not user_id or not ip_address:
                st.error("Please enter both a User ID and an IP address.")
            else:
                with st.spinner(f"🔍 Investigating {user_id} @ {ip_address}…"):
                    try:
                        result = investigate(user_id, ip_address)
                        st.session_state.verdict = result
                        st.session_state.steps   = result.get("investigation_steps", [])
                    except Exception as e:
                        st.session_state.error = str(e)

    # Status feed (always visible, updates after each run)
    st.markdown("---")
    if st.session_state.error:
        st.error(f"❌ Backend error: {st.session_state.error}")
        st.info("Is the backend running? → `uvicorn backend.main:app --reload --port 8000`")

    render_status_feed(st.session_state.steps)

with right_col:
    render_verdict_card(st.session_state.verdict)
    st.markdown("---")
    render_containment_box(st.session_state.verdict)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.caption(
    "CyberTrace AI · Hackathon Demo · "
    "Stack: Python · FastAPI · LangGraph · SQLite · Streamlit"
)
