"""
CyberTrace AI — Investigation Status Feed component.

Renders the real-time agent execution timeline.
"""
import streamlit as st

_ICONS = {
    "TRIAGE":     "🔍",
    "RETRIEVAL":  "📡",
    "VALIDATION": "🧠",
    "RESPONSE":   "📋",
    "COMPLETE":   "✅",
}

def _step_icon(step: str) -> str:
    for key, icon in _ICONS.items():
        if key in step.upper():
            return icon
    return "⚙️"


def render_status_feed(steps: list[str]) -> None:
    """Render the investigation steps as a timestamped timeline."""
    st.markdown("### 📋 Agent Execution Log")

    if not steps:
        st.info("Run an investigation to see the agent pipeline in action.")
        return

    # Scrollable container
    with st.container():
        for step in steps:
            icon = _step_icon(step)
            # Parse timestamp from step string for colour coding
            if "TRIAGE" in step.upper():
                colour = "#3b82f6"   # blue
            elif "RETRIEVAL" in step.upper():
                colour = "#8b5cf6"   # purple
            elif "VALIDATION" in step.upper():
                colour = "#f59e0b"   # amber
            elif "RESPONSE" in step.upper() or "COMPLETE" in step.upper():
                colour = "#10b981"   # green
            else:
                colour = "#6b7280"   # grey

            st.markdown(
                f"""<div style="
                    border-left: 3px solid {colour};
                    padding: 4px 12px;
                    margin: 4px 0;
                    font-family: monospace;
                    font-size: 0.85rem;
                    color: #e2e8f0;
                    background: #1e293b;
                    border-radius: 0 4px 4px 0;
                ">{icon} {step}</div>""",
                unsafe_allow_html=True,
            )
