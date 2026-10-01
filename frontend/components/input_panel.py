"""
CyberTrace AI — Input Panel component.

Renders the alert trigger form and returns the submitted values.
"""
import streamlit as st


def render_input_panel() -> dict | None:
    """
    Render the investigation input form.

    Returns a dict with keys `user_id`, `ip_address`, and `action`
    when the user submits, or None if no action was taken.
    """
    st.markdown("### 🔍 Trigger Investigation")

    with st.form("investigate_form", clear_on_submit=False):
        col1, col2 = st.columns(2)
        with col1:
            user_id = st.text_input(
                "User ID",
                value       = "user_carol",
                placeholder = "e.g. user_carol",
                help        = "The user account to investigate",
            )
        with col2:
            ip_address = st.text_input(
                "Source IP Address",
                value       = "198.51.100.99",
                placeholder = "e.g. 198.51.100.99",
                help        = "The IP address that triggered the alert",
            )

        st.markdown("**Quick-fill scenarios:**")
        qcol1, qcol2, qcol3 = st.columns(3)
        with qcol1:
            if st.form_submit_button("💻 Laptop A (Normal)", use_container_width=True):
                return {"user_id": "user_alice", "ip_address": "192.168.1.10", "action": "investigate"}
        with qcol2:
            if st.form_submit_button("✈️ Laptop B (Travel)", use_container_width=True):
                return {"user_id": "user_bob", "ip_address": "203.0.113.45", "action": "investigate"}
        with qcol3:
            if st.form_submit_button("🚨 Laptop C (Attack)", use_container_width=True):
                return {"user_id": "user_carol", "ip_address": "198.51.100.99", "action": "investigate"}

        st.markdown("---")
        bcol1, bcol2 = st.columns([3, 1])
        with bcol1:
            submitted = st.form_submit_button(
                "🔎 Run Investigation",
                use_container_width = True,
                type                = "primary",
            )
        with bcol2:
            simulate = st.form_submit_button(
                "💥 Simulate Attack",
                use_container_width = True,
                help                = "Inject live Laptop C telemetry into the database",
            )

        if submitted:
            return {"user_id": user_id.strip(), "ip_address": ip_address.strip(), "action": "investigate"}
        if simulate:
            return {"user_id": user_id.strip(), "ip_address": ip_address.strip(), "action": "simulate"}

    return None
