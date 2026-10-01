"""
CyberTrace AI — Human-in-the-Loop Containment Box component.

Renders action buttons that are only enabled when the verdict is HIGH_RISK.
Each action calls the backend containment API and shows a confirmation spinner.
"""
import time
import streamlit as st

from frontend.utils.api_client import block_ip, revoke_token, get_audit_log


def render_containment_box(verdict: dict) -> None:
    """
    Render the containment action panel.

    Buttons are disabled unless risk_level is HIGH_RISK or MEDIUM_RISK.
    """
    st.markdown("### 🔒 Human-in-the-Loop Containment")

    if not verdict:
        st.info("Run an investigation first to unlock containment actions.")
        return

    risk_level = verdict.get("risk_level", "LOW_RISK")
    ip_address = verdict.get("ip_address", "")
    user_id    = verdict.get("user_id", "")
    enabled    = risk_level in ("HIGH_RISK", "MEDIUM_RISK")

    if enabled:
        st.warning(
            f"⚠️ **Analyst approval required.** The following actions will be executed against "
            f"user `{user_id}` / IP `{ip_address}`."
        )
    else:
        st.success("✅ No containment action required for this verdict.")

    col1, col2, col3 = st.columns(3)

    # ── Block IP ──────────────────────────────────────────────────────────────
    with col1:
        if st.button(
            "🚫 Block IP Address",
            disabled          = not enabled,
            use_container_width = True,
            type              = "primary" if enabled else "secondary",
            key               = "btn_block_ip",
        ):
            with st.spinner(f"Blocking {ip_address}…"):
                time.sleep(1.5)   # Simulate latency for demo realism
                try:
                    result = block_ip(ip_address)
                    st.success(result["message"])
                    st.json(result)
                except Exception as e:
                    st.error(f"Action failed: {e}")

    # ── Revoke Token ──────────────────────────────────────────────────────────
    with col2:
        if st.button(
            "🔑 Revoke User Token",
            disabled            = not enabled,
            use_container_width = True,
            type                = "primary" if enabled else "secondary",
            key                 = "btn_revoke",
        ):
            with st.spinner(f"Revoking tokens for {user_id}…"):
                time.sleep(1.5)
                try:
                    result = revoke_token(user_id)
                    st.success(result["message"])
                    st.json(result)
                except Exception as e:
                    st.error(f"Action failed: {e}")

    # ── Both Actions ──────────────────────────────────────────────────────────
    with col3:
        if st.button(
            "⚡ Execute Full Containment",
            disabled            = not enabled,
            use_container_width = True,
            type                = "primary" if enabled else "secondary",
            key                 = "btn_both",
        ):
            with st.spinner("Executing full containment protocol…"):
                time.sleep(2.0)
                try:
                    r1 = block_ip(ip_address)
                    r2 = revoke_token(user_id)
                    st.success("🔒 Full containment executed successfully.")
                    st.write("**Block IP:**", r1["message"])
                    st.write("**Revoke Token:**", r2["message"])
                except Exception as e:
                    st.error(f"Containment failed: {e}")

    # ── Audit Log ─────────────────────────────────────────────────────────────
    with st.expander("📜 Containment Audit Log", expanded=False):
        try:
            log = get_audit_log()
            if log["count"] == 0:
                st.info("No containment actions have been executed yet.")
            else:
                for action in log["actions"]:
                    st.markdown(
                        f"- `{action['timestamp']}` — **{action['action_type']}** → `{action['target']}`  "
                        f"Status: `{action['status']}`"
                    )
        except Exception as e:
            st.warning(f"Could not load audit log: {e}")
