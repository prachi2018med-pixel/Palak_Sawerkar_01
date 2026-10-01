"""
CyberTrace AI (Netraksh AI) — Endpoint SOC Operations Dashboard Component
Renders live monitored endpoint hosts, password attempt counters, transfer speeds,
AI triaged security alerts, and SOS Emergency Broadcast + Network Isolation Controls.
"""
import streamlit as st
from frontend.utils.api_client import (
    get_monitored_hosts, 
    get_soc_alerts, 
    set_host_directive, 
    broadcast_sos_alert, 
    cut_off_host
)

def render_agent_dashboard():
    st.markdown("### 🛡️ Netraksh AI — Endpoint Security & SOC Control Center")
    st.caption("Continuous backend condition verification: Password Attempt Thresholds (≤3), Transfer Speeds, Mysterious Activity Detection & Emergency SOS Containment.")

    # Fetch live data from API
    hosts_data = get_monitored_hosts()
    alerts_data = get_soc_alerts()

    hosts_dict = hosts_data.get("hosts", {})
    alerts_list = alerts_data.get("alerts", [])

    # Top Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="Company Devices", value=len(hosts_dict))
    with col2:
        critical_count = sum(1 for a in alerts_list if a.get("risk_level") in ("CRITICAL", "HIGH"))
        st.metric(label="High / Critical Threats", value=critical_count)
    with col3:
        st.metric(label="Max Allowed Password Attempts", value="3 Attempts")
    with col4:
        st.metric(label="Privacy Guardrails", value="Active 🔒")

    st.markdown("---")

    # Global SOS Broadcast Alert Banner Button at top
    st.markdown("""
    <div style="background: linear-gradient(135deg, #7f1d1d 0%, #450a0a 100%); padding:16px 20px; border-radius:10px; border:2px solid #ef4444; margin-bottom:20px;">
        <h3 style="color:#fca5a5; margin:0;">🚨 COMPANY-WIDE EMERGENCY SOS BROADCAST</h3>
        <p style="color:#fecaca; margin:4px 0 10px 0; font-size:14px;">
            If a confirmed threat (hacker or ransomware) is spreading, trigger an immediate SOS Emergency Alert popup across ALL connected employee laptops.
        </p>
    </div>
    """, unsafe_allow_html=True)

    sos_msg_input = st.text_input(
        "Emergency SOS Message to Display on All Laptops:",
        value="🚨 EMERGENCY SOS WARNING: Critical security intrusion confirmed on company network! Save your work immediately."
    )
    if st.button("🚨 BROADCAST SOS TO ALL COMPANY COMPUTERS NOW", type="primary", use_container_width=True):
        try:
            res = broadcast_sos_alert(sos_msg_input)
            st.error(f"🚨 EMERGENCY SOS BROADCAST ACTIVATED! Sent warning popup to all company endpoints!")
        except Exception as e:
            st.error(f"Failed to send SOS broadcast: {e}")

    st.markdown("---")

    # Layout: Left = Monitored Hosts & Alerts | Right = Computer Isolation Console
    left_col, right_col = st.columns([3, 2], gap="large")

    with left_col:
        st.subheader("🚨 Live Threat & Anomaly Feed")

        if not alerts_list:
            st.info("✅ All backend condition checks passing. User logins valid & transfer speeds normal.")
        else:
            for alert in alerts_list[:10]:
                risk_level = alert.get("risk_level", "LOW")
                score = alert.get("risk_score", 0)
                user_valid = alert.get("user_valid", True)

                # Color formatting based on risk
                if risk_level == "CRITICAL":
                    badge_color = "#ef4444"
                elif risk_level == "HIGH":
                    badge_color = "#f97316"
                elif risk_level == "MEDIUM":
                    badge_color = "#eab308"
                else:
                    badge_color = "#22c55e"

                valid_text = "✅ VALID USER" if user_valid else "🚨 UNAUTHORIZED / SUSPICIOUS"

                with st.expander(f"[{risk_level}] Host: {alert.get('hostname')} — Score: {score}/100 — {valid_text}"):
                    st.markdown(f"**AI Reasoning:** {alert.get('ai_summary')}")
                    st.markdown(f"**Failed Password Attempts:** `{alert.get('failed_logins', 0)} / 3 Limit`")
                    st.markdown(f"**Uploading Speed:** `{alert.get('upload_speed_mbps', 0.0)} MB/s` | **Fetching Speed:** `{alert.get('download_speed_mbps', 0.0)} MB/s`")
                    st.markdown(f"**Category:** `{alert.get('category')}`")

                    matched_rules = alert.get("matched_rules", [])
                    if matched_rules:
                        st.markdown("**Matched Security Anomalies:**")
                        for r in matched_rules:
                            st.write(f"- `{r.get('technique_id')}` **{r.get('technique_name')}** (CLI: `{r.get('cmdline')}`)")

        st.markdown("---")
        st.subheader("🖥️ Connected Company Laptops")

        if not hosts_dict:
            st.warning("No endpoint agents currently connected. Run `python -m endpoint_agent.agent_daemon` on client computers.")
        else:
            for host_id, hinfo in hosts_dict.items():
                data = hinfo.get("data", {})
                sys_info = data.get("system_info", {})
                speeds = data.get("transfer_speeds", {})
                logins = data.get("login_metrics", {})
                summary = data.get("security_summary", {})

                failed_att = logins.get("failed_login_attempts", 0)
                login_badge = "🔴 LOGINS EXCEEDED (>3)" if failed_att > 3 else "🟢 LOGINS NORMAL"

                st.markdown(f"""
                <div style="background:#1e293b; padding:14px 18px; border-radius:8px; border:1px solid #334155; margin-bottom:12px;">
                    <div style="display:flex; justify-content:space-between;">
                        <strong style="color:#60a5fa; font-size:16px;">💻 {sys_info.get('hostname')}</strong>
                        <span style="font-size:12px; font-weight:bold;">{login_badge}</span>
                    </div>
                    <small style="color:#94a3b8;">Host ID: {host_id} | OS: {sys_info.get('os')} | CPU: {sys_info.get('cpu_usage_percent')}% | RAM: {sys_info.get('memory_usage_percent')}%</small><br/>
                    <div style="margin-top:6px;">
                        <small style="color:#38bdf8;">📤 Uploading Speed: {speeds.get('upload_speed_mbps', 0.0)} MB/s</small> &nbsp;|&nbsp;
                        <small style="color:#38bdf8;">📥 Fetching Speed: {speeds.get('download_speed_mbps', 0.0)} MB/s</small>
                    </div>
                    <small style="color:#34d399;">Password Attempts: {failed_att} / 3 | Flagged Processes: {summary.get('flagged_process_count', 0)}</small>
                </div>
                """, unsafe_allow_html=True)

    with right_col:
        st.subheader("🔒 Cut Off Computer From Company End")
        st.info("If mysterious activity or virus behavior is confirmed on a specific laptop, cut it off from the company network immediately.")

        host_options = list(hosts_dict.keys()) if hosts_dict else ["test-host-WORKSTATION-01"]
        selected_host = st.selectbox("Select Target Computer to Isolate:", options=host_options)

        if st.button("🔒 CUT OFF THIS COMPUTER FROM COMPANY NETWORK", use_container_width=True):
            try:
                res = cut_off_host(selected_host)
                st.error(f"🔒 ISOLATION ENFORCED: Computer '{selected_host}' has been cut off from the company network!")
            except Exception as e:
                st.error(f"Failed to cut off computer: {e}")

        st.markdown("---")
        st.markdown("#### Send Targeted Workstation Alert")
        single_msg = st.text_area(
            "Individual Computer Alert Message:",
            value="⚠️ WARNING: Mysterious activity detected on your login session. Please contact the security team immediately.",
            height=90
        )
        if st.button("📩 Send Warning Popup to Selected Computer", use_container_width=True):
            try:
                res = set_host_directive(selected_host, trigger_emergency_alert=True, alert_message=single_msg)
                st.success(f"✅ Warning banner sent to {selected_host}!")
            except Exception as e:
                st.error(f"Failed to send warning: {e}")
