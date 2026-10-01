"""
CyberTrace AI — Endpoint SOC Operations Dashboard Component (Phase 3)
Renders live monitored endpoint hosts, AI triaged security alerts,
and Human-in-the-Loop emergency controls (Desktop Popup & Network Isolation).
"""
import streamlit as st
from frontend.utils.api_client import get_monitored_hosts, get_soc_alerts, set_host_directive

def render_agent_dashboard():
    st.markdown("### 🖥️ Endpoint SOC Agent Control & Live Monitoring")
    st.caption("Real-time monitoring of company laptops with AI Incident Triage and Human-in-the-Loop containment.")

    # Fetch live data from API
    hosts_data = get_monitored_hosts()
    alerts_data = get_soc_alerts()

    hosts_dict = hosts_data.get("hosts", {})
    alerts_list = alerts_data.get("alerts", [])

    # Top Metrics Row
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="Active Monitored Hosts", value=len(hosts_dict))
    with col2:
        critical_count = sum(1 for a in alerts_list if a.get("risk_level") in ("CRITICAL", "HIGH"))
        st.metric(label="High/Critical AI Alerts", value=critical_count)
    with col3:
        st.metric(label="Privacy Guardrails", value="Active 🛡️")

    st.markdown("---")

    # Layout: Left = Monitored Hosts & Alerts | Right = Human-in-the-Loop Response Console
    left_col, right_col = st.columns([3, 2], gap="large")

    with left_col:
        st.subheader("🚨 Live AI Triaged Incidents")

        if not alerts_list:
            st.info("✅ No active high-risk security threats detected on monitored endpoints.")
        else:
            for alert in alerts_list[:10]:
                risk_level = alert.get("risk_level", "LOW")
                score = alert.get("risk_score", 0)

                # Color formatting based on risk
                if risk_level == "CRITICAL":
                    badge_color = "#ef4444"
                elif risk_level == "HIGH":
                    badge_color = "#f97316"
                elif risk_level == "MEDIUM":
                    badge_color = "#eab308"
                else:
                    badge_color = "#22c55e"

                with st.expander(f"[{risk_level}] Host: {alert.get('hostname')} — Risk Score: {score}/100"):
                    st.markdown(f"**AI Reasoning Synthesis:** {alert.get('ai_summary')}")
                    st.markdown(f"**Category:** `{alert.get('category')}`")
                    st.markdown(f"**False Positive Probability:** `{alert.get('false_positive_probability', 0) * 100:.1f}%`")
                    st.markdown(f"**Recommended Action:** `{alert.get('recommended_action')}`")

                    matched_rules = alert.get("matched_rules", [])
                    if matched_rules:
                        st.markdown("**Matched MITRE ATT&CK Techniques:**")
                        for r in matched_rules:
                            st.write(f"- `{r.get('technique_id')}` **{r.get('technique_name')}** (Process: `{r.get('process')}`, PID: {r.get('pid')})")
                            st.caption(f"CLI: `{r.get('cmdline')}`")

        st.markdown("---")
        st.subheader("🖥️ Connected Monitored Devices")

        if not hosts_dict:
            st.warning("No endpoint agents currently connected. Run `python -m endpoint_agent.agent_daemon` on client computers.")
        else:
            for host_id, hinfo in hosts_dict.items():
                data = hinfo.get("data", {})
                sys_info = data.get("system_info", {})
                summary = data.get("security_summary", {})

                st.markdown(f"""
                <div style="background:#1e293b; padding:12px 16px; border-radius:8px; border:1px solid #334155; margin-bottom:10px;">
                    <strong style="color:#60a5fa;">💻 {sys_info.get('hostname')}</strong> ({sys_info.get('os')} {sys_info.get('os_release')})<br/>
                    <small style="color:#94a3b8;">Host ID: {host_id} | CPU: {sys_info.get('cpu_usage_percent')}% | Memory: {sys_info.get('memory_usage_percent')}%</small><br/>
                    <small style="color:#34d399;">Running Processes: {data.get('total_running_processes', 0)} | Flagged CLI: {summary.get('flagged_process_count', 0)} | Sockets: {summary.get('active_socket_count', 0)}</small>
                </div>
                """, unsafe_allow_html=True)

    with right_col:
        st.subheader("⚡ Human-in-the-Loop Analyst Response")
        st.info("Execute security containment actions with mandatory SOC analyst authorization.")

        host_options = list(hosts_dict.keys()) if hosts_dict else ["test-host-WORKSTATION-01"]
        selected_host = st.selectbox("Select Target Host for Response", options=host_options)

        st.markdown("#### Action 1: Broadcast Desktop Emergency Alert")
        alert_msg = st.text_area(
            "Emergency Message for Employee Screen",
            value="⚠️ EMERGENCY SECURITY WARNING: CyberTrace SOC has detected suspicious ransomware activity on your computer. Stop work immediately and contact IT Security.",
            height=100
        )
        if st.button("🚨 Broadcast Emergency Popup Banner", type="primary", use_container_width=True):
            try:
                res = set_host_directive(selected_host, trigger_emergency_alert=True, alert_message=alert_msg)
                st.success(f"✅ Emergency banner directive sent to {selected_host}!")
            except Exception as e:
                st.error(f"Failed to issue directive: {e}")

        st.markdown("---")
        st.markdown("#### Action 2: Network Containment / Isolation")
        st.caption("Cuts infected machine off from local network, preserving connection only to SOC Server.")

        if st.button("🔒 Isolate Host from Network", use_container_width=True):
            try:
                res = set_host_directive(selected_host, isolate_host=True)
                st.warning(f"🔒 Host containment directive issued for {selected_host}. Host is isolated!")
            except Exception as e:
                st.error(f"Failed to isolate host: {e}")
