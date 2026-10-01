"""
CyberTrace AI — LangGraph node implementations.

Node execution order:
    triage_node → retrieval_node → validation_node → response_node

Each node receives the full AgentState, mutates only its own fields,
appends a step to investigation_steps, and returns the updated state.
"""
from datetime import datetime, timezone

from backend.agents.state import AgentState
from backend.agents.tools import query_auth_logs, query_activity_logs
from backend.config import (
    FAILED_LOGIN_HIGH_THRESHOLD,
    FAILED_LOGIN_MEDIUM_THRESHOLD,
    BYTES_HIGH_THRESHOLD,
    BYTES_MEDIUM_THRESHOLD,
    SCORE_FAILED_HIGH,
    SCORE_FAILED_MEDIUM,
    SCORE_BYTES_HIGH,
    SCORE_BYTES_MEDIUM,
    RISK_HIGH,
    RISK_MEDIUM,
    RISK_LOW,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


# ─────────────────────────────────────────────────────────────────────────────
# ① TRIAGE NODE
# ─────────────────────────────────────────────────────────────────────────────
def triage_node(state: AgentState) -> AgentState:
    """
    Classify the incoming alert.
    Performs a lightweight pre-check on the IP before hitting the DB.
    """
    steps = list(state.get("investigation_steps", []))
    steps.append(f"[{_now()}] 🔍 TRIAGE  — Received alert for user '{state['user_id']}' "
                  f"from IP {state['ip_address']}")

    # Quick heuristic: private-range IPs are almost certainly internal
    ip = state["ip_address"]
    if ip.startswith(("192.168.", "10.", "172.16.")):
        alert_type = "INTERNAL_LOGIN"
    else:
        alert_type = "SUSPICIOUS_EXTERNAL_LOGIN"

    steps.append(f"[{_now()}] 🔍 TRIAGE  — Alert classified as: {alert_type}")

    return {
        **state,
        "alert_type":          alert_type,
        "investigation_steps": steps,
        # Initialise downstream fields with safe defaults
        "auth_events":         [],
        "activity_events":     [],
        "failed_login_count":  0,
        "total_bytes":         0,
        "risk_score":          0,
        "risk_level":          RISK_LOW,
        "containment_plan":    "",
        "final_verdict":       {},
    }


# ─────────────────────────────────────────────────────────────────────────────
# ② RETRIEVAL NODE
# ─────────────────────────────────────────────────────────────────────────────
def retrieval_node(state: AgentState) -> AgentState:
    """
    Pull authentication and file-activity telemetry from SQLite.
    """
    steps = list(state["investigation_steps"])
    steps.append(f"[{_now()}] 📡 RETRIEVAL — Querying auth_logs for '{state['user_id']}'…")

    auth_events = query_auth_logs(
        user_id=state["user_id"],
        ip_address=None,   # fetch ALL IPs so we catch brute-force from any source
        hours_back=48,
    )
    steps.append(f"[{_now()}] 📡 RETRIEVAL — Found {len(auth_events)} auth event(s).")

    steps.append(f"[{_now()}] 📡 RETRIEVAL — Querying activity_logs for '{state['user_id']}'…")
    activity_events = query_activity_logs(
        user_id=state["user_id"],
        hours_back=48,
    )
    total_bytes = sum(e.get("bytes_transferred", 0) for e in activity_events)
    steps.append(
        f"[{_now()}] 📡 RETRIEVAL — Found {len(activity_events)} activity event(s) "
        f"totalling {total_bytes / 1_000_000:.1f} MB."
    )

    return {
        **state,
        "auth_events":         auth_events,
        "activity_events":     activity_events,
        "total_bytes":         total_bytes,
        "investigation_steps": steps,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ③ VALIDATION NODE  (fully deterministic — no LLM)
# ─────────────────────────────────────────────────────────────────────────────
def validation_node(state: AgentState) -> AgentState:
    """
    Compute a deterministic risk score and classify the alert.

    Scoring:
      failed_login_count >= 10  → +60 pts
      failed_login_count >= 3   → +30 pts
      total_bytes >= 500 MB     → +40 pts
      total_bytes >= 100 MB     → +20 pts

    Classification:
      score >= 70  → HIGH_RISK
      score >= 30  → MEDIUM_RISK
      score <  30  → LOW_RISK
    """
    steps = list(state["investigation_steps"])
    steps.append(f"[{_now()}] 🧠 VALIDATION — Running deterministic risk scorer…")

    auth_events        = state["auth_events"]
    failed_login_count = sum(1 for e in auth_events if e["status"] == "failed")
    total_bytes        = state["total_bytes"]

    # ── Score calculation ────────────────────────────────────────────────────
    score = 0
    reasons: list[str] = []

    if failed_login_count >= FAILED_LOGIN_HIGH_THRESHOLD:
        score += SCORE_FAILED_HIGH
        reasons.append(f"{failed_login_count} failed logins (brute-force threshold exceeded)")
    elif failed_login_count >= FAILED_LOGIN_MEDIUM_THRESHOLD:
        score += SCORE_FAILED_MEDIUM
        reasons.append(f"{failed_login_count} failed logins (moderate threshold exceeded)")

    if total_bytes >= BYTES_HIGH_THRESHOLD:
        score += SCORE_BYTES_HIGH
        reasons.append(f"{total_bytes / 1_000_000:.0f} MB transferred (exfiltration threshold exceeded)")
    elif total_bytes >= BYTES_MEDIUM_THRESHOLD:
        score += SCORE_BYTES_MEDIUM
        reasons.append(f"{total_bytes / 1_000_000:.0f} MB transferred (elevated volume)")

    # ── Classification ───────────────────────────────────────────────────────
    if score >= 70:
        risk_level = RISK_HIGH
    elif score >= 30:
        risk_level = RISK_MEDIUM
    else:
        risk_level = RISK_LOW

    steps.append(
        f"[{_now()}] 🧠 VALIDATION — Score: {score}/100 → {risk_level}  |  "
        f"Failed logins: {failed_login_count}  |  Bytes: {total_bytes / 1_000_000:.1f} MB"
    )
    if reasons:
        for r in reasons:
            steps.append(f"[{_now()}] 🧠 VALIDATION —   ⚠  {r}")

    return {
        **state,
        "failed_login_count":  failed_login_count,
        "risk_score":          score,
        "risk_level":          risk_level,
        "investigation_steps": steps,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ④ RESPONSE NODE
# ─────────────────────────────────────────────────────────────────────────────
_PLANS = {
    RISK_HIGH: """
🚨 HIGH-RISK CONTAINMENT PLAN
══════════════════════════════════════════════════════════════
IMMEDIATE ACTIONS (execute within 5 minutes):
  1. Block source IP {ip} at perimeter firewall and cloud WAF.
  2. Revoke all active sessions and OAuth tokens for {uid}.
  3. Reset credentials via out-of-band channel (call user directly).
  4. Preserve forensic snapshot: memory dump + disk image of {device}.
  5. Isolate endpoint {device} from network (quarantine VLAN).

SHORT-TERM (next 2 hours):
  6. Review all files accessed/downloaded in the past 48 h.
  7. Notify Data Protection Officer if PII data was exfiltrated.
  8. Open P1 incident ticket and engage IR team.
  9. Check lateral movement — scan for other endpoints contacting {ip}.

EVIDENCE SUMMARY:
  • Failed login attempts:  {fails}
  • Bytes transferred:      {mb:.1f} MB
  • Risk score:             {score}/100
══════════════════════════════════════════════════════════════
""".strip(),

    RISK_MEDIUM: """
⚠️  MEDIUM-RISK INVESTIGATION PLAN
══════════════════════════════════════════════════════════════
RECOMMENDED ACTIONS:
  1. Step-up authentication: force MFA re-verification for {uid}.
  2. Monitor IP {ip} for the next 24 h; alert on new connections.
  3. Review recent file-access history with {uid}'s manager.
  4. No immediate blocking required — continue passive monitoring.

EVIDENCE SUMMARY:
  • Failed login attempts:  {fails}
  • Bytes transferred:      {mb:.1f} MB
  • Risk score:             {score}/100
══════════════════════════════════════════════════════════════
""".strip(),

    RISK_LOW: """
✅  LOW-RISK — FALSE POSITIVE RESOLUTION
══════════════════════════════════════════════════════════════
ASSESSMENT:
  No brute-force indicators or anomalous data volumes detected.
  Login pattern consistent with travel or after-hours access.

RECOMMENDED ACTIONS:
  1. Mark alert as FALSE POSITIVE in SIEM.
  2. Optional: verify with {uid} via Slack/email as a courtesy.
  3. Consider adding IP {ip} to user's trusted-device list.

EVIDENCE SUMMARY:
  • Failed login attempts:  {fails}
  • Bytes transferred:      {mb:.1f} MB
  • Risk score:             {score}/100
══════════════════════════════════════════════════════════════
""".strip(),
}


def response_node(state: AgentState) -> AgentState:
    """
    Generate a human-readable, evidence-backed containment plan.
    """
    steps = list(state["investigation_steps"])
    steps.append(f"[{_now()}] 📋 RESPONSE  — Generating containment plan for {state['risk_level']}…")

    # Pick device from first auth event (best-effort)
    device = "UNKNOWN"
    if state["auth_events"]:
        device = state["auth_events"][0].get("device_id", "UNKNOWN")

    plan = _PLANS[state["risk_level"]].format(
        ip     = state["ip_address"],
        uid    = state["user_id"],
        device = device,
        fails  = state["failed_login_count"],
        mb     = state["total_bytes"] / 1_000_000,
        score  = state["risk_score"],
    )

    steps.append(f"[{_now()}] ✅ COMPLETE  — Investigation finished. Verdict: {state['risk_level']}")

    final_verdict = {
        "user_id":             state["user_id"],
        "ip_address":          state["ip_address"],
        "alert_type":          state["alert_type"],
        "risk_level":          state["risk_level"],
        "risk_score":          state["risk_score"],
        "failed_login_count":  state["failed_login_count"],
        "total_bytes_mb":      round(state["total_bytes"] / 1_000_000, 2),
        "auth_event_count":    len(state["auth_events"]),
        "activity_event_count":len(state["activity_events"]),
        "containment_plan":    plan,
        "investigated_at":     datetime.now(timezone.utc).isoformat(),
    }

    return {
        **state,
        "containment_plan":    plan,
        "final_verdict":       final_verdict,
        "investigation_steps": steps,
    }
