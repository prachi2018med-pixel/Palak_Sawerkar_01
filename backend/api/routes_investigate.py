"""
CyberTrace AI — POST /investigate
Runs the compiled LangGraph workflow for a given user + IP.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.agents.graph import investigation_graph

router = APIRouter(prefix="/investigate", tags=["investigate"])


class InvestigateRequest(BaseModel):
    user_id:    str = Field(..., example="user_carol")
    ip_address: str = Field(..., example="198.51.100.99")


class InvestigateResponse(BaseModel):
    user_id:              str
    ip_address:           str
    alert_type:           str
    risk_level:           str
    risk_score:           int
    failed_login_count:   int
    total_bytes_mb:       float
    auth_event_count:     int
    activity_event_count: int
    containment_plan:     str
    investigation_steps:  list[str]
    investigated_at:      str


@router.post("", response_model=InvestigateResponse)
def run_investigation(body: InvestigateRequest) -> InvestigateResponse:
    """
    Execute the autonomous 4-node investigation pipeline.

    Returns a fully populated verdict including risk level, score,
    evidence counts, and a human-readable containment plan.
    """
    try:
        initial_state = {
            "user_id":             body.user_id,
            "ip_address":          body.ip_address,
            "alert_type":          "",
            "auth_events":         [],
            "activity_events":     [],
            "risk_score":          0,
            "risk_level":          "",
            "failed_login_count":  0,
            "total_bytes":         0,
            "containment_plan":    "",
            "investigation_steps": [],
            "final_verdict":       {},
        }

        result = investigation_graph.invoke(initial_state)

        verdict = result["final_verdict"]
        return InvestigateResponse(
            user_id              = verdict["user_id"],
            ip_address           = verdict["ip_address"],
            alert_type           = verdict["alert_type"],
            risk_level           = verdict["risk_level"],
            risk_score           = verdict["risk_score"],
            failed_login_count   = verdict["failed_login_count"],
            total_bytes_mb       = verdict["total_bytes_mb"],
            auth_event_count     = verdict["auth_event_count"],
            activity_event_count = verdict["activity_event_count"],
            containment_plan     = verdict["containment_plan"],
            investigation_steps  = result["investigation_steps"],
            investigated_at      = verdict["investigated_at"],
        )

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
