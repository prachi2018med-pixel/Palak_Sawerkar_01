"""
CyberTrace AI — LangGraph StateGraph compilation.

Imports the four node functions and wires them into a linear pipeline:
    triage → retrieval → validation → response → END
"""
from langgraph.graph import StateGraph, END

from backend.agents.state import AgentState
from backend.agents.nodes import (
    triage_node,
    retrieval_node,
    validation_node,
    response_node,
)


def build_graph() -> StateGraph:
    """Compile and return the investigation workflow graph."""
    workflow = StateGraph(AgentState)

    # ── Register nodes ────────────────────────────────────────────────────────
    workflow.add_node("triage",     triage_node)
    workflow.add_node("retrieval",  retrieval_node)
    workflow.add_node("validation", validation_node)
    workflow.add_node("response",   response_node)

    # ── Wire edges (linear pipeline) ─────────────────────────────────────────
    workflow.set_entry_point("triage")
    workflow.add_edge("triage",     "retrieval")
    workflow.add_edge("retrieval",  "validation")
    workflow.add_edge("validation", "response")
    workflow.add_edge("response",   END)

    return workflow.compile()


# Module-level singleton — imported by API routes
investigation_graph = build_graph()
