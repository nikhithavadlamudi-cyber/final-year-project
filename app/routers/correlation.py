"""
Correlation Router — Phase 4
─────────────────────────────
API and HTML routes for forensic artefact normalisation, correlation,
rule-based suspicious activity detection, and activity timeline reconstruction.

Endpoints:
  GET  /correlation                     — Hub to select analysis sessions
  GET  /correlation/{session_id}        — Comprehensive 8-tab correlation dashboard
  GET  /correlation/case/{case_id}      — Case-wide findings and review summary
  POST /api/correlation/pipeline/{id}   — Run full normalisation, correlation, detection & timeline
  POST /api/correlation/normalise/{id}  — Normalise raw Vol3 plugin outputs
  POST /api/correlation/correlate/{id}  — Correlate parent-child, network, cmdline
  POST /api/correlation/detect/{id}     — Run heuristic suspicious activity detection
  POST /api/correlation/timeline/{id}   — Build chronological activity timeline
  GET  /api/correlation/artefacts/{id}  — List normalised artefacts
  GET  /api/correlation/links/{id}      — List correlation links
  GET  /api/correlation/findings/{id}   — List suspicious findings
  PUT  /api/findings/{finding_id}/review— Update analyst review status and notes
  GET  /api/correlation/timeline/{id}   — Get timeline events
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.config import TEMPLATES_DIR, APP_TITLE
from app.database import (
    get_all_sessions,
    get_analysis_session,
    get_case_by_id,
    get_evidence_by_id,
    get_artefacts_by_session,
    get_correlations_by_session,
    get_findings_by_session,
    get_findings_by_case,
    get_finding_by_id,
    update_finding_review,
    get_timeline_by_session,
)
from app.models import FindingUpdateRequest
from app.services.normaliser import normalise_session
from app.services.correlator import run_all_correlations
from app.services.suspicious_detector import run_all_detectors
from app.services.timeline_builder import build_timeline

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
logger = logging.getLogger("forensics.correlation_router")


# ─────────────────────────────────────────────────────────────────────────────
# HTML UI Routes
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/correlation", response_class=HTMLResponse, tags=["Correlation UI"])
async def correlation_hub_page(request: Request):
    """Correlation Hub page: lists sessions ready for correlation."""
    sessions = get_all_sessions()
    return templates.TemplateResponse(
        request=request,
        name="correlation_hub.html",
        context={
            "request": request,
            "title": f"Artefact Correlation Hub | {APP_TITLE}",
            "active_tab": "correlation",
            "sessions": sessions,
        },
    )


@router.get("/correlation/{session_id}", response_class=HTMLResponse, tags=["Correlation UI"])
async def correlation_dashboard_page(request: Request, session_id: int):
    """
    Detailed 8-tab correlation dashboard:
      1. Overview & Pipeline Status
      2. Process Analysis & Hierarchy
      3. Network Connections & Sockets
      4. Command History & Execution
      5. Loaded Kernel Modules
      6. Suspicious Activity Findings (Review Interface)
      7. Activity Timeline (Chronological)
      8. Correlation Relationships Graph/Table
    """
    session = get_analysis_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Analysis session {session_id} not found.")

    artefacts = get_artefacts_by_session(session_id)
    links = get_correlations_by_session(session_id)
    findings = get_findings_by_session(session_id)
    timeline = get_timeline_by_session(session_id)

    # Group artefacts by type for tabs
    procs = [a for a in artefacts if a["artefact_type"] == "process"]
    nets = [a for a in artefacts if a["artefact_type"] == "network"]
    cmds = [a for a in artefacts if a["artefact_type"] == "command"]
    mods = [a for a in artefacts if a["artefact_type"] == "module"]

    # Calculate severity counts
    sev_counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        s = f.get("severity", "Medium")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    return templates.TemplateResponse(
        request=request,
        name="correlation.html",
        context={
            "request": request,
            "title": f"Correlation & Findings #{session_id} | {APP_TITLE}",
            "active_tab": "correlation",
            "session": session,
            "artefacts_count": len(artefacts),
            "processes": procs,
            "networks": nets,
            "commands": cmds,
            "modules": mods,
            "links": links,
            "findings": findings,
            "timeline": timeline,
            "severity_counts": sev_counts,
        },
    )


@router.get("/correlation/case/{case_id}", response_class=HTMLResponse, tags=["Correlation UI"])
async def case_findings_page(request: Request, case_id: int):
    """Displays consolidated findings for an entire investigation case."""
    case = get_case_by_id(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    findings = get_findings_by_case(case_id)
    return templates.TemplateResponse(
        request=request,
        name="case_findings.html",
        context={
            "request": request,
            "title": f"Case Findings {case['case_number']} | {APP_TITLE}",
            "active_tab": "correlation",
            "case": case,
            "findings": findings,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# REST API Pipeline & Action Routes
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/api/correlation/pipeline/{session_id}", tags=["Correlation API"])
async def api_run_full_pipeline(session_id: int):
    """
    Executes the complete Phase 4 correlation pipeline in sequence:
      1. Normalise raw Volatility plugin outputs
      2. Correlate parent-child, network sockets, commands and modules
      3. Evaluate heuristic detection rules for suspicious activities
      4. Assemble authentic chronological activity timeline
    """
    session = get_analysis_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")

    # 1. Normalisation
    norm_result = normalise_session(session_id)
    # 2. Correlation
    corr_result = run_all_correlations(session_id)
    # 3. Detection
    detect_result = run_all_detectors(session_id)
    # 4. Timeline
    time_result = build_timeline(session_id)

    findings = get_findings_by_session(session_id)
    links = get_correlations_by_session(session_id)

    return {
        "message": "Correlation pipeline executed successfully.",
        "session_id": session_id,
        "normalisation": norm_result,
        "correlation": corr_result,
        "detection": detect_result,
        "timeline": time_result,
        "total_findings": len(findings),
        "total_links": len(links),
    }


@router.post("/api/correlation/normalise/{session_id}", tags=["Correlation API"])
async def api_normalise(session_id: int):
    session = get_analysis_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    return normalise_session(session_id)


@router.post("/api/correlation/correlate/{session_id}", tags=["Correlation API"])
async def api_correlate(session_id: int):
    session = get_analysis_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    return run_all_correlations(session_id)


@router.post("/api/correlation/detect/{session_id}", tags=["Correlation API"])
async def api_detect(session_id: int):
    session = get_analysis_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    return run_all_detectors(session_id)


@router.post("/api/correlation/timeline/{session_id}", tags=["Correlation API"])
async def api_timeline(session_id: int):
    session = get_analysis_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    return build_timeline(session_id)


@router.get("/api/correlation/artefacts/{session_id}", tags=["Correlation API"])
async def api_get_artefacts(session_id: int, artefact_type: Optional[str] = None):
    artefacts = get_artefacts_by_session(session_id, artefact_type=artefact_type)
    return {"session_id": session_id, "artefacts": artefacts, "count": len(artefacts)}


@router.get("/api/correlation/links/{session_id}", tags=["Correlation API"])
async def api_get_links(session_id: int):
    links = get_correlations_by_session(session_id)
    return {"session_id": session_id, "links": links, "count": len(links)}


@router.get("/api/correlation/findings/{session_id}", tags=["Correlation API"])
async def api_get_findings(session_id: int):
    findings = get_findings_by_session(session_id)
    return {"session_id": session_id, "findings": findings, "count": len(findings)}


@router.put("/api/findings/{finding_id}/review", tags=["Correlation API"])
async def api_update_finding(finding_id: int, payload: FindingUpdateRequest):
    """Updates analyst review determination and commentary."""
    existing = get_finding_by_id(finding_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found.")

    try:
        updated = update_finding_review(
            finding_id=finding_id,
            review_status=payload.review_status,
            analyst_notes=payload.analyst_notes,
            reviewed_by=payload.reviewed_by,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"message": "Finding review status updated.", "finding": updated}


@router.get("/api/correlation/timeline/{session_id}", tags=["Correlation API"])
async def api_get_timeline(session_id: int):
    events = get_timeline_by_session(session_id)
    return {"session_id": session_id, "events": events, "count": len(events)}
