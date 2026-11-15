"""
Analysis Router — Phase 3
──────────────────────────
API + HTML routes for Volatility 3 automated memory analysis.

Endpoints:
  GET  /analysis                     — Analysis hub HTML page
  GET  /analysis/{session_id}        — Per-session results HTML page
  GET  /api/analysis/status          — Vol3 system status (version, paths)
  GET  /api/analysis/plugins         — Full plugin catalog as JSON
  POST /api/analysis/start           — Start a new analysis session
  GET  /api/analysis/sessions        — List all sessions
  GET  /api/analysis/sessions/{id}   — Get one session
  GET  /api/analysis/sessions/{id}/runs — All plugin runs for a session
  GET  /api/analysis/runs/{id}       — Get one plugin run
  GET  /api/analysis/sessions/{id}/export — Export session as JSON
"""
import json
import logging
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.config import TEMPLATES_DIR, APP_TITLE, VOLATILITY_PLUGINS, PLUGIN_TIMEOUT_SECONDS
from app.database import (
    get_all_cases, get_all_evidence, get_evidence_by_id, get_case_by_id,
    get_all_sessions, get_analysis_session, get_sessions_by_evidence,
    get_plugin_runs_by_session, get_plugin_run,
    fail_analysis_session,
)
from app.models import (
    AnalysisStartRequest, AnalysisSessionResponse, PluginRunResponse,
)
from app.services.volatility_runner import (
    detect_volatility, select_plugins, run_analysis_session,
)

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
logger = logging.getLogger("forensics.analysis_router")

# Track in-progress sessions so the UI can poll without re-launching
_running_sessions: dict[int, str] = {}   # evidence_id → "running"


# ─────────────────────────────────────────────────────────────────────────────
# HTML UI Routes
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/analysis", response_class=HTMLResponse, tags=["Analysis UI"])
async def analysis_hub_page(request: Request):
    """Renders the Volatility Analysis Hub where investigators start new runs."""
    vol_status = detect_volatility()
    all_evidence = get_all_evidence()
    all_cases = get_all_cases()
    sessions = get_all_sessions()

    # Enrich evidence with human-readable size
    for ev in all_evidence:
        size = ev.get("file_size_bytes", 0)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                ev["human_size"] = f"{size:.1f} {unit}"
                break
            size /= 1024
        else:
            ev["human_size"] = f"{size:.1f} TB"

    return templates.TemplateResponse(
        request=request,
        name="analysis.html",
        context={
            "request": request,
            "title": f"Volatility Analysis | {APP_TITLE}",
            "active_tab": "analysis",
            "vol_status": vol_status,
            "evidence_list": all_evidence,
            "cases": all_cases,
            "sessions": sessions,
            "plugins_catalog": VOLATILITY_PLUGINS,
        },
    )


@router.get("/analysis/{session_id}", response_class=HTMLResponse, tags=["Analysis UI"])
async def analysis_session_page(request: Request, session_id: int):
    """Renders the detailed results page for a completed or running analysis session."""
    session = get_analysis_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Analysis session {session_id} not found.")

    runs = get_plugin_runs_by_session(session_id)

    # Group runs by category for tabbed display
    categories: dict = {}
    for run in runs:
        cat = run.get("category") or "General"
        categories.setdefault(cat, []).append(run)
        # Deserialize parsed_json for template use
        if run.get("parsed_json"):
            try:
                run["parsed_rows"] = json.loads(run["parsed_json"])
            except Exception:
                run["parsed_rows"] = []
        else:
            run["parsed_rows"] = []

    return templates.TemplateResponse(
        request=request,
        name="analysis_detail.html",
        context={
            "request": request,
            "title": f"Analysis Session #{session_id} | {APP_TITLE}",
            "active_tab": "analysis",
            "session": session,
            "runs": runs,
            "categories": categories,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# REST API Routes
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/api/analysis/status", tags=["Analysis API"])
async def api_vol_status():
    """Returns real-time Volatility 3 installation status and version."""
    return detect_volatility()


@router.get("/api/analysis/plugins", tags=["Analysis API"])
async def api_plugin_catalog(os_family: Optional[str] = None):
    """
    Returns the full plugin catalog as JSON.
    If os_family is provided (windows/linux), filters to matching plugins.
    """
    plugins = select_plugins(os_family or "any")
    return {"plugins": plugins, "count": len(plugins)}


@router.post(
    "/api/analysis/start",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Analysis API"],
)
async def api_start_analysis(
    payload: AnalysisStartRequest,
    background_tasks: BackgroundTasks,
):
    """
    Starts a Volatility 3 analysis session in the background.

    Steps performed asynchronously:
      1. Verify SHA-256 of the evidence file.
      2. Detect OS via banners plugin.
      3. Run all appropriate plugins.
      4. Store results in SQLite.

    Returns immediately with a session_id so the UI can poll for progress.
    """
    ev = get_evidence_by_id(payload.evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence {payload.evidence_id} not found.")

    stored_path = ev.get("stored_path", "")
    if not Path(stored_path).exists():
        raise HTTPException(
            status_code=404,
            detail="Evidence file not found on disk. It may have been moved or deleted."
        )

    baseline_hash = ev["sha256_hash"]
    case_id = ev["case_id"]

    # Run in background so the HTTP response is returned immediately
    background_tasks.add_task(
        _run_analysis_background,
        image_path=stored_path,
        evidence_id=payload.evidence_id,
        case_id=case_id,
        baseline_hash=baseline_hash,
        plugin_keys=payload.plugin_keys,
        timeout=payload.timeout,
    )

    return {
        "message": "Analysis started in background.",
        "evidence_id": payload.evidence_id,
        "evidence_filename": ev["filename"],
        "note": "Poll GET /api/analysis/sessions to check for the completed session.",
    }


async def _run_analysis_background(
    image_path: str,
    evidence_id: int,
    case_id: int,
    baseline_hash: str,
    plugin_keys: Optional[List[str]],
    timeout: int,
):
    """Background coroutine that calls the synchronous analysis engine."""
    import asyncio
    loop = asyncio.get_event_loop()
    # Run the synchronous (blocking) function in a thread pool so it does not block FastAPI
    await loop.run_in_executor(
        None,
        lambda: run_analysis_session(
            image_path=image_path,
            evidence_id=evidence_id,
            case_id=case_id,
            baseline_hash=baseline_hash,
            requested_plugin_keys=plugin_keys,
            timeout=timeout,
        )
    )


@router.get("/api/analysis/sessions", tags=["Analysis API"])
async def api_list_sessions(evidence_id: Optional[int] = None):
    """Returns all analysis sessions, optionally filtered by evidence_id."""
    if evidence_id is not None:
        sessions = get_sessions_by_evidence(evidence_id)
    else:
        sessions = get_all_sessions()
    return {"sessions": sessions, "count": len(sessions)}


@router.get("/api/analysis/sessions/{session_id}", tags=["Analysis API"])
async def api_get_session(session_id: int):
    """Returns a single analysis session record."""
    session = get_analysis_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    return session


@router.get("/api/analysis/sessions/{session_id}/runs", tags=["Analysis API"])
async def api_get_session_runs(session_id: int):
    """Returns all plugin runs for one analysis session."""
    session = get_analysis_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    runs = get_plugin_runs_by_session(session_id)
    return {"session_id": session_id, "runs": runs, "count": len(runs)}


@router.get("/api/analysis/runs/{run_id}", tags=["Analysis API"])
async def api_get_run(run_id: int):
    """Returns a single plugin run record including raw output and parsed rows."""
    run = get_plugin_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Plugin run {run_id} not found.")
    # Parse JSON for the response
    if run.get("parsed_json"):
        try:
            run["parsed_rows"] = json.loads(run["parsed_json"])
        except Exception:
            run["parsed_rows"] = []
    return run


@router.get("/api/analysis/sessions/{session_id}/export", tags=["Analysis API"])
async def api_export_session(session_id: int):
    """
    Exports a complete analysis session (session metadata + all plugin results)
    as a downloadable JSON file.
    """
    session = get_analysis_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")

    runs = get_plugin_runs_by_session(session_id)

    # Parse stored JSON in each run for the export
    for run in runs:
        if run.get("parsed_json"):
            try:
                run["parsed_rows"] = json.loads(run["parsed_json"])
            except Exception:
                run["parsed_rows"] = []
        else:
            run["parsed_rows"] = []
        # Remove raw binary blobs if very large to keep JSON manageable
        if run.get("raw_output") and len(run["raw_output"]) > 50000:
            run["raw_output"] = run["raw_output"][:50000] + "\n... [TRUNCATED]"

    export_data = {
        "export_type": "volatility3_analysis_session",
        "tool": "CloudAware Memory Forensics Platform",
        "session": session,
        "plugin_runs": runs,
        "total_runs": len(runs),
    }

    return JSONResponse(
        content=export_data,
        headers={
            "Content-Disposition": f"attachment; filename=session_{session_id}_export.json"
        },
    )
