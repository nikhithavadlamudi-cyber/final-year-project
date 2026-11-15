"""
Dashboard Router
Serves the primary analytical dashboard, system health checks, and module navigation.
"""
import sys
import json
import platform
import shutil
from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.config import TEMPLATES_DIR, APP_TITLE, DB_PATH, UPLOAD_DIR
from app.database import get_dashboard_statistics, get_all_cases

router = APIRouter()
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def check_volatility_status() -> dict:
    """Checks whether Volatility 3 is installed, accessible, and reports its version."""
    try:
        import volatility3
        version = getattr(volatility3, "__version__", "Available")
        return {
            "installed": True,
            "version": version,
            "path": getattr(volatility3, "__file__", "Unknown"),
            "status": "Operational"
        }
    except ImportError as e:
        return {
            "installed": False,
            "version": None,
            "error": str(e),
            "status": "Not Installed"
        }


@router.get("/", response_class=HTMLResponse, tags=["Dashboard UI"])
async def dashboard_page(request: Request):
    """Renders the central forensic operations dashboard."""
    stats = get_dashboard_statistics()
    recent_cases = get_all_cases()[:6]
    vol_status = check_volatility_status()
    
    # Disk usage in uploads directory
    total, used, free = shutil.disk_usage(str(UPLOAD_DIR))
    disk_info = {
        "free_gb": round(free / (1024**3), 2),
        "total_gb": round(total / (1024**3), 2),
        "percent_used": round((used / total) * 100, 1)
    }

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "title": f"Operations Dashboard | {APP_TITLE}",
            "active_tab": "dashboard",
            "stats": stats,
            "recent_cases": recent_cases,
            "vol_status": vol_status,
            "disk_info": disk_info,
            "python_version": platform.python_version(),
            "os_info": f"{platform.system()} {platform.release()}"
        }
    )


@router.get("/api/dashboard/stats", tags=["Dashboard API"])
async def api_dashboard_stats():
    """Returns aggregated case and evidence statistics in JSON."""
    return get_dashboard_statistics()


@router.get("/api/system/status", tags=["Dashboard API"])
async def api_system_status():
    """Returns real-time health metrics of the database and forensic backend."""
    vol_status = check_volatility_status()
    db_exists = DB_PATH.exists()
    db_size_kb = round(DB_PATH.stat().st_size / 1024, 2) if db_exists else 0
    
    return {
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python_version": sys.version.split()[0],
        "database": {
            "path": str(DB_PATH),
            "healthy": db_exists,
            "size_kb": db_size_kb
        },
        "volatility_framework": vol_status,
        "active_phase": "Phase 1: Project Foundation & Dashboard"
    }


# =====================================================================
# Six-Module Navigation Router Endpoints
# =====================================================================

MODULE_DEFINITIONS = {
    2: {
        "number": 2,
        "title": "Module 2: Memory Image Ingestion & SHA-256 Integrity",
        "badge": "Phase 2 (Next Step)",
        "icon": "shield-check",
        "summary": "Accepts memory images (RAW, MEM, DMP), validates file constraints, generates cryptographic SHA-256 hashes, and securely records acquisition provenance without altering original evidence.",
        "requirements": [
            "Support RAW, MEM, DMP forensic memory dumps.",
            "Cryptographic SHA-256 hash calculation upon receipt.",
            "Record acquisition source (IaaS Guest VM vs. Physical RAM).",
            "Integrity verification against initial baseline hash.",
            "Secure, read-only evidence file storage protection."
        ]
    },
    3: {
        "number": 3,
        "title": "Module 3: Volatility 3 Automated Analysis Engine",
        "badge": "Phase 3 (Scheduled)",
        "icon": "cpu",
        "summary": "Integrates the Volatility 3 framework to inspect memory dumps, automatically detecting OS symbols and running core forensic plugins.",
        "requirements": [
            "Volatility 3 framework integration with CLI/Python APIs.",
            "Automatic OS architecture and symbol identification.",
            "Process extraction (pslist, pstree, psscan).",
            "Network connection extraction (netscan, netstat).",
            "Loaded drivers & DLL modules extraction (modules, ldrmodules).",
            "Command-line history & console activity recovery (cmdline)."
        ]
    },
    4: {
        "number": 4,
        "title": "Module 4: Evidence Analysis & Correlation Engine",
        "badge": "Phase 4 (Scheduled)",
        "icon": "git-merge",
        "summary": "Correlates processes, network sockets, injected modules, and command history into unified JSON evidence schemas with suspicious indicator scoring.",
        "requirements": [
            "Standardized JSON normalization for all plugin outputs.",
            "Process-to-Network connection correlation.",
            "Unified chronological forensic activity timeline.",
            "Rule-based detection for suspicious parent-child process anomalies.",
            "Transparent confidence scoring and forensic limitation disclaimers."
        ]
    },
    5: {
        "number": 5,
        "title": "Module 5: Cloud-Aware Evidence Management & Reporting",
        "badge": "Phase 5 (Scheduled)",
        "icon": "cloud",
        "summary": "Differentiates IaaS (guest VM volatile RAM) and SaaS (provider audit logs) evidence, models legal/access boundaries, and produces exportable audit reports.",
        "requirements": [
            "IaaS Guest Memory Evidence category with hypervisor provenance.",
            "SaaS Audit Evidence category (API logs, admin exports).",
            "Clear documentation of SaaS host RAM access barriers (provider limitation).",
            "Comprehensive chain-of-custody logging with analyst timestamps.",
            "PDF and HTML formal forensic investigation report generation."
        ]
    },
    6: {
        "number": 6,
        "title": "Module 6: Testing, Evaluation & Final Demonstration",
        "badge": "Phase 6 (Operational)",
        "icon": "check-circle",
        "summary": "Benchmarking and scientific evaluation comparing automated vs. manual analysis time, repeatability, and ground-truth recovery metrics on public test memory images.",
        "requirements": [
            "Automated test suite across all 6 core modules.",
            "Evaluation on public forensic memory test images.",
            "Empirical analysis: Manual vs. Automated recovery time.",
            "Artifact recovery coverage and plugin execution success rate.",
            "Final academic demonstration guide and viva presentation workflow."
        ]
    }
}


@router.get("/evaluation", response_class=HTMLResponse, tags=["Evaluation UI"])
async def evaluation_page(request: Request):
    """Renders the comprehensive Phase 6 testing and evaluation benchmark dashboard."""
    vol_status = check_volatility_status()
    stats = get_dashboard_statistics()

    eval_json_path = DB_PATH.parent / "reports" / "experimental_evaluation.json"
    eval_data = {}
    if eval_json_path.exists():
        try:
            with open(eval_json_path, "r", encoding="utf-8") as f:
                eval_data = json.load(f)
        except Exception:
            eval_data = {}

    return templates.TemplateResponse(
        request=request,
        name="evaluation.html",
        context={
            "request": request,
            "title": f"Testing & Evaluation Center | {APP_TITLE}",
            "active_tab": "evaluation",
            "stats": stats,
            "vol_status": vol_status,
            "eval_data": eval_data,
            "summary_metrics": eval_data.get("summary_metrics", {})
        }
    )


@router.get("/api/evaluation/benchmarks", tags=["Evaluation API"])
async def api_get_benchmarks():
    """Returns the latest empirical evaluation metrics and experiment results."""
    eval_json_path = DB_PATH.parent / "reports" / "experimental_evaluation.json"
    if eval_json_path.exists():
        with open(eval_json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"error": "Evaluation benchmarks not found. Run tests/run_experiments.py to generate."}


@router.post("/api/evaluation/run", tags=["Evaluation API"])
async def api_run_benchmarks():
    """Re-executes the 7 empirical experiments and returns fresh metrics."""
    from tests.run_experiments import run_all_experiments
    results = run_all_experiments()
    return {"message": "Empirical evaluation suite executed successfully.", "results": results}


@router.get("/modules/{mod_id}", response_class=HTMLResponse, tags=["Modules Navigation"])
async def module_preview_page(request: Request, mod_id: int):
    """Renders the navigation view for all 6 modules of the forensic pipeline."""
    if mod_id not in MODULE_DEFINITIONS:
        mod_info = {
            "number": mod_id,
            "title": f"Module {mod_id}",
            "badge": "Pending Development",
            "summary": "This module is slated for subsequent phase implementation.",
            "requirements": []
        }
    else:
        mod_info = MODULE_DEFINITIONS[mod_id]

    return templates.TemplateResponse(
        request=request,
        name="module_placeholder.html",
        context={
            "request": request,
            "title": f"{mod_info['title']} | {APP_TITLE}",
            "active_tab": f"module_{mod_id}",
            "module": mod_info
        }
    )
