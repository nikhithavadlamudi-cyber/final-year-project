"""
FastAPI Application Entry Point
Configures routes, static asset hosting, template engine, and startup lifecycle.
"""
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import APP_TITLE, APP_VERSION, APP_DESCRIPTION, STATIC_DIR
from app.database import init_db
from app.routers import dashboard, cases, evidence, analysis, correlation, cloud_evidence, reports

# Initialize FastAPI instance
app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    description=APP_DESCRIPTION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for local API access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (CSS, JS, assets)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.on_event("startup")
async def on_startup():
    """Initializes SQLite database schemas on application launch."""
    init_db()


# Include Application Routers
app.include_router(dashboard.router)
app.include_router(cases.router)
app.include_router(evidence.router)
app.include_router(analysis.router)
app.include_router(correlation.router)
app.include_router(cloud_evidence.router)
app.include_router(reports.router)


@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    """Graceful JSON or HTML 404 response."""
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=404, content={"error": "Endpoint not found", "path": request.url.path})
    return JSONResponse(status_code=404, content={"message": "Forensic resource or page not found."})
