"""
FastAPI application entry point.
"""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.database.database import init_db
from app.routers import auth, dashboard, cases, evidence, custody, audit, reports

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    docs_url="/api/docs" if settings.debug else None,
    redoc_url=None,
)

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Register routers
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(cases.router)
app.include_router(evidence.router)
app.include_router(custody.router)
app.include_router(audit.router)
app.include_router(reports.router)


@app.on_event("startup")
async def startup_event():
    """Initialize database and ensure storage directories exist."""
    init_db()
    settings.evidence_storage_dir  # triggers mkdir
    settings.reports_storage_dir


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    from fastapi.responses import HTMLResponse
    from pathlib import Path
    html = Path("app/templates/404.html").read_text(encoding="utf-8")
    return HTMLResponse(content=html, status_code=404)


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    from fastapi.responses import HTMLResponse
    from pathlib import Path
    html = Path("app/templates/500.html").read_text(encoding="utf-8")
    return HTMLResponse(content=html, status_code=500)
