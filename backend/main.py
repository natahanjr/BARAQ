"""SentinelSOC FastAPI application."""
from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from backend.api import (
    alerts,
    assistant,
    dashboard,
    evaluation,
    events,
    investigation,
    reports,
    system,
)
from backend.config import API_KEYS, AUTH_ENABLED, CORS_ORIGINS, REPORT_DIR
from backend.database.connection import SessionLocal, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger("sentinel")

_scheduler_thread: threading.Thread | None = None
_scheduler_stop = threading.Event()


def _scheduler_loop(interval_seconds: int = 15):
    """Background collection + detection loop."""
    logger.info("Scheduler started (interval=%ss)", interval_seconds)
    from backend.analyzers import dashboard
    from backend.collectors import CollectorManager
    from backend.database.connection import SessionLocal
    from backend.ml.anomaly import get_detector

    manager = CollectorManager()
    from backend.api.system import run_pipeline

    counter = 0
    while not _scheduler_stop.is_set():
        try:
            db = SessionLocal()
            try:
                records = manager.collect()
                if records:
                    result = run_pipeline(db, records)
                    logger.info(
                        "Scheduler cycle: %d records, %d new alerts",
                        result["collected"], result["alerts_created"],
                    )
                counter += 1
                if counter % 20 == 0:
                    dashboard.snapshot(db)
                if counter % 10 == 0 and get_detector().is_ready:
                    get_detector().analyze_events(db, hours=1)
            finally:
                db.close()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Scheduler cycle failed: %s", exc)
        _scheduler_stop.wait(interval_seconds)
    logger.info("Scheduler stopped")


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    import os

    init_db()
    global _scheduler_thread
    no_scheduler = os.environ.get("SENTINEL_NO_SCHEDULER", "0").lower() in (
        "1", "true", "yes", "on",
    )
    if not no_scheduler and (not _scheduler_thread or not _scheduler_thread.is_alive()):
        _scheduler_stop.clear()
        from backend.config import COLLECT_INTERVAL_SECONDS
        _scheduler_thread = threading.Thread(
            target=_scheduler_loop, args=(COLLECT_INTERVAL_SECONDS,), daemon=True
        )
        _scheduler_thread.start()
    logger.info("SentinelSOC API is ready")
    yield
    _scheduler_stop.set()
    if _scheduler_thread:
        _scheduler_thread.join(timeout=5)
    logger.info("SentinelSOC API shut down")


app = FastAPI(
    title="SentinelSOC API",
    description=(
        "Intelligent Lightweight Security Operations Center Platform for "
        "Real-Time Windows Threat Detection and Incident Analysis"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# API key authentication (RBAC). Every /api/* request must carry a valid
# X-API-Key; the resolved role is stored on request.state for the endpoint
# role dependencies (require_auth / require_admin in backend/security.py).
# Health, docs and static mounts are excluded.
# ---------------------------------------------------------------------------
_PUBLIC_PREFIXES = ("/api/health", "/docs", "/openapi.json", "/redoc")


@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    path = request.url.path
    if AUTH_ENABLED and path.startswith("/api/") and not path.startswith(_PUBLIC_PREFIXES):
        key = request.headers.get("X-API-Key", "").strip()
        role = API_KEYS.get(key)
        if not role:
            return JSONResponse(
                {"detail": "Missing or invalid API key (X-API-Key header)"},
                status_code=401,
            )
        request.state.api_role = role
    elif AUTH_ENABLED:
        request.state.api_role = "admin"
    else:
        request.state.api_role = "admin"
    return await call_next(request)

for router in (
    dashboard.router,
    alerts.router,
    events.router,
    investigation.router,
    reports.router,
    assistant.router,
    evaluation.router,
    system.router,
):
    app.include_router(router)

app.mount("/reports", StaticFiles(directory=REPORT_DIR), name="reports")


@app.get("/")
def root():
    return {
        "application": "SentinelSOC",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/system/status",
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Serve the built React SPA (single-command deployment). Registered last so the
# API routes above always take precedence; unknown paths fall back to
# index.html to support client-side routing.
# ---------------------------------------------------------------------------
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


class _SPAMount(StaticFiles):
    """Serve the built SPA, falling back to index.html for client routes."""

    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code == 404:
                index = FRONTEND_DIST / "index.html"
                if index.is_file():
                    return FileResponse(index)
            raise


if FRONTEND_DIST.is_dir():
    app.mount("/", _SPAMount(directory=FRONTEND_DIST, html=True), name="frontend")
