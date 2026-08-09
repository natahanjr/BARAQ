"""SentinelSOC FastAPI application."""
from __future__ import annotations

import asyncio
import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException

from backend.api import (
    alerts,
    assistant,
    auth,
    dashboard,
    endpoints,
    evaluation,
    events,
    graph,
    incidents,
    intel,
    investigation,
    reports,
    realtime,
    system,
)
from backend.auth import verify_token
from backend.config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    API_KEYS,
    AUTH_ENABLED,
    CORS_ORIGINS,
    IS_PRODUCTION,
    METRICS_PUBLIC,
    REPORT_DIR,
    SENTINEL_ENV,
    SINGLE_INSTANCE,
)
from backend.database.connection import SessionLocal, get_db, init_db
from backend.logging_config import setup_logging

setup_logging()
logger = logging.getLogger("sentinel")

def _seed_admin_user() -> None:
    """Create the bootstrap admin account if the users table is empty."""
    from sqlalchemy import select

    from backend.auth import hash_password
    from backend.database.models import User

    db = SessionLocal()
    try:
        if db.scalar(select(User).limit(1)):
            return
        admin = User(
            username=ADMIN_USERNAME,
            password_hash=hash_password(ADMIN_PASSWORD),
            role="admin",
            full_name="SentinelSOC Administrator",
            is_active=True,
        )
        db.add(admin)
        db.commit()
        logger.info("Seeded bootstrap admin user '%s'", ADMIN_USERNAME)
    finally:
        db.close()


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
                from sqlalchemy import func, select

                from backend.config import ML_TRAIN_MIN_SAMPLES
                from backend.database.models import NormalizedEvent

                records = manager.collect()
                if records:
                    result = run_pipeline(db, records)
                    logger.info(
                        "Scheduler cycle: %d records, %d new alerts",
                        result["collected"], result["alerts_created"],
                    )
                counter += 1
                from backend.realtime import publish_status

                publish_status({"summary": dashboard.dashboard_summary(db)})
                if counter % 20 == 0:
                    dashboard.snapshot(db)
                if counter % 4 == 0 and get_detector().is_ready:
                    get_detector().analyze_events(db, hours=1)
                if counter % 4 == 0:
                    stale, reason = get_detector().is_stale(db)
                    if stale:
                        if reason == "never-trained":
                            total_events = db.scalar(
                                select(func.count(NormalizedEvent.id))
                            ) or 0
                            if total_events >= ML_TRAIN_MIN_SAMPLES:
                                logger.info(
                                    "ML never trained; initial auto-training on %d events",
                                    total_events,
                                )
                                get_detector().train(db, hours=24, validate=False)
                        else:
                            logger.info("ML model stale (%s); retraining", reason)
                            get_detector().train(db, hours=24, validate=False)
                if counter % 240 == 0:  # every ~1 hour (240 cycles x 15s)
                    from backend.database.retention import purge_old_data
                    purged = purge_old_data(db)
                    if any(purged.values()):
                        logger.info(
                            "Retention: purged %d old record(s)",
                            sum(purged.values()),
                        )
            finally:
                db.close()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Scheduler cycle failed: %s", exc)
        _scheduler_stop.wait(interval_seconds)
    logger.info("Scheduler stopped")


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    import os

    from backend.realtime import hub

    hub.bind(asyncio.get_running_loop())
    init_db()
    _seed_admin_user()
    from backend.locks import acquire_instance_lock, release_instance_lock

    global _scheduler_thread
    no_scheduler = os.environ.get("SENTINEL_NO_SCHEDULER", "0").lower() in (
        "1", "true", "yes", "on",
    )
    scheduler_owner = True
    if SINGLE_INSTANCE:
        from backend.database.connection import engine as app_engine

        scheduler_owner = acquire_instance_lock(app_engine)
        if not scheduler_owner:
            logger.critical(
                "Another SentinelSOC instance holds the instance lock; "
                "scheduler is DISABLED here (API reads still served). Start "
                "only one server or set SENTINEL_SINGLE_INSTANCE=0."
            )
    if scheduler_owner and not no_scheduler and (
        not _scheduler_thread or not _scheduler_thread.is_alive()
    ):
        _scheduler_stop.clear()
        from backend.config import COLLECT_INTERVAL_SECONDS
        _scheduler_thread = threading.Thread(
            target=_scheduler_loop, args=(COLLECT_INTERVAL_SECONDS,), daemon=True
        )
        _scheduler_thread.start()
    from backend.streaming import start as start_streaming

    start_streaming()
    logger.info(
        "SentinelSOC API is ready (profile=%s%s, scheduler=%s)",
        SENTINEL_ENV,
        ", production gate active" if IS_PRODUCTION else "",
        "on" if scheduler_owner and not no_scheduler else "off",
    )
    yield
    _scheduler_stop.set()
    if _scheduler_thread:
        _scheduler_thread.join(timeout=5)
    release_instance_lock()
    logger.info("SentinelSOC API shut down")


app = FastAPI(
    title="SentinelSOC API",
    description=(
        "Intelligent Lightweight Security Operations Center Platform for "
        "Real-Time Windows Threat Detection and Incident Analysis"
    ),
    version="1.0.0",
    lifespan=lifespan,
    # Production profile hides the interactive API surface (schema leaks
    # endpoints/fields and invites attack-surface probing).
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
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
_PUBLIC_PREFIXES = (
    "/api/health",
    "/api/auth/login",
    "/api/auth/mfa/verify",
    "/api/auth/oidc/login",
    "/api/auth/oidc/callback",
    "/api/auth/oidc/status",
    "/docs", "/openapi.json", "/redoc",
)
#: Routes that authenticate with their own scheme (X-Agent-Key) instead of X-API-Key.
_AGENT_PATHS = ("/api/ingest", "/api/commands/")
#: Methods that change server state; cookie-authenticated calls to these must
#: carry a valid CSRF token (see api_key_auth below).
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_CSRF_HEADER = "X-CSRF-Token"


def _csrf_token_matches(request: Request) -> bool:
    """Double-submit CSRF check: the X-CSRF-Token header must equal the
    sentinel_csrf cookie value (constant-time compare). Only meaningful for
    cookie-authenticated browser sessions."""
    from backend.config import CSRF_ENABLED
    if not CSRF_ENABLED:
        return True
    cookie = request.cookies.get("sentinel_csrf", "")
    header = request.headers.get(_CSRF_HEADER, "")
    if not cookie or not header:
        return False
    import hmac
    return hmac.compare_digest(cookie, header)


@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    path = request.url.path
    if AUTH_ENABLED and path.startswith("/api/") and not path.startswith(_PUBLIC_PREFIXES) and not path.startswith(_AGENT_PATHS):
        # New session-token auth: Authorization: Bearer <token> (or the
        # httpOnly session cookie set at login, so the token never touches JS).
        authorization = request.headers.get("Authorization", "")
        from_cookie = False
        if not authorization.lower().startswith("bearer "):
            session = request.cookies.get("sentinel_session", "")
            if session:
                authorization = f"Bearer {session}"
                from_cookie = True
        if authorization.lower().startswith("bearer "):
            secret = authorization[7:].strip()
            payload = verify_token(secret)
            if not payload:
                # Prometheus-style scrapers send the shared key as a Bearer
                # secret (Prometheus v3 no longer supports custom headers).
                role = API_KEYS.get(secret)
                if not role:
                    return JSONResponse(
                        {"detail": "Invalid or expired session token"},
                        status_code=401,
                    )
                request.state.api_role = role
                request.state.token_user = None
                return await call_next(request)
            request.state.api_role = payload.get("role", "analyst")
            request.state.token_user = payload
            # CSRF: when the session came from the cookie (browser flow),
            # state-changing calls must echo the double-submit token. API
            # callers with an explicit Authorization header cannot be CSRF'd.
            if (
                from_cookie
                and request.method in _STATE_CHANGING_METHODS
                and not _csrf_token_matches(request)
            ):
                return JSONResponse(
                    {"detail": "CSRF token missing or invalid (X-CSRF-Token)"},
                    status_code=403,
                )
        else:
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


@app.middleware("http")
async def request_body_limit(request: Request, call_next):
    """Reject oversized bodies (413) before routing or parsing them.

    Checks Content-Length when present and also guards chunked/streamed
    bodies whose final size is unknown up front.
    """
    from backend.config import MAX_REQUEST_BYTES

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    {"detail": f"Request body exceeds {MAX_REQUEST_BYTES} bytes"},
                    status_code=413,
                )
        except ValueError:
            pass  # malformed Content-Length is handled by the server

    receive = request._receive
    received = 0

    async def limited_receive():
        nonlocal received
        message = await receive()
        if message["type"] == "http.request":
            received += len(message.get("body", b""))
            if received > MAX_REQUEST_BYTES:
                raise _BodyTooLargeError()
        return message

    request._receive = limited_receive
    try:
        return await call_next(request)
    except _BodyTooLargeError:
        return JSONResponse(
            {"detail": f"Request body exceeds {MAX_REQUEST_BYTES} bytes"},
            status_code=413,
        )


class _BodyTooLargeError(Exception):
    """Raised by the receive wrapper when a streamed body exceeds the cap."""

for router in (
    dashboard.router,
    alerts.router,
    events.router,
    investigation.router,
    reports.router,
    assistant.router,
    evaluation.router,
    system.router,
    endpoints.router,
    incidents.router,
    intel.router,
    graph.router,
    auth.router,
    realtime.router,
):
    app.include_router(router)

app.mount("/reports", StaticFiles(directory=REPORT_DIR), name="reports")


@app.get("/api/health")
def health():
    from backend.locks import instance_lock_status

    return {"status": "ok", "single_instance": instance_lock_status()}


@app.get("/metrics")
def prometheus_metrics(db: Session = Depends(get_db)):
    """Public Prometheus scrape target. Requires SENTINEL_METRICS_PUBLIC=1
    (otherwise a scraper must use the authenticated /api/system/metrics route)."""
    from fastapi.responses import Response

    if not METRICS_PUBLIC:
        raise HTTPException(status_code=401, detail="Metrics endpoint is private")
    from backend.metrics import collect_metrics

    return Response(collect_metrics(db), media_type="text/plain; version=0.0.4")


# ---------------------------------------------------------------------------
# Serve the built React SPA (single-command deployment). Registered last so the
# API routes above always take precedence; unknown paths fall back to
# index.html to support client-side routing.
# ---------------------------------------------------------------------------
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


_ASSET_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript",
    ".css": "text/css",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
}


class _SPAMount(StaticFiles):
    """Serve the built SPA, falling back to index.html for client routes.

    Cache policy (prevents the "black screen" symptom caused by a stale
    cached index.html referencing hashed assets that no longer exist):
      * index.html (and any SPA fallback) -> ``no-store``; the browser must
        always fetch the latest entry point so it picks up new asset hashes.
      * /assets/* built files are content-hashed by Vite -> immutable caching.
    """

    def _apply_cache(self, path: str, response) -> "Response":
        # ``path`` may arrive with a leading slash and, on Windows, as a native
        # path using backslashes (e.g. ``assets\\index-...js``).
        normalized = path.replace("\\", "/").lstrip("/")
        if normalized.startswith("assets/"):
            # Hashed by Vite: safe to cache forever in the browser.
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            # The SPA entry point must never be cached so the browser always
            # picks up the latest hashed asset references.
            response.headers["Cache-Control"] = "no-store"
        return response

    async def get_response(self, path: str, scope):
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code == 404:
                # Production profile: the interactive API surface is disabled
                # at construction; don't let the SPA fallback present those
                # known paths as valid routes (masked 200s are probe bait).
                if IS_PRODUCTION and path.lstrip("/").lower() in (
                    "docs", "redoc", "openapi.json",
                ):
                    raise
                index = FRONTEND_DIST / "index.html"
                if index.is_file():
                    return self._apply_cache(
                        "index.html",
                        FileResponse(index, media_type="text/html; charset=utf-8"),
                    )
            raise
        return self._apply_cache(path, response)


if FRONTEND_DIST.is_dir():
    app.mount("/", _SPAMount(directory=FRONTEND_DIST, html=True), name="frontend")
