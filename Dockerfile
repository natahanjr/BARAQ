# BARAQ SOC - Linux API/scheduler image (roadmap 5.1 CI-CD).
#
# The collectors are Windows-native (Sysmon / ETW / DPAPI vault / toasts), so
# this image targets the stateless roles only:
#   * BARAQ_ROLE=api       - uvicorn serving backend.main:app
#   * BARAQ_ROLE=scheduler - python -m backend.scheduler_service
# Agent / host data still comes from Windows agents (scripts/agent.py) and
# the on-prem PostgreSQL primary.
#
# Build:
#   docker build -t baraq/soc:latest .
# Multi-stage: node builds the SPA into frontend/dist, python serves it.

# ---------- Stage 1: frontend -------------------------------------------------
FROM node:20-alpine AS web
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci || npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: backend --------------------------------------------------
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    BARAQ_ROLE=api

RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 baraq

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY --from=web /src/dist ./frontend/dist
# The SPA mount requires the directory to exist even when a deployment ships
# without the frontend build.
RUN mkdir -p frontend/dist reports logs

USER baraq
EXPOSE 8000

# Healthcheck hits the unauthenticated /api/health endpoint. Anything
# under /api/system/* requires X-API-Key (BARAQ_AUTH_ENABLED=1 default),
# so using /api/system/status here would 401 and the container would be
# marked unhealthy on every start.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
