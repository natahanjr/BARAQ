# BARAQ SOC - Production multi-stage Dockerfile.
#
# Multi-stage: Node builds the SPA, Python serves everything.
# Supports both API-only and combined API+scheduler modes.
#
# Build:
#   docker build -t baraq/soc:latest .
# Run:
#   docker run -p 8001:8001 -e BARAQ_DATABASE_URL=... baraq/soc:latest

# ---------- Stage 1: frontend build -----------------------------------------
FROM node:22-alpine AS web
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci || npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: backend ------------------------------------------------
FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BARAQ_ROLE=api \
    BARAQ_TELEMETRY_V2=1 \
    BARAQ_ALERTS_V2=1 \
    BARAQ_CORRELATION=1 \
    BARAQ_RISK=1 \
    BARAQ_BEHAVIOR_GROUPS=1 \
    BARAQ_V2_ENGINES_ALLOW_PROD=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 baraq

WORKDIR /app

# Install Python dependencies (use Docker-specific requirements without pywin32)
COPY requirements-docker.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend ./backend
COPY alembic.ini ./
COPY alembic ./alembic/
COPY start_dev.py ./

# Copy frontend build from Stage 1
COPY --from=web /src/dist ./frontend/dist

# Create runtime directories
RUN mkdir -p frontend/dist reports logs backups datasets \
    && chown -R baraq:baraq /app

USER baraq
EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8001/api/health || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["python", "start_dev.py"]
