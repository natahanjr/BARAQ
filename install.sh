#!/usr/bin/env bash
# BARAQ SOC - One-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/natahanjr/BARAQ/main/install.sh | bash
set -euo pipefail

BARAQ_REPO="https://github.com/natahanjr/BARAQ.git"
BARAQ_DIR="$HOME/baraq"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     BARAQ SOC Platform Installer        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── 1. Check OS ──────────────────────────────────────────────────────────
info "Checking operating system..."
case "$(uname -s)" in
    Linux*)   OS="linux";;
    Darwin*)  OS="macos";;
    MINGW*|MSYS*|CYGWIN*) OS="windows";;
    *)        err "Unsupported OS: $(uname -s). Use Windows (start.bat) or Docker manually.";;
esac
ok "Detected $OS"

# ── 2. Check / Install Docker ───────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    info "Docker not found. Installing..."
    if [ "$OS" = "linux" ]; then
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER"
        warn "Added you to docker group. Log out and back in for group changes."
    elif [ "$OS" = "macos" ]; then
        err "Install Docker Desktop from https://docs.docker.com/desktop/install/mac-install/"
    fi
    ok "Docker installed"
else
    ok "Docker found: $(docker --version)"
fi

# ── 3. Check / Install Docker Compose ───────────────────────────────────
if ! docker compose version &>/dev/null; then
    info "Docker Compose not found. Installing..."
    if [ "$OS" = "linux" ]; then
        sudo apt-get update && sudo apt-get install -y docker-compose-plugin
    fi
    ok "Docker Compose installed"
else
    ok "Docker Compose found: $(docker compose version --short)"
fi

# ── 4. Clone repo ───────────────────────────────────────────────────────
if [ -d "$BARAQ_DIR/.git" ]; then
    info "BARAQ directory exists at $BARAQ_DIR. Pulling latest..."
    cd "$BARAQ_DIR"
    git pull origin main
else
    info "Cloning BARAQ to $BARAQ_DIR..."
    git clone "$BARAQ_REPO" "$BARAQ_DIR"
    cd "$BARAQ_DIR"
fi
ok "Repository ready"

# ── 5. Setup .env ────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    info "Creating .env from template..."
    cp .env.example .env 2>/dev/null || cat > .env <<'ENVEOF'
# BARAQ Configuration
BARAQ_DATABASE_URL=postgresql+psycopg://baraq:baraq_secret_2026@db:5432/baraq
BARAQ_API_KEYS={"baraq-dev-admin":"admin"}
BARAQ_AUTH_ENABLED=1
BARAQ_TELEMETRY_V2=1
BARAQ_ALERTS_V2=1
BARAQ_CORRELATION=1
BARAQ_RISK=1
BARAQ_BEHAVIOR_GROUPS=1
POSTGRES_DB=baraq
POSTGRES_USER=baraq
POSTGRES_PASSWORD=baraq_secret_2026
ENVEOF
    ok ".env created"
else
    ok ".env already exists"
fi

# ── 6. Start services ───────────────────────────────────────────────────
info "Starting BARAQ with Docker Compose..."
docker compose up -d --build

# ── 7. Wait for health ──────────────────────────────────────────────────
info "Waiting for BARAQ to be healthy..."
for i in $(seq 1 30); do
    if curl -fsS http://localhost:8001/api/health &>/dev/null; then
        break
    fi
    sleep 2
done

# ── 8. Print access info ────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        BARAQ is ready!                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Dashboard:   ${CYAN}http://localhost:8001${NC}"
echo -e "  API Docs:    ${CYAN}http://localhost:8001/docs${NC}"
echo -e "  Health:      ${CYAN}http://localhost:8001/api/health${NC}"
echo ""
echo -e "  Login:       ${YELLOW}admin${NC} / ${YELLOW}BaraqAdmin2026!${NC}"
echo ""
echo -e "  Stop:        ${CYAN}cd $BARAQ_DIR && docker compose down${NC}"
echo -e "  Logs:        ${CYAN}cd $BARAQ_DIR && docker compose logs -f${NC}"
echo -e "  Reset:       ${CYAN}cd $BARAQ_DIR && docker compose down -v${NC}"
echo ""
