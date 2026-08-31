#!/usr/bin/env bash
# ==============================================================================
# DecodeX — One-Command First-Run Evaluation Setup
# ==============================================================================
# This script initializes an evaluation environment for DecodeX:
# 1. Verifies prerequisites (Docker, Docker Compose, Python 3).
# 2. Generates secure, high-entropy cryptographic keys into .env if not present.
# 3. Starts all containers via Docker Compose.
#
# NOTE: Auto-generated keys are strictly for LOCAL / EVALUATION use.
# For production deployments, configure dedicated, persistent secrets manually.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
RED="\033[0;31m"
NC="\033[0m"

echo -e "${BOLD}${BLUE}"
echo "================================================================"
echo "    DecodeX Threat Hunting & Web Security Platform"
echo "    First-Run Evaluation Initializer"
echo "================================================================"
echo -e "${NC}"

# 1. Prerequisite Checks
if ! command -v docker &>/dev/null; then
    echo -e "${RED}[ERROR] Docker is not installed or not in PATH.${NC}"
    echo "Please install Docker Desktop or Docker Engine: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker compose version &>/dev/null; then
    echo -e "${RED}[ERROR] Docker Compose (v2) is not available.${NC}"
    echo "Please ensure Docker Compose v2 is installed."
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[ERROR] Python 3 is required for secure key generation.${NC}"
    exit 1
fi

# 2. Environment Configuration
ENV_FILE="${ROOT_DIR}/.env"
BACKEND_ENV_FILE="${ROOT_DIR}/backend/.env"

if [ ! -f "${ENV_FILE}" ]; then
    echo -e "${YELLOW}[INFO] .env not found. Initializing from .env.example...${NC}"
    if [ ! -f "${ROOT_DIR}/.env.example" ]; then
        echo -e "${RED}[ERROR] .env.example template missing.${NC}"
        exit 1
    fi
    cp "${ROOT_DIR}/.env.example" "${ENV_FILE}"

    echo -e "${BLUE}[INFO] Generating secure cryptographic keys for evaluation...${NC}"
    GEN_ENCRYPTION_KEY="$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")"
    GEN_SECRET_KEY="$(python3 -c "import secrets; print(secrets.token_hex(32))")"
    GEN_ZAP_KEY="$(python3 -c "import secrets; print(secrets.token_hex(16))")"

    # Inject generated keys into .env
    sed -i.bak -e "s|^ENCRYPTION_KEY=.*|ENCRYPTION_KEY=${GEN_ENCRYPTION_KEY}|" "${ENV_FILE}"
    sed -i.bak -e "s|^SECRET_KEY=.*|SECRET_KEY=${GEN_SECRET_KEY}|" "${ENV_FILE}"
    sed -i.bak -e "s|^ZAP_API_KEY=.*|ZAP_API_KEY=${GEN_ZAP_KEY}|" "${ENV_FILE}"
    rm -f "${ENV_FILE}.bak"

    # Sync to backend/.env
    cp "${ENV_FILE}" "${BACKEND_ENV_FILE}"

    echo -e "${GREEN}[OK] Generated fresh evaluation secrets into .env and backend/.env:${NC}"
    echo "     - ENCRYPTION_KEY: (Generated 32-byte Fernet vault key)"
    echo "     - SECRET_KEY:     (Generated 32-byte session key)"
    echo "     - ZAP_API_KEY:    (Generated 16-byte ZAP daemon key)"
    echo ""
    echo -e "${YELLOW}     WARNING: These auto-generated keys are for LOCAL EVALUATION ONLY.${NC}"
    echo "     Do NOT use these in production without manual review."
else
    echo -e "${GREEN}[OK] Existing .env file detected.${NC}"
    if [ ! -f "${BACKEND_ENV_FILE}" ]; then
        cp "${ENV_FILE}" "${BACKEND_ENV_FILE}"
    fi
fi

# 3. Initialize Host Files & Data Directories
if [ -d "${ROOT_DIR}/backend/threat_hunting.db" ]; then
    rm -rf "${ROOT_DIR}/backend/threat_hunting.db"
fi
if [ ! -f "${ROOT_DIR}/backend/threat_hunting.db" ]; then
    touch "${ROOT_DIR}/backend/threat_hunting.db"
fi
mkdir -p "${ROOT_DIR}/backend/data/logs"

# 4. Start Docker Compose Stack
echo ""
echo -e "${BLUE}[INFO] Launching DecodeX containers via Docker Compose...${NC}"
# Clean up any stale or conflicting existing containers first
docker compose down --remove-orphans &>/dev/null || true
docker compose up -d

# 4. Wait briefly for backend health probe
echo -e "${BLUE}[INFO] Waiting for backend service initialization...${NC}"
for i in {1..15}; do
    if curl -sf http://localhost/api/health &>/dev/null; then
        echo -e "${GREEN}[OK] Platform is healthy and operational!${NC}"
        break
    fi
    sleep 2
done

echo ""
echo -e "${BOLD}${GREEN}================================================================${NC}"
echo -e "${BOLD}${GREEN}    DecodeX is ready!${NC}"
echo -e "${BOLD}${GREEN}================================================================${NC}"
echo ""
echo -e "  ${BOLD}Platform URL:${NC}    http://localhost
  ${BOLD}Default Admin:${NC}   admin / ChangeMe_Admin_Password123!
  ${BOLD}Default Analyst:${NC} analyst / ChangeMe_Analyst_Password123!
  ${BOLD}Default Viewer:${NC}  viewer / ChangeMe_Viewer_Password123!

  ${BOLD}${RED}⚠️  SECURITY WARNING: 'ChangeMe_Admin_Password123!' is a STATIC DEFAULT.${NC}
  ${BOLD}${RED}    CHANGE THIS DEFAULT PASSWORD IN .env BEFORE ANY REAL USE OR NETWORK EXPOSURE!${NC}

  ${BOLD}Useful Commands:${NC}
    - View logs:        docker compose logs -f
    - Stop platform:    docker compose down
    - Run health check: ./health-check.sh"
echo ""
echo -e "  ${YELLOW}Remember:${NC} Only scan systems you own or have explicit written permission to test."
echo ""
