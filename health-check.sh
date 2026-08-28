#!/bin/bash

# Threat Hunting Platform - Health Check Script
# Run this after docker compose up -d to verify the stack is healthy

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================================"
echo "Threat Hunting Platform Health Check"
echo "================================================"
echo ""

# Helper functions
check_container() {
    local name=$1
    local status=$(docker inspect -f '{{.State.Status}}' $name 2>/dev/null || echo "missing")
    if [ "$status" = "running" ]; then
        echo -e "${GREEN}✓${NC} Container $name is RUNNING"
        return 0
    else
        echo -e "${RED}✗${NC} Container $name is $status"
        return 1
    fi
}

check_healthcheck() {
    local name=$1
    local health=$(docker inspect -f '{{.State.Health.Status}}' $name 2>/dev/null || echo "none")
    if [ "$health" = "healthy" ]; then
        echo -e "${GREEN}✓${NC}   Healthcheck: HEALTHY"
        return 0
    elif [ "$health" = "none" ]; then
        echo -e "${YELLOW}○${NC}   Healthcheck: not configured"
        return 0
    else
        echo -e "${RED}✗${NC}   Healthcheck: $health"
        return 1
    fi
}

check_port() {
    local name=$1
    local port=$2
    if docker port $name $port 2>/dev/null | grep -q "0.0.0.0:$port"; then
        echo -e "${GREEN}✓${NC}   Port $port mapped"
        return 0
    else
        echo -e "${YELLOW}○${NC}   Port $port not mapped (may be fine if service bridges via other container)"
        return 0
    fi
}

check_url() {
    local url=$1
    local expected=$2
    local response=$(curl -s -w "\n%{http_code}" "$url" 2>/dev/null || echo "000")
    local http_code=$(echo "$response" | tail -1)
    
    if [[ "$http_code" =~ ^(200|301|302|400|401|403|404)$ ]]; then
        echo -e "${GREEN}✓${NC}   HTTP $http_code (expected)"
        return 0
    else
        echo -e "${RED}✗${NC}   HTTP $http_code (unexpected)"
        return 1
    fi
}

# ===== CONTAINER STATUS =====
echo "1. CONTAINER STATUS"
echo "---"

status_ok=true
check_container "zap_scanner" || status_ok=false
check_healthcheck "zap_scanner"
check_port "zap_scanner" "8080"
echo ""

check_container "threat_hunt_backend" || status_ok=false
check_healthcheck "threat_hunt_backend"
check_port "threat_hunt_backend" "5000"
echo ""

check_container "threat_hunt_frontend" || status_ok=false
check_port "threat_hunt_frontend" "3000"
echo ""

check_container "threat_hunt_proxy" || status_ok=false
check_healthcheck "threat_hunt_proxy"
check_port "threat_hunt_proxy" "80"
echo ""

# ===== INTER-CONTAINER CONNECTIVITY =====
echo "2. INTER-CONTAINER CONNECTIVITY"
echo "---"

# Backend → ZAP
echo "Backend → ZAP:"
if docker exec threat_hunt_backend curl -s http://zap:8080/json/core/view/version?apikey=[REDACTED_HISTORICAL_ZAP_KEY] &>/dev/null; then
    echo -e "${GREEN}✓${NC}   Backend can reach ZAP API"
else
    echo -e "${RED}✗${NC}   Backend cannot reach ZAP"
    status_ok=false
fi
echo ""

# Backend → Socket.IO
echo "Backend → Socket.IO:"
if docker exec threat_hunt_backend curl -s http://localhost:5000/socket.io/?EIO=4 &>/dev/null; then
    echo -e "${GREEN}✓${NC}   Backend socket.io listening"
else
    echo -e "${RED}✗${NC}   Backend socket.io not responding"
    status_ok=false
fi
echo ""

# Nginx → Backend
echo "Nginx → Backend:"
if docker exec threat_hunt_proxy curl -s http://backend:5000/api/ &>/dev/null; then
    echo -e "${GREEN}✓${NC}   Nginx can reach backend"
else
    echo -e "${RED}✗${NC}   Nginx cannot reach backend"
    status_ok=false
fi
echo ""

# ===== EXTERNAL ENDPOINT CHECKS =====
echo "3. EXTERNAL ENDPOINT CHECKS (via localhost)"
echo "---"

echo "Frontend (/):"
check_url "http://localhost/" || status_ok=false
echo ""

echo "Backend API (/api/ - should give 400 or redirect):"
curl -s http://localhost/api/ | grep -q "<!DOCTYPE\|<html\|error\|{" && echo -e "${GREEN}✓${NC}   Backend API responding" || echo -e "${RED}✗${NC}   Backend API not responding"
echo ""

echo "Auth endpoint (/api/auth/login - should give 401 or 400):"
http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost/api/auth/login -H "Content-Type: application/json" -d '{}')
if [[ "$http_code" =~ ^(400|401|405)$ ]]; then
    echo -e "${GREEN}✓${NC}   Backend auth endpoint responding (HTTP $http_code)"
else
    echo -e "${RED}✗${NC}   Backend auth endpoint returned HTTP $http_code"
    status_ok=false
fi
echo ""

# ===== NETWORK VERIFICATION =====
echo "4. NETWORK VERIFICATION"
echo "---"

network_ok=true
for container in zap_scanner threat_hunt_backend threat_hunt_frontend threat_hunt_proxy; do
    if docker exec $container ping -c 1 backend &>/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}   $container can resolve 'backend' DNS"
    else
        echo -e "${RED}✗${NC}   $container cannot resolve 'backend' DNS"
        network_ok=false
    fi
done
[ "$network_ok" = false ] && status_ok=false
echo ""

# ===== LOG SUMMARY =====
echo "5. RECENT ERRORS IN LOGS"
echo "---"

echo "Backend errors:"
docker logs threat_hunt_backend 2>&1 | grep -i "error\|exception\|failed\|traceback" | head -3 || echo -e "${GREEN}✓${NC}   No obvious errors"
echo ""

echo "Nginx errors:"
docker logs threat_hunt_proxy 2>&1 | grep -i "error\|502\|503\|connection" | head -3 || echo -e "${GREEN}✓${NC}   No obvious errors"
echo ""

echo "ZAP errors:"
docker logs zap_scanner 2>&1 | grep -i "error\|exception" | head -3 || echo -e "${GREEN}✓${NC}   No obvious errors"
echo ""

# ===== SUMMARY =====
echo "================================================"
if [ "$status_ok" = true ]; then
    echo -e "${GREEN}✓ ALL CHECKS PASSED${NC}"
    echo "================================================"
    echo ""
    echo "Next steps:"
    echo "  1. Visit http://localhost in your browser"
    echo "  2. Login with: admin / YourSecurePassword123!"
    echo "  3. Check backend logs: docker compose logs -f backend"
    echo "  4. Monitor alerts: curl http://localhost/api/alerts"
    exit 0
else
    echo -e "${RED}✗ SOME CHECKS FAILED${NC}"
    echo "================================================"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check Docker daemon: docker info"
    echo "  2. View compose status: docker compose ps"
    echo "  3. Check full logs: docker compose logs"
    echo "  4. Restart stack: docker compose restart"
    echo "  5. Full reset: docker compose down -v && docker compose up -d"
    exit 1
fi
