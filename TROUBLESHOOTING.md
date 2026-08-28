# Threat Hunting Platform - Docker Compose Troubleshooting Guide

## **Overview of Issues & Fixes Applied**

### Issue 1: Port 5000 Already in Use
**Symptom:** `Error: address already in use: listen tcp 0.0.0.0:5000`
**Root Cause:** Lingering gunicorn process from previous failed container start
**Fix Applied:**
```bash
# Kill lingering processes
lsof -i :5000 | grep LISTEN | awk '{print $2}' | xargs kill -9
lsof -i :80 | grep LISTEN | awk '{print $2}' | xargs kill -9

# Restart Docker daemon
osascript -e 'quit app "Docker"'
sleep 10
open -a Docker.app
sleep 30  # Give Docker 30s to fully restart
```

### Issue 2: Missing Container Healthchecks & Dependency Ordering
**Symptom:** Backend starts before ZAP is ready → 502 Bad Gateway, ZAP connection errors
**Root Cause:** `depends_on: - zap` only checks if container started, not if it's ready
**Fix Applied:**
- Added healthcheck to ZAP (checks `/json/core/view/version` endpoint)
- Added healthcheck to backend (checks port 5000 with curl)
- Added healthcheck to nginx (checks root path)
- Changed all `depends_on` to use `condition: service_healthy` where critical
- Created explicit bridge network `threat-net` for reliable inter-container DNS

### Issue 3: Frontend WebSocket Failures
**Symptom:** `WebSocket connection to 'ws://localhost/socket.io/?EIO=4&transport=websocket' failed`
**Root Cause:** 
- Nginx WebSocket upgrade headers present but connection refused (backend not ready)
- Frontend depended on backend startup, not health
**Fix Applied:**
- Frontend now waits for `backend: condition: service_healthy`
- Nginx waits for `backend: condition: service_healthy` before routing traffic

### Issue 4: Nginx Routing & WebSocket Config
**Status:** ✅ VERIFIED CORRECT
**Review of `/nginx/nginx.conf`:**
```nginx
location /socket.io/ {
    proxy_pass http://backend:5000/socket.io/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;          # ✅ PRESENT
    proxy_set_header Connection "Upgrade";           # ✅ PRESENT
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 86400s;                       # ✅ LONG TIMEOUT
    proxy_send_timeout 86400s;                       # ✅ LONG TIMEOUT
    proxy_buffering off;                             # ✅ NO BUFFERING
}
```
**No changes needed.** Config is correct.

---

## **Steps to Fully Deploy**

### Step 1: Restart Docker Engine
On macOS:
```bash
# Option A: Via UI
osascript -e 'quit app "Docker"'
sleep 10
open -a Docker.app
sleep 30  # Wait for daemon to be ready

# Option B: Via Terminal (if osascript fails)
killall Docker com.docker.hyperkit 2>/dev/null
sleep 10
open -a Docker.app
sleep 30
```

Verify Docker is ready:
```bash
docker ps
# Should return a table, not an error
```

### Step 2: Clean Up Port Conflicts
```bash
# Kill any processes on ports 5000, 80, 8080
lsof -i :5000 -s TCP:LISTEN | tail -1 | awk '{print $2}' | xargs kill -9 2>/dev/null
lsof -i :80 -s TCP:LISTEN | tail -1 | awk '{print $2}' | xargs kill -9 2>/dev/null
lsof -i :8080 -s TCP:LISTEN | tail -1 | awk '{print $2}' | xargs kill -9 2>/dev/null

# Verify ports are free
echo "Port 5000:" && lsof -i :5000 2>&1 | grep -q LISTEN && echo "IN USE" || echo "FREE"
echo "Port 80:" && lsof -i :80 2>&1 | grep -q LISTEN && echo "IN USE" || echo "FREE"
echo "Port 8080:" && lsof -i :8080 2>&1 | grep -q LISTEN && echo "IN USE" || echo "FREE"
```

### Step 3: Start Compose Stack
```bash
cd /Users/manan/Desktop/Projects/Threat-Hunting-Platform

# Remove old containers/networks
docker compose down -v

# Start in daemon mode
docker compose up -d

# Monitor startup (run in separate terminal)
docker compose logs -f
```

### Step 4: Wait for Healthchecks to Pass
The startup order is:
1. **ZAP starts** → 45s startup period, then checks health endpoint
2. **Backend starts** (only after ZAP healthy) → 30s startup period, then checks curl to :5000
3. **Frontend starts** (only after backend healthy) → no healthcheck
4. **Nginx starts** (only after backend healthy) → 10s startup period, then checks root

**Expected timeline:**
- 0-60s: ZAP initializing
- 60-95s: Backend starting
- 95-100s: Frontend starting
- 100-110s: Nginx starting

```bash
# Check container health in real-time
watch -n 1 'docker ps --format "table {{.Names}}\t{{.Status}}"'
```

### Step 5: Verify All Containers Are Running & Healthy
```bash
docker ps -a

# Expected output:
# NAMES                    STATUS
# threat_hunt_backend      Up X minutes (healthy)
# threat_hunt_frontend     Up X minutes
# threat_hunt_proxy        Up X minutes (healthy)
# zap_scanner              Up X minutes (healthy)
```

---

## **Detailed Health Verification**

### Check 1: ZAP Connectivity from Backend
```bash
docker exec threat_hunt_backend curl -s http://zap:8080/json/core/view/version?apikey=ufmqbdsum4iqindh6jaququfso | head -20

# Expected: JSON response with "version" field
```

### Check 2: Backend API Endpoint
```bash
curl -s http://localhost:5000/ | head -20

# Expected: 200 OK response or JSON error (not 502)
```

### Check 3: Frontend React App
```bash
curl -s http://localhost/index.html | grep -i "react\|<!DOCTYPE"

# Expected: HTML page with React app
```

### Check 4: Nginx Proxy to Backend API
```bash
curl -s http://localhost/api/auth/login -X POST -H "Content-Type: application/json" -d '{}' 2>&1 | head

# Expected: 400 or 401 (auth error), NOT 502
```

### Check 5: Nginx Proxy to Frontend
```bash
curl -s http://localhost/ | grep -o "<html\|<div id=\"root\""

# Expected: HTML or React root div
```

### Check 6: WebSocket Connection via Nginx
```bash
# From browser console, or use websocat:
websocat ws://localhost/socket.io/?EIO=4&transport=websocket

# Expected: Connected, then receives heartbeat messages
```

### Check 7: Backend Logs for ZAP Integration
```bash
docker logs threat_hunt_backend | grep -i "zap\|error" | tail -20

# Look for:
# ✅ "ZAP_URL=http://zap:8080"
# ✅ "ZAP_ENABLED=true"
# ❌ Connection refused errors
```

### Check 8: Nginx Logs for Proxy Errors
```bash
docker logs threat_hunt_proxy | grep -i "502\|error\|upstream" | tail -10

# Look for:
# ✅ Normal HTTP logs (no 502s)
# ❌ "502 Bad Gateway"
# ❌ "upstream timed out"
```

---

## **Troubleshooting by Symptom**

### **Symptom: 502 Bad Gateway on `/api/auth/login`**
**Steps:**
1. Check backend is healthy: `docker ps` → `threat_hunt_backend` should show `(healthy)`
2. Verify backend is listening: `docker exec threat_hunt_backend curl -s http://localhost:5000/ | head`
3. Check nginx routing: `docker exec threat_hunt_proxy cat /etc/nginx/conf.d/default.conf | grep -A 5 "location /api/"`
4. Check backend logs: `docker logs threat_hunt_backend | tail -50`

**Likely causes:**
- Backend container stuck in `Created` or `Exited` state → restart: `docker compose restart threat_hunt_backend`
- Backend import errors on startup → check logs for Python traceback
- Nginx cannot resolve DNS name "backend" → check network: `docker network inspect threat-net`

### **Symptom: WebSocket Connection Fails (ERR_CONNECTION_REFUSED)**
**Steps:**
1. Verify nginx is running: `docker ps | grep threat_hunt_proxy`
2. Check socket.io is listening on backend: `docker exec threat_hunt_backend curl -s http://localhost:5000/socket.io/?EIO=4 | head`
3. Test nginx proxy: `docker exec threat_hunt_proxy curl -s http://localhost/socket.io/?EIO=4 | head`
4. Check nginx WebSocket headers: `docker exec threat_hunt_proxy grep -A 3 "Upgrade" /etc/nginx/conf.d/default.conf`

**Likely causes:**
- Backend not responding because it's still initializing → wait for healthcheck to pass
- Flask-SocketIO not started → check `FLASK_ENV`, imports in `webapp.py`
- Nginx restarting before backend ready → increase `start_period` in nginx healthcheck

### **Symptom: Backend Can't Reach ZAP (Connection Refused)**
**Steps:**
1. Check ZAP is healthy: `docker ps | grep zap_scanner` → should show `(healthy)`
2. Verify ZAP is listening: `docker exec zap_scanner wget --spider http://localhost:8080/json/core/view/version?apikey=ufmqbdsum4iqindh6jaququfso`
3. Check backend environment vars: `docker exec threat_hunt_backend env | grep ZAP`
4. Verify backend can resolve DNS: `docker exec threat_hunt_backend ping -c 1 zap`

**Likely causes:**
- ZAP not fully started (healthcheck still initializing) → wait 2 minutes
- Network misconfiguration → verify all containers are on `threat-net`: `docker network inspect threat-net`
- ZAP API key mismatch → both should be `ufmqbdsum4iqindh6jaququfso`

---

## **Network Verification**

```bash
# List all containers on threat-net
docker network inspect threat-net | grep -A 5 "Containers"

# Expected:
# - zap_scanner: 172.x.x.x
# - threat_hunt_backend: 172.x.x.x
# - threat_hunt_frontend: 172.x.x.x
# - threat_hunt_proxy: 172.x.x.x

# Test inter-container DNS
docker exec threat_hunt_backend ping -c 1 zap
docker exec threat_hunt_backend ping -c 1 backend
docker exec threat_hunt_proxy ping -c 1 backend
```

---

## **Quick Restart Procedure**

If everything is stuck, nuke and restart:

```bash
# Full clean
docker compose down -v
docker system prune -f --volumes
sleep 5

# Fresh start
docker compose up -d
docker compose logs -f

# Wait ~2 minutes for all healthchecks to pass
```

---

## **Summary of Changes in Updated docker-compose.yaml**

| Change | Reason |
|--------|--------|
| Moved ZAP service to top | Clearer dependency order (ZAP first) |
| Added `networks: threat-net` to all services | Explicit bridge for reliable DNS |
| Backend depends on `zap: condition: service_healthy` | Backend won't start until ZAP ready |
| Frontend depends on `backend: condition: service_healthy` | Frontend won't load until backend API ready |
| Nginx depends on `backend: condition: service_healthy` | Nginx won't route until backend ready |
| Added backend healthcheck (curl to :5000) | Nginx waits for actual API availability |
| Added nginx healthcheck (wget root) | Detects nginx startup failures |
| Reordered service definitions | ZAP → Backend → Frontend → Nginx (logical order) |

---

## **Next Steps After Stack is Running**

1. Login: `curl -X POST http://localhost/api/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"YourSecurePassword123!"}'`
2. Check dashboard: `curl -s http://localhost/api/alerts | jq .`
3. Monitor logs: `docker compose logs -f backend`
4. Export secrets: `docker compose config` (shows env vars—be careful with credentials)
