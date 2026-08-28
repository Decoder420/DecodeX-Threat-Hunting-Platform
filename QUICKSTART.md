# Quick Start - After Docker Restart

## 1️⃣ Restart Docker
```bash
osascript -e 'quit app "Docker"'
sleep 10
open -a Docker.app
sleep 30
```

Verify Docker is ready:
```bash
docker ps
```

## 2️⃣ Clean Ports
```bash
pkill -9 -f "gunicorn"
lsof -i :5000 -s TCP:LISTEN | tail -1 | awk '{print $2}' | xargs kill -9 2>/dev/null
lsof -i :80 -s TCP:LISTEN | tail -1 | awk '{print $2}' | xargs kill -9 2>/dev/null
lsof -i :8080 -s TCP:LISTEN | tail -1 | awk '{print $2}' | xargs kill -9 2>/dev/null
sleep 2
```

## 3️⃣ Deploy
```bash
cd /Users/manan/Desktop/Projects/Threat-Hunting-Platform
docker compose down -v
docker compose up -d
```

## 4️⃣ Monitor Startup (2 minutes)
```bash
# Terminal 1: Watch containers
watch -n 1 'docker ps --format "table {{.Names}}\t{{.Status}}"'

# Terminal 2: Watch logs
docker compose logs -f backend
```

## 5️⃣ Test Health (after 2 minutes)
```bash
bash health-check.sh
```

## 6️⃣ Access App
- **Frontend**: http://localhost
- **Backend API**: http://localhost/api/
- **ZAP Scanner**: http://localhost:8080 (not exposed via nginx, only on :8080)

## 7️⃣ Login
- **Username**: admin
- **Password**: YourSecurePassword123!

---

## Troubleshooting Quick Ref

| Issue | Command |
|-------|---------|
| Check container status | `docker ps -a` |
| View backend errors | `docker logs threat_hunt_backend` |
| View nginx errors | `docker logs threat_hunt_proxy` |
| Test backend directly | `curl http://localhost/api/` |
| Test login | `curl -X POST http://localhost/api/auth/login -H "Content-Type: application/json" -d '{}'` |
| Restart backend | `docker compose restart threat_hunt_backend` |
| Full reset | `docker compose down -v && docker compose up -d` |
| Verify inter-container DNS | `docker exec threat_hunt_backend ping zap` |

---

## Expected Output (when healthy)

```
CONTAINER ID   IMAGE                            STATUS              
...            zap_scanner                      Up 2 minutes (healthy)
...            threat_hunt_backend              Up 1 minute (healthy)
...            threat_hunt_frontend             Up 50 seconds
...            threat_hunt_proxy                Up 30 seconds (healthy)
```

All 4 containers should be `Up` and marked `(healthy)` ✅
