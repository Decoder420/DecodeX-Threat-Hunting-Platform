# API overview

Base: `http://127.0.0.1:5000/api`  
Auth: `Authorization: Bearer <token>` from `POST /auth/login`

## Auth
- `POST /auth/login` · `POST /auth/logout` · `GET /auth/me`

## Core SOC
- `GET /dashboard`
- `GET /alerts` · `GET /alerts/<id>` · `POST /alerts/<id>/status` · `POST /alerts/<id>/assign`
- `GET /alert_context/<id>`
- `POST /alerts/<id>/case` · `POST /alerts/<id>/create_case`
- `GET /events` · `GET /events/search`

## Cases / incidents
- `GET/POST /cases` · `GET /cases/<id>` · `POST /cases/<id>/notes`
- `GET /incidents` · `GET /incidents/<id>` · `POST /incidents/correlate`

## Intelligence / assets
- `GET/POST /ioc` · `GET /ioc/search`
- `GET/POST /assets`

## Ingestion
- `GET /ingestion/status` · `POST /ingestion/run`
- `POST /ingest/manual` · `POST /ingest_logs` · `POST /ingest/vercel`

## Web scan
- `GET/POST /web-targets` · `PATCH /web-targets/<id>` · `POST /web-targets/<id>/scan`
- `GET /web-scans/<id>` · `GET /web-findings`

## Admin
- `/admin/users*` · `/admin/rules*` · `/admin/feeds*` · `/admin/ingest_keys*`
- `GET /audit`
- `POST /sigma/import`

## Response / reports
- `POST /soar/action` (SIMULATION MODE)
- `GET /report/<id>?token=`

Errors:

```json
{ "error": { "code": "FORBIDDEN", "message": "…" } }
```
