# Log ingestion

## Sources

- Files under `backend/data/logs/*.log` (NDJSON)
- `POST /api/ingest/manual`, `/api/ingest_logs`, `/api/ingest/vercel`

## Watcher

`log_watcher.start_log_watcher` runs as a daemon thread when the API starts.

- Uses `IngestionState.offset` (byte offset)
- Handles new lines; resets offset on truncation/rotation
- Skips malformed JSON
- Deduplicates via event fingerprint unique constraint
- After detect → risk → persist → Socket.IO → correlation

## Status API

`GET /api/ingestion/status` (permission `events.read`)

Returns watcher status + per-source offset / event_count / last_error.
