# Web scanner (authorized / safe)

## Safety

- Only `AUTHORIZATION_STATUS=AUTHORIZED` targets can be scanned
- Requires `confirm=true`
- No exploit, DoS, credential stuffing, or crawling the internet
- Timeouts + limited redirects

## Checks

- TLS certificate validity / expiry / protocol
- Security headers (CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy)
- Cookie Secure/HttpOnly hints
- Server header disclosure
- robots.txt presence

## Models

`WebTarget` → `WebScan` → `WebFinding` (with risk_score)

## APIs

- `GET/POST /api/web-targets`
- `PATCH /api/web-targets/<id>`
- `POST /api/web-targets/<id>/scan`
- `GET /api/web-scans/<id>`
- `GET /api/web-findings`
