# Security Policy

## Supported Versions

Security fixes are applied to the actively maintained `main` branch of this project.

| Branch / release | Supported |
| ---------------- | --------- |
| `main` (latest)  | :white_check_mark: |
| Older tags / forks | :x: (please rebase onto latest `main`) |

This repository is an educational / SOC prototype. Treat production deployments as your own responsibility: pin dependencies, harden configuration, and do not expose the service to the public internet without additional controls.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report suspected security issues privately so we can investigate before disclosure.

### How to report

1. Prefer **GitHub Security Advisories** for this repository:  
   **Security → Report a vulnerability** (or [advisories](https://github.com/Decoder420/Threat-Hunting-Platform/security/advisories/new) if available on the repo).
2. If advisories are unavailable, email the maintainer privately using the contact method listed on the GitHub profile / repository owner page, with subject:  
   `[SECURITY] DecodeX Platform`

### What to include

- Description of the issue and potential impact
- Affected component (e.g. auth, RBAC, web scanner, ingestion API, frontend)
- Steps to reproduce (PoC that does **not** target systems you do not own)
- Suggested remediation, if known
- Whether you plan coordinated disclosure

### What to expect

| Stage | Target timeline |
| ----- | --------------- |
| Initial acknowledgement | Within **7 days** |
| Status update | Within **14 days** of acknowledgement |
| Fix or decision | As soon as practical; complexity varies |

- **Accepted:** We will work on a fix, credit you if you wish, and may publish a brief advisory after a fix is available.
- **Declined:** We will explain why (e.g. intended behavior, out of scope, duplicate, or not reproducible).

### Out of scope (examples)

- Issues that require scanning or attacking third-party systems without authorization
- Reports against local lab configurations that intentionally allow private-network scanning (`WEBSCAN_ALLOW_PRIVATE_TARGETS=true`)
- Denial-of-service against a single-developer workstation deployment
- Dependency CVEs with no demonstrated impact on this application (still appreciated if you include a clear exploit path)
- Social engineering of maintainers

### Scope of particular interest

We especially welcome reports related to:

- Authentication / session handling
- RBAC bypass or privilege escalation
- SSRF or unsafe URL handling in the web scanner
- Command injection via scanner integrations (Nuclei / Nmap / ZAP)
- Secrets exposure (`.env`, ingest keys, tokens) in logs or API responses
- Unsafe deserialization or path traversal in rule / log ingestion

## Safe use of the web scanner

Only scan targets you are **explicitly authorized** to assess. Unauthorized scanning may be illegal. Authorization is enforced server-side; do not attempt to bypass it.

## Coordinated disclosure

We ask that you give us a reasonable window to remediate before public disclosure. We will not pursue legal action against good-faith researchers who follow this policy and avoid privacy violations, data destruction, or service disruption.
