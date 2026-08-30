# Contributing to DecodeX

Thank you for your interest in contributing to DecodeX! As a threat hunting and security intelligence platform, code quality, stability, and security are paramount.

Please take a moment to review these guidelines before submitting code.

---

## 🔒 Heightened Scrutiny for Security-Sensitive Components

> [!IMPORTANT]
> Because DecodeX handles active web vulnerability scanning, network probing, and sensitive credentials:
> **Any pull request modifying authentication, role-based access control (RBAC), CORS policies, SSRF protections, cryptographic vault logic, or secret handling will undergo rigorous manual and automated security review.**
>
> - Wildcard CORS origins (`*`) are strictly prohibited and will be rejected automatically by CI.
> - Never hardcode passwords, tokens, or default cryptographic keys in committed code or configuration templates.
> - Ensure all scan URL handling adheres to SSRF validation rules (`validate_scan_url`).

---

## 🛠️ Local Development Setup

### 1. Prerequisites
- **Python 3.11+**
- **Node.js 18+ & npm**
- **Docker & Docker Compose v2**

### 2. Backend Development
```bash
# Navigate to backend and initialize virtualenv
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure local development environment
cp .env.example .env

# Run backend development server
python -m th.webapp
```
The API server will listen on `http://127.0.0.1:5000`.

### 3. Frontend Development
```bash
# Navigate to frontend and install dependencies
cd frontend
npm install

# Start React development server
npm start
```
The React development server will start on `http://localhost:3000` with hot-reloading.

---

## 🧪 Running Automated Tests

All changes must pass existing unit tests and include new test coverage.

### Run Backend Test Suite
```bash
backend/.venv/bin/python -m unittest discover -s backend/tests -p 'test_*.py'
```

### Run Frontend Test Suite
```bash
cd frontend
CI=true npm test -- --watchAll=false
```

### Validate Production Build
```bash
cd frontend
npm run build
```

### Run Security Static Guardrails
```bash
# 1. CORS wildcard check
grep -rnE 'cors_allowed_origins.*[\*]' backend/src/ && echo "FAIL" || echo "[OK] No CORS wildcards"

# 2. Leaked legacy secret string check
grep -rnF '[REDACTED_HISTORICAL_ZAP_KEY]' --exclude-dir=.git --exclude-dir=.github --exclude-dir=node_modules --exclude-dir=.venv --exclude="*.md" . && echo "FAIL" || echo "[OK] Clean"
```

---

## 📋 Pull Request Process

1. **Fork the Repository**: Create a topic branch from `main` (e.g. `feat/custom-yara-importer` or `fix/target-pagination`).
2. **Follow Conventional Commits**: Structure commit messages logically:
   - `feat(scope): add feature description`
   - `fix(scope): resolve bug description`
   - `test(scope): add regression coverage`
   - `docs(scope): update documentation`
3. **Keep PRs Focused**: Avoid massive, multi-purpose diffs. Group related improvements together.
4. **Update Documentation**: If your PR introduces new environment variables, API endpoints, or modifies scan behaviors, update `README.md`, `SECURITY.md`, and `CHANGELOG.md` accordingly.
5. **Verify CI**: Ensure GitHub Actions passes all test matrices and static guardrails before requesting review.

---

## 📜 Code of Conduct

All contributors are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md). Please report any unacceptable behavior to `mananmandal006@gmail.com`.
