## Description
<!-- Briefly describe the changes introduced by this pull request and the rationale behind them. -->

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature that changes existing API contracts or expected behaviors)
- [ ] Documentation update
- [ ] Security hardening / refactor

## Security & Quality Checklist
Please confirm each item before requesting review:

- [ ] **Tests Added & Passing**: Unit and integration tests cover new or modified functionality (`python -m unittest discover` and `npm test`).
- [ ] **Zero Hardcoded Secrets**: No passwords, API keys, JWT tokens, or encryption keys are committed in code or templates.
- [ ] **No CORS Wildcards**: No wildcard origins (`*`) introduced in Flask or Socket.IO handlers.
- [ ] **SSRF Protections Preserved**: Any new target URL handling calls `validate_scan_url` and prohibits private IP ranges unless lab mode is explicitly enabled.
- [ ] **Fail-Closed Vault Maintained**: No fallback to hardcoded keys when `ENCRYPTION_KEY` is missing.
- [ ] **Documentation Updated**: If configuration variables, endpoints, or scan policies changed, `README.md`, `SECURITY.md`, and/or `CHANGELOG.md` have been updated.

## Verification & Screenshots
<!-- Provide terminal output, test results, or screenshots demonstrating that the change functions as expected. -->
```bash
# Paste test output here
```
