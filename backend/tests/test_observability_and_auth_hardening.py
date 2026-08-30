"""
Tests for Phase Next observability and security hardening features:
- Fernet encrypted credentials at rest
- /api/health endpoint
- Login sliding-window rate limiting
- Structured logging secret redaction
"""

import json
import unittest
from unittest.mock import patch

from th.db import encrypt_secret, decrypt_secret, VaultConfigurationError
from th.logging_config import redact_sensitive_text
from th.webapp import app, _check_login_rate_limit, _login_rate_limits, _login_rate_lock


class TestObservabilityAndHardening(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        with _login_rate_lock:
            _login_rate_limits.clear()

    def test_credential_encryption_fails_closed_without_key(self):
        """Confirm credential vault refuses encryption/decryption with VaultConfigurationError when no key is set."""
        with patch.dict("os.environ", {"ENCRYPTION_KEY": "", "SECRET_KEY": ""}):
            with self.assertRaises(VaultConfigurationError):
                encrypt_secret("test_secret_token")
            with self.assertRaises(VaultConfigurationError):
                decrypt_secret("some_ciphertext")

    def test_credential_encryption_roundtrip(self):
        """Confirm sensitive target credentials encrypt and decrypt properly when a key is configured."""
        with patch.dict("os.environ", {"ENCRYPTION_KEY": "test_dedicated_vault_key_12345"}):
            plaintext = json.dumps({"token": "secret_jwt_token_xyz_123", "header_name": "Authorization"})
            ciphertext = encrypt_secret(plaintext)
            self.assertTrue(ciphertext)
            self.assertNotEqual(ciphertext, plaintext)
            self.assertNotIn("secret_jwt_token_xyz_123", ciphertext)

            decrypted = decrypt_secret(ciphertext)
            self.assertEqual(decrypted, plaintext)

    def test_api_refuses_target_auth_without_vault_key(self):
        """Confirm API refuses to store credentials with HTTP 500 VAULT_NOT_CONFIGURED when no key is set."""
        from th.db import get_db, User, issue_token
        db = get_db()
        admin_user = db.query(User).filter_by(username="admin").first()
        token = issue_token(db, admin_user)

        with patch("th.enterprise_api.validate_scan_url", return_value={"url": "https://example.com", "resolved_ips": ["93.184.216.34"]}):
            with patch.dict("os.environ", {"ENCRYPTION_KEY": "", "SECRET_KEY": ""}):
                res = self.client.post(
                    "/api/web-targets",
                    headers={"Authorization": f"Bearer {token}"},
                    json={
                        "name": "Test Vault Refusal",
                        "url": "https://example.com",
                        "auth_type": "token",
                        "auth_config": {"token": "secret_token_123"},
                    },
                )
                self.assertEqual(res.status_code, 500)
                data = res.get_json()
                self.assertEqual(data.get("error", {}).get("code"), "VAULT_NOT_CONFIGURED")
                self.assertIn("neither ENCRYPTION_KEY nor SECRET_KEY", data.get("error", {}).get("message", ""))

    def test_health_endpoint(self):
        """Confirm /api/health returns HTTP 200 and expected health telemetry."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "healthy")
        self.assertIn("database", data)
        self.assertEqual(data["database"]["status"], "connected")
        self.assertIn("latency_ms", data["database"])
        self.assertIn("engines", data)
        self.assertIn("builtin", data["engines"])
        self.assertIn("background_services", data)

    def test_login_rate_limiter_blocks_excessive_attempts(self):
        """Confirm client IP is rate limited after exceeding threshold and receives HTTP 429."""
        test_ip = "198.51.100.42"
        # Simulate 30 rapid attempts
        for _ in range(30):
            allowed, _ = _check_login_rate_limit(test_ip)
            self.assertTrue(allowed)

        # 31st attempt should be rejected
        allowed, retry_after = _check_login_rate_limit(test_ip)
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 1)

        # Confirm HTTP route behavior
        with patch("th.webapp.AUTH_RATE_LIMIT_MAX", 2):
            with _login_rate_lock:
                _login_rate_limits.clear()
            # 1st attempt
            r1 = self.client.post("/api/auth/login", json={"username": "fake", "password": "wrong"}, environ_base={"REMOTE_ADDR": "192.0.2.1"})
            self.assertEqual(r1.status_code, 401)
            # 2nd attempt
            r2 = self.client.post("/api/auth/login", json={"username": "fake", "password": "wrong"}, environ_base={"REMOTE_ADDR": "192.0.2.1"})
            self.assertEqual(r2.status_code, 401)
            # 3rd attempt: rate limited!
            r3 = self.client.post("/api/auth/login", json={"username": "fake", "password": "wrong"}, environ_base={"REMOTE_ADDR": "192.0.2.1"})
            self.assertEqual(r3.status_code, 429)
            self.assertIn("Retry-After", r3.headers)

    def test_log_redaction_filter(self):
        """Confirm sensitive tokens and passwords are redacted from log strings."""
        raw_bearer = "Request received with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        redacted_bearer = redact_sensitive_text(raw_bearer)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted_bearer)
        self.assertIn("[REDACTED_TOKEN]", redacted_bearer)

        raw_password = 'User login failed with password="SecretPassword123!"'
        redacted_pwd = redact_sensitive_text(raw_password)
        self.assertNotIn("SecretPassword123!", redacted_pwd)
        self.assertIn("[REDACTED_PASSWORD]", redacted_pwd)

    def test_login_rate_limiter_resets_after_window_expires(self):
        """Confirm that after the rate limit window (e.g. 60s) expires, subsequent login requests are permitted again."""
        test_ip = "203.0.113.88"
        base_time = 1000000.0

        with patch("time.time", return_value=base_time):
            with patch("th.webapp.AUTH_RATE_LIMIT_MAX", 2):
                with patch("th.webapp.AUTH_RATE_LIMIT_WINDOW", 60):
                    with _login_rate_lock:
                        _login_rate_limits.clear()

                    # 1st attempt at T=0 -> allowed
                    ok1, _ = _check_login_rate_limit(test_ip)
                    self.assertTrue(ok1)
                    # 2nd attempt at T=0 -> allowed
                    ok2, _ = _check_login_rate_limit(test_ip)
                    self.assertTrue(ok2)
                    # 3rd attempt at T=0 -> BLOCKED (threshold reached)
                    ok3, retry_after = _check_login_rate_limit(test_ip)
                    self.assertFalse(ok3)
                    self.assertGreaterEqual(retry_after, 1)

        # Advance time past the 60-second window (T=65s)
        with patch("time.time", return_value=base_time + 65.0):
            with patch("th.webapp.AUTH_RATE_LIMIT_MAX", 2):
                with patch("th.webapp.AUTH_RATE_LIMIT_WINDOW", 60):
                    # Should be reset and permitted!
                    ok_after_expiry, _ = _check_login_rate_limit(test_ip)
                    self.assertTrue(ok_after_expiry)


if __name__ == "__main__":
    unittest.main()
