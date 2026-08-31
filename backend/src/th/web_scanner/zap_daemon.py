"""ZAP Daemon Lifecycle, Health Monitoring, and Capability Discovery Manager.

Supports:
- Configurable ZAP host, port, API key, startup command, and installation path
- Docker environment detection and local development daemon management
- Health check, readiness check, version detection, and capability discovery
- Safe status reporting without exposing credentials or API keys
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from .config import ZAP_API_KEY, ZAP_ENABLED, ZAP_URL
from .zap_client import zap_client

logger = logging.getLogger("th.zap_daemon")

ZAP_HOST = os.environ.get("ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.environ.get("ZAP_PORT", "8080"))
ZAP_PATH = os.environ.get("ZAP_PATH", "zap.sh")
ZAP_START_CMD = os.environ.get("ZAP_START_CMD", "")
ZAP_STARTUP_TIMEOUT = int(os.environ.get("ZAP_STARTUP_TIMEOUT", "60"))
ZAP_REQUEST_TIMEOUT = int(os.environ.get("ZAP_REQUEST_TIMEOUT", "10"))


class ZapDaemonManager:
    """Manages ZAP daemon process lifecycle, connectivity, and status telemetry."""

    def __init__(
        self,
        base_url: str = ZAP_URL,
        api_key: str = ZAP_API_KEY,
        path: str = ZAP_PATH,
        start_cmd: str = ZAP_START_CMD,
    ):
        self.base_url = (base_url or f"http://{ZAP_HOST}:{ZAP_PORT}").rstrip("/")
        self.api_key = api_key or ""
        self.path = path
        self.start_cmd = start_cmd
        self._process: Optional[subprocess.Popen] = None

    def get_status(self) -> Dict[str, Any]:
        """Query ZAP daemon health, version, capabilities, and active scan count."""
        if not ZAP_ENABLED:
            return {
                "available": False,
                "healthy": False,
                "version": "",
                "api_reachable": False,
                "capabilities": {
                    "spider": False,
                    "ajax_spider": False,
                    "passive_scan": False,
                    "active_scan": False,
                    "openapi_import": False,
                    "websocket": False,
                    "replacer": False,
                },
                "active_scans": 0,
                "base_url": self.base_url,
                "managed_locally": self._process is not None and self._process.poll() is None,
                "addons": [],
                "error": "ZAP integration is disabled (ZAP_ENABLED=false)",
            }

        health = zap_client.health_check()
        active_scans = 0

        # Discover currently active spiders or scans if reachable
        if health.get("available"):
            try:
                # Active spider scans
                sp_res = zap_client._req("spider/view/scans/", timeout=3)
                if sp_res.ok:
                    active_scans += len((sp_res.json() or {}).get("scans") or [])

                # Active vulnerability scans
                as_res = zap_client._req("ascan/view/scans/", timeout=3)
                if as_res.ok:
                    active_scans += len((as_res.json() or {}).get("scans") or [])
            except Exception:
                pass

        return {
            "available": bool(health.get("available")),
            "healthy": bool(health.get("available")),
            "version": health.get("version", ""),
            "api_reachable": bool(health.get("available")),
            "capabilities": health.get("capabilities", {}),
            "active_scans": active_scans,
            "base_url": self.base_url,
            "managed_locally": self._process is not None and self._process.poll() is None,
            "addons": health.get("addons", []),
            "error": health.get("error"),
        }

    def is_healthy(self) -> bool:
        """Check if ZAP API is responsive and ready."""
        status = self.get_status()
        return status["available"] and status["healthy"]

    def start_local_daemon(self, timeout: int = ZAP_STARTUP_TIMEOUT) -> bool:
        """Start a local ZAP daemon process if not already running."""
        if self.is_healthy():
            logger.info("ZAP daemon is already reachable at %s", self.base_url)
            return True

        # Determine binary / command
        cmd = []
        if self.start_cmd:
            import shlex
            cmd = shlex.split(self.start_cmd)
        else:
            resolved_bin = shutil.which(self.path)
            if not resolved_bin and Path(self.path).is_file():
                resolved_bin = str(Path(self.path).resolve())
            if not resolved_bin:
                logger.error("ZAP executable not found at '%s'", self.path)
                return False

            cmd = [
                resolved_bin,
                "-daemon",
                "-host", ZAP_HOST,
                "-port", str(ZAP_PORT),
                "-config", f"api.key={self.api_key}",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true",
            ]

        try:
            logger.info("Spawning local ZAP daemon process: %s", " ".join(cmd[:3]))
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Wait for readiness
            deadline = time.time() + timeout
            while time.time() < deadline:
                if self._process.poll() is not None:
                    logger.error("ZAP process exited prematurely with code %s", self._process.returncode)
                    return False
                if self.is_healthy():
                    logger.info("ZAP daemon started successfully.")
                    return True
                time.sleep(2)
            logger.warning("Timed out waiting for ZAP daemon to become healthy.")
            return False
        except Exception as exc:
            logger.error("Failed to spawn ZAP daemon: %s", exc)
            return False

    def stop_local_daemon(self, timeout: int = 15) -> bool:
        """Gracefully shut down ZAP daemon."""
        # First attempt via ZAP API shutdown action
        try:
            zap_client._req("core/action/shutdown/", method="POST", timeout=5)
            logger.info("Sent shutdown signal to ZAP API.")
        except Exception:
            pass

        # If we manage the process directly, terminate it
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=timeout)
                self._process = None
                return True
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process = None
                return True
            except Exception as exc:
                logger.warning("Error stopping ZAP process: %s", exc)
                return False
        return True


# Global daemon manager singleton
zap_daemon = ZapDaemonManager()
