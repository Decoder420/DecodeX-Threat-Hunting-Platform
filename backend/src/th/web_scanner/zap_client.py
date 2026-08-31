"""Production OWASP ZAP Integration Client for DecodeX Platform.

Provides structured daemon lifecycle management, contextual scoping,
spider, AJAX spider, OpenAPI import, passive/active scanning, rate-limiting,
and real-time attack surface streaming with strict SSRF guardrails.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from .config import (
    WEBSCAN_ALLOW_PRIVATE_TARGETS,
    ZAP_API_KEY,
    ZAP_ENABLED,
    ZAP_URL,
)
from .validators import validate_scan_url

logger = logging.getLogger("th.zap_client")

# Canonical severity mapping from ZAP risk levels
ZAP_RISK_MAP = {
    "INFORMATIONAL": "INFO",
    "INFO": "INFO",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}


class ZapClient:
    """Enterprise client for OWASP ZAP 2.14+ REST API."""

    def __init__(self, base_url: str = ZAP_URL, api_key: str = ZAP_API_KEY):
        self.base_url = (base_url or "http://127.0.0.1:8080").rstrip("/")
        self.api_key = api_key or ""
        self._session = requests.Session()
        if self.api_key:
            self._session.headers.update({"X-ZAP-API-Key": self.api_key})

    def _req(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: int = 15,
        method: str = "GET",
    ) -> requests.Response:
        """Issue an authenticated request to ZAP API."""
        url = f"{self.base_url}/JSON/{endpoint.lstrip('/')}"
        p = dict(params or {})
        if self.api_key and "apikey" not in p:
            p["apikey"] = self.api_key
        if method == "POST":
            return self._session.post(url, data=p, timeout=timeout)
        return self._session.get(url, params=p, timeout=timeout)

    # -------------------------------------------------------------------------
    # 1. Health Checks & Capability Discovery
    # -------------------------------------------------------------------------
    def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check and discover installed ZAP capabilities."""
        status = {
            "available": False,
            "version": "",
            "base_url": self.base_url,
            "capabilities": {
                "spider": True,
                "ajax_spider": False,
                "passive_scan": True,
                "active_scan": True,
                "openapi_import": False,
                "websocket": False,
                "replacer": False,
            },
            "addons": [],
            "error": None,
        }
        try:
            ver_resp = self._req("core/view/version/", timeout=5)
            if not ver_resp.ok:
                status["error"] = f"ZAP responded with status {ver_resp.status_code}"
                return status

            status["available"] = True
            data = ver_resp.json() or {}
            status["version"] = data.get("version", "unknown")

            # Query installed add-ons
            try:
                addon_resp = self._req("autoupdate/view/installedAddons/", timeout=5)
                if addon_resp.ok:
                    raw_addons = (addon_resp.json() or {}).get("installedAddons") or []
                    addon_ids = set()
                    for item in raw_addons:
                        if isinstance(item, dict):
                            aid = item.get("id", "")
                            addon_ids.add(aid.lower())
                            status["addons"].append({
                                "id": aid,
                                "version": item.get("version", ""),
                                "name": item.get("name", aid),
                            })
                    caps = status["capabilities"]
                    caps["ajax_spider"] = "spiderajax" in addon_ids or "ajaxspider" in addon_ids
                    caps["openapi_import"] = "openapi" in addon_ids
                    caps["websocket"] = "websocket" in addon_ids
                    caps["replacer"] = "replacer" in addon_ids
            except Exception as exc:
                logger.debug("Failed querying ZAP add-ons: %s", exc)

            return status
        except Exception as exc:
            status["error"] = f"Cannot reach ZAP daemon: {exc}"
            return status

    # -------------------------------------------------------------------------
    # 2. Scoping, Context & Session Management
    # -------------------------------------------------------------------------
    def create_target_context(
        self,
        context_name: str,
        target_url: str,
        include_regex: Optional[str] = None,
        exclude_regexes: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Create an isolated, scoped ZAP context for a target to prevent scanning out-of-scope assets."""
        try:
            # 1. New Context
            res = self._req("context/action/newContext/", {"contextName": context_name}, method="POST")
            cid = None
            if res.ok:
                cid = (res.json() or {}).get("contextId")

            # 2. Scope include regex (defaults to target origin prefix)
            parsed = urlparse(target_url)
            host_pattern = re.escape(parsed.netloc or parsed.hostname or "")
            regex = include_regex or f"^{re.escape(parsed.scheme)}://{host_pattern}.*$"
            self._req("context/action/includeInContext/", {"contextName": context_name, "regexUrl": regex}, method="POST")

            # 3. Scope exclude regexes (logout, dangerous actions)
            defaults_exclude = [
                r".*logout.*",
                r".*signout.*",
                r".*delete-account.*",
            ]
            for ex in (exclude_regexes or defaults_exclude):
                self._req("context/action/excludeFromContext/", {"contextName": context_name, "regexUrl": ex}, method="POST")

            # 4. Set in scope
            self._req("context/action/setContextInScope/", {"contextName": context_name, "booleanInScope": "true"}, method="POST")
            return cid
        except Exception as exc:
            logger.warning("Failed creating ZAP context '%s': %s", context_name, exc)
            return None

    def configure_custom_headers(self, headers_dict: Dict[str, str]) -> None:
        """Inject custom HTTP request headers (e.g. Authorization, X-API-Key) via Replacer extension if available."""
        if not headers_dict:
            return
        for header_name, header_value in headers_dict.items():
            try:
                self._req(
                    "replacer/action/addRule/",
                    {
                        "description": f"DecodeX Header {header_name}",
                        "enabled": "true",
                        "matchType": "REQ_HEADER",
                        "matchString": header_name,
                        "replacement": header_value,
                        "initiators": "",
                    },
                    method="POST",
                )
            except Exception:
                pass

    def configure_auth_credentials(
        self,
        context_name: str,
        auth_type: str,
        auth_config: Dict[str, Any],
        target_url: str,
    ) -> bool:
        """Configure authentication in ZAP context (form-based or header/token) without logging credentials."""
        if not auth_type or auth_type == "none" or not auth_config:
            return False

        try:
            auth_type_norm = (auth_type or "").lower().strip()
            if auth_type_norm in {"token", "bearer", "custom_header"}:
                header_name = auth_config.get("header_name") or "Authorization"
                header_val = auth_config.get("token") or auth_config.get("header_value") or ""
                if header_val:
                    if auth_type_norm == "bearer" and not header_val.lower().startswith("bearer "):
                        header_val = f"Bearer {header_val}"
                    self.configure_custom_headers({header_name: header_val})
                    logger.info("Configured ZAP authenticated scanning via header: %s", header_name)
                    return True

            elif auth_type_norm == "form":
                login_url = auth_config.get("login_url") or target_url
                login_request_data = auth_config.get("login_request_data") or ""
                username = auth_config.get("username") or ""
                password = auth_config.get("password") or ""
                username_field = auth_config.get("username_field") or "username"
                password_field = auth_config.get("password_field") or "password"
                if not login_request_data and username:
                    login_request_data = f"{username_field}={{%username%}}&{password_field}={{%password%}}"

                method_config = f"loginUrl={login_url}&loginRequestData={login_request_data}"
                self._req("authentication/action/setAuthenticationMethod/", {
                    "contextName": context_name,
                    "authMethodName": "formBasedAuthentication",
                    "authMethodConfigParams": method_config,
                }, method="POST")

                u_res = self._req("users/action/newUser/", {
                    "contextName": context_name,
                    "name": username or "scan_user",
                }, method="POST")
                uid = (u_res.json() or {}).get("userId")
                if uid:
                    cred_config = f"username={username}&password={password}"
                    self._req("users/action/setAuthenticationCredentials/", {
                        "contextName": context_name,
                        "userId": str(uid),
                        "authCredentialsConfigParams": cred_config,
                    }, method="POST")
                    self._req("users/action/setUserEnabled/", {
                        "contextName": context_name,
                        "userId": str(uid),
                        "enabled": "true",
                    }, method="POST")
                    self._req("forcedUser/action/setForcedUser/", {
                        "contextName": context_name,
                        "userId": str(uid),
                    }, method="POST")
                    self._req("forcedUser/action/setForcedUserModeEnabled/", {
                        "boolean": "true",
                    }, method="POST")
                    logger.info("Configured ZAP form-based user authentication on context: %s", context_name)
                    return True
        except Exception as exc:
            logger.warning("Failed configuring ZAP authentication: %s", exc)
        return False

    # -------------------------------------------------------------------------
    # 3. Traditional Spider (HTML / Links Crawl)
    # -------------------------------------------------------------------------
    def run_spider(
        self,
        url: str,
        context_name: Optional[str] = None,
        max_children: int = 50,
        max_depth: int = 5,
        timeout: int = 60,
        cancel_check: Optional[Callable[[], bool]] = None,
        progress_callback: Optional[Callable[[int], None]] = None,
        allow_private: bool = WEBSCAN_ALLOW_PRIVATE_TARGETS,
    ) -> Tuple[List[str], Optional[str]]:
        """Run ZAP traditional spider with scope enforcement, max depth, progress streaming, and cancellation."""
        # SSRF validation BEFORE sending outbound request
        validate_scan_url(url, allow_private=allow_private)

        # Set spider max depth
        try:
            self._req("spider/action/setOptionMaxDepth/", {"Integer": str(max(1, max_depth))}, method="POST")
        except Exception:
            pass

        params: Dict[str, Any] = {
            "url": url,
            "maxChildren": str(max_children),
            "recurse": "true",
            "subtreeOnly": "true",
        }
        if context_name:
            params["contextName"] = context_name

        try:
            res = self._req("spider/action/scan/", params, method="POST")
            if not res.ok:
                return [], f"Failed to start spider: {res.text}"
            scan_id = (res.json() or {}).get("scan")
            if scan_id is None:
                return [], "ZAP did not return spider scan ID."

            deadline = time.time() + timeout
            while time.time() < deadline:
                if cancel_check and cancel_check():
                    self._req("spider/action/stop/", {"scanId": scan_id}, method="POST")
                    return [], "Spider cancelled."

                st_res = self._req("spider/view/status/", {"scanId": scan_id})
                if st_res.ok:
                    prog_str = (st_res.json() or {}).get("status", "0")
                    try:
                        prog_int = int(prog_str)
                        if progress_callback:
                            progress_callback(prog_int)
                        if prog_int >= 100:
                            break
                    except ValueError:
                        pass
                time.sleep(1.5)

            # Retrieve spidered URLs
            urls = []
            results_res = self._req("spider/view/results/", {"scanId": scan_id})
            if results_res.ok:
                for item in (results_res.json() or {}).get("results") or []:
                    if isinstance(item, str) and item.startswith("http"):
                        urls.append(item)

            return urls, None
        except Exception as exc:
            return [], f"Spider error: {exc}"

    # -------------------------------------------------------------------------
    # 4. AJAX Spider (Headless Browser Crawling for SPAs)
    # -------------------------------------------------------------------------
    def run_ajax_spider(
        self,
        url: str,
        context_name: Optional[str] = None,
        timeout: int = 60,
        cancel_check: Optional[Callable[[], bool]] = None,
        allow_private: bool = WEBSCAN_ALLOW_PRIVATE_TARGETS,
    ) -> Tuple[List[str], Optional[str]]:
        """Run ZAP AJAX Spider (Headless browser crawl) for rich single-page applications."""
        validate_scan_url(url, allow_private=allow_private)

        params: Dict[str, Any] = {
            "url": url,
            "inScope": "true",
            "subtreeOnly": "true",
        }
        if context_name:
            params["contextName"] = context_name

        try:
            start_res = self._req("ajaxSpider/action/scan/", params, method="POST")
            if not start_res.ok:
                return [], f"AJAX Spider not supported or failed to start: {start_res.text}"

            deadline = time.time() + timeout
            while time.time() < deadline:
                if cancel_check and cancel_check():
                    self._req("ajaxSpider/action/stop/", method="POST")
                    return [], "AJAX Spider cancelled."

                st_res = self._req("ajaxSpider/view/status/")
                if st_res.ok:
                    status_val = str((st_res.json() or {}).get("status", "")).lower()
                    if status_val == "stopped":
                        break
                time.sleep(2.0)

            # Fetch discovered URLs
            urls = []
            res_list = self._req("ajaxSpider/view/results/", {"start": "0", "count": "200"})
            if res_list.ok:
                for item in (res_list.json() or {}).get("results") or []:
                    if isinstance(item, dict):
                        u = item.get("url")
                        if u and isinstance(u, str) and u.startswith("http"):
                            urls.append(u)
                    elif isinstance(item, str) and item.startswith("http"):
                        urls.append(item)
            return urls, None
        except Exception as exc:
            return [], f"AJAX Spider unavailable: {exc}"

    # -------------------------------------------------------------------------
    # 5. OpenAPI / Swagger Definition Import
    # -------------------------------------------------------------------------
    def import_openapi_spec(
        self,
        spec_url: str,
        context_id: Optional[str] = None,
        allow_private: bool = WEBSCAN_ALLOW_PRIVATE_TARGETS,
    ) -> Tuple[List[str], Optional[str]]:
        """Import OpenAPI/Swagger definition into ZAP to discover and document API endpoints."""
        validate_scan_url(spec_url, allow_private=allow_private)

        params = {"url": spec_url}
        if context_id:
            params["contextId"] = context_id

        try:
            res = self._req("openapi/action/importUrl/", params, method="POST")
            if not res.ok:
                return [], f"OpenAPI import failed: {res.text}"

            # Query core URLs matching target base
            base_parsed = urlparse(spec_url)
            base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"
            urls_res = self._req("core/view/urls/", {"baseurl": base_origin})
            discovered = []
            if urls_res.ok:
                for u in (urls_res.json() or {}).get("urls") or []:
                    if isinstance(u, str) and u.startswith("http"):
                        discovered.append(u)
            return discovered, None
        except Exception as exc:
            return [], f"OpenAPI import not available: {exc}"

    # -------------------------------------------------------------------------
    # 6. Passive Scan Queue Drain
    # -------------------------------------------------------------------------
    def wait_for_passive_scan(
        self,
        timeout: int = 30,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> int:
        """Wait until ZAP passive scan queue drains all pending records."""
        deadline = time.time() + timeout
        records_left = 0
        while time.time() < deadline:
            if cancel_check and cancel_check():
                break
            try:
                res = self._req("pscan/view/recordsToScan/")
                if res.ok:
                    records_str = (res.json() or {}).get("recordsToScan", "0")
                    records_left = int(records_str)
                    if records_left <= 0:
                        break
            except Exception:
                pass
            time.sleep(1.0)
        return records_left

    # -------------------------------------------------------------------------
    # 7. Active Scanner with Rate Limiting & Scope Guardrails
    # -------------------------------------------------------------------------
    def run_active_scan(
        self,
        url: str,
        context_id: Optional[str] = None,
        delay_ms: int = 100,
        timeout: int = 120,
        cancel_check: Optional[Callable[[], bool]] = None,
        progress_callback: Optional[Callable[[int], None]] = None,
        allow_private: bool = WEBSCAN_ALLOW_PRIVATE_TARGETS,
        policy: Optional[str] = None,
        alert_threshold: Optional[str] = None,
        attack_strength: Optional[str] = None,
    ) -> Tuple[int, Optional[str]]:
        """Execute scoped active scan against authorized target with rate limiting and policy/threshold control."""
        validate_scan_url(url, allow_private=allow_private)

        # Set delay between active scan requests
        try:
            self._req("ascan/action/setOptionDelayInMs/", {"Integer": str(max(50, delay_ms))}, method="POST")
        except Exception:
            pass

        # Apply alert threshold & attack strength if specified
        if alert_threshold:
            try:
                self._req("ascan/action/setPolicyAlertThreshold/", {
                    "id": "0",
                    "alertThreshold": alert_threshold.upper(),
                }, method="POST")
            except Exception:
                pass
        if attack_strength:
            try:
                self._req("ascan/action/setPolicyAttackStrength/", {
                    "id": "0",
                    "attackStrength": attack_strength.upper(),
                }, method="POST")
            except Exception:
                pass

        params: Dict[str, Any] = {
            "url": url,
            "recurse": "true",
            "inScopeOnly": "true",
        }
        if context_id:
            params["contextId"] = context_id
        if policy:
            params["scanPolicyName"] = policy

        try:
            start_res = self._req("ascan/action/scan/", params, method="POST")
            if not start_res.ok:
                return 0, f"Active scan start failed: {start_res.text}"
            scan_id = (start_res.json() or {}).get("scan")
            if scan_id is None:
                return 0, "No active scan ID returned."

            deadline = time.time() + timeout
            while time.time() < deadline:
                if cancel_check and cancel_check():
                    self._req("ascan/action/stop/", {"scanId": scan_id}, method="POST")
                    return 0, "Active scan cancelled."

                st_res = self._req("ascan/view/status/", {"scanId": scan_id})
                if st_res.ok:
                    prog_str = (st_res.json() or {}).get("status", "0")
                    try:
                        prog_int = int(prog_str)
                        if progress_callback:
                            progress_callback(prog_int)
                        if prog_int >= 100:
                            break
                    except ValueError:
                        pass
                time.sleep(2.0)

            return 100, None
        except Exception as exc:
            return 0, f"Active scan error: {exc}"

    # -------------------------------------------------------------------------
    # 8. Alert Retrieval & Normalization
    # -------------------------------------------------------------------------
    def fetch_normalized_alerts(
        self,
        base_url: str,
        min_risk: str = "Informational",
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Retrieve all alerts for target from ZAP and normalize into DecodeX schema."""
        raw_alerts = []
        try:
            # Query by baseurl
            for test_url in [base_url, base_url.rstrip("/"), f"{base_url.rstrip('/')}/"]:
                resp = self._req("alert/view/alerts/", {"baseurl": test_url, "start": "0", "count": "200"})
                if resp.ok:
                    items = (resp.json() or {}).get("alerts") or []
                    if items:
                        raw_alerts = items
                        break

            # Fallback: query general session alerts and filter by host
            if not raw_alerts:
                sess_resp = self._req("alert/view/alerts/", {"start": "0", "count": "100"})
                if sess_resp.ok:
                    parsed_target = urlparse(base_url)
                    target_host = (parsed_target.netloc or parsed_target.hostname or "").lower()
                    items = (sess_resp.json() or {}).get("alerts") or []
                    raw_alerts = [a for a in items if target_host in (a.get("url") or "").lower()]

            findings = []
            for a in raw_alerts:
                risk_raw = str(a.get("risk") or "Informational").upper()
                cwe_id = str(a.get("cweid") or "")
                cwe_str = f"CWE-{cwe_id}" if cwe_id and cwe_id != "-1" and not cwe_id.startswith("CWE-") else cwe_id

                # Calculate confidence (0-100)
                conf_raw = str(a.get("confidence") or "").lower()
                conf_score = 90 if "certain" in conf_raw or "high" in conf_raw else (70 if "medium" in conf_raw or "firm" in conf_raw else 50)

                findings.append({
                    "title": a.get("alert") or a.get("name") or "OWASP ZAP Finding",
                    "description": (a.get("description") or "")[:3000],
                    "severity": ZAP_RISK_MAP.get(risk_raw, "INFO"),
                    "confidence": conf_score,
                    "category": "zap",
                    "cwe": cwe_str,
                    "cve": "",
                    "evidence": (a.get("evidence") or a.get("other") or "")[:2000],
                    "recommendation": (a.get("solution") or "Consult OWASP ZAP advisory.")[:2000],
                    "affected_url": a.get("url") or base_url,
                    "source_engine": "zap",
                    "method": a.get("method") or "GET",
                    "parameter": a.get("param") or "",
                    "attack": a.get("attack") or "",
                    "reference": a.get("reference") or "",
                })

            return findings, None
        except Exception as exc:
            return [], f"Failed fetching ZAP alerts: {exc}"

    # -------------------------------------------------------------------------
    # 9. Scan Comparison & Diffing
    # -------------------------------------------------------------------------
    @staticmethod
    def compare_scans(
        previous_findings: List[Dict[str, Any]],
        current_findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compute delta between previous scan and current scan for finding lifecycle management."""
        def _key(f: Dict[str, Any]) -> str:
            return f"{f.get('title')}:{f.get('affected_url')}:{f.get('parameter')}"

        prev_map = {_key(f): f for f in previous_findings}
        curr_map = {_key(f): f for f in current_findings}

        new_keys = set(curr_map.keys()) - set(prev_map.keys())
        resolved_keys = set(prev_map.keys()) - set(curr_map.keys())
        persisted_keys = set(curr_map.keys()) & set(prev_map.keys())

        return {
            "new_findings_count": len(new_keys),
            "resolved_findings_count": len(resolved_keys),
            "persistent_findings_count": len(persisted_keys),
            "new_findings": [curr_map[k] for k in new_keys],
            "resolved_findings": [prev_map[k] for k in resolved_keys],
            "persistent_findings": [curr_map[k] for k in persisted_keys],
        }


# Global singleton instance
zap_client = ZapClient()
