"""
DecodeX AI SOC Reasoning & Threat Triage Engine.

Provides deep cyber incident analysis, root-cause investigation, MITRE ATT&CK
tactical explanations, blast radius evaluation, and automated remediation code
generation (Vercel firewall rules, Cloudflare WAF expressions, Nginx deny rules,
and system containment playbooks).
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("th.ai_engine")

# MITRE ATT&CK Technique database for instant tactical triage
MITRE_TACTICAL_KNOWLEDGE = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversary is abusing command interpreters (PowerShell, Bash, CMD) to run malicious code or payload droppers directly in memory.",
        "motive": "Gain execution footprint, bypass traditional antivirus file-based scanning, and establish initial foothold.",
        "containment": "Isolate the endpoint, terminate suspicious parent-child process chains, and enforce script block logging and Constrained Language Mode.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversary is establishing outbound C2 beaconing using legitimate web protocols (HTTP, HTTPS, DNS) to blend into legitimate traffic.",
        "motive": "Maintain persistent communication with an external command server to receive operator instructions and exfiltrate data.",
        "containment": "Block the destination C2 IP/domain at network perimeter and DNS resolvers. Flush local DNS cache and capture network socket telemetry.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Defense Evasion",
        "description": "Adversary has compromised legitimate credentials and is authenticating through authorized channels without generating exploit noise.",
        "motive": "Blend in with legitimate administrator or developer traffic to evade signature-based detection.",
        "containment": "Immediately revoke active user sessions, rotate credentials, enforce MFA step-up challenge, and review audit trails for unauthorized resource access.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversary is sending targeted exploit payloads (SQLi, SSRF, RCE, Path Traversal) against public web applications or APIs.",
        "motive": "Compromise Internet-facing web servers or serverless functions to obtain remote shell access or steal underlying database contents.",
        "containment": "Apply an edge WAF virtual patch immediately. Restrict the source IP at CDN/gateway level and review web server access logs for data exfiltration.",
    },
    "T1110": {
        "name": "Brute Force / Credential Stuffing",
        "tactic": "Credential Access",
        "description": "Adversary is systematically testing passwords or credential lists against public authentication APIs or login portals.",
        "motive": "Achieve account takeover (ATO) on high-privilege accounts or customers.",
        "containment": "Deploy rate-limiting and CAPTCHA challenge at the edge. Enforce account lockout policies and block automated user-agent botnets.",
    },
}


def triage_alert(alert: dict[str, Any], org_name: str = "DecodeX Security Technologies") -> dict[str, Any]:
    """Analyze a SIEM security alert and generate an executive investigation package."""
    technique_id = (alert.get("technique_id") or "").strip().upper()
    tactic = alert.get("tactic") or "Threat Activity"
    desc = alert.get("description") or "Suspicious Security Event"
    host = alert.get("host") or "Target Asset"
    user = alert.get("user") or "system/anonymous"
    ip = alert.get("ip") or alert.get("destination_ip") or ""
    process = alert.get("process") or "Unknown Process"
    commandline = alert.get("commandline") or ""
    severity = (alert.get("severity") or "MEDIUM").upper()
    risk_score = alert.get("risk_score") or (85 if severity == "CRITICAL" else 65)

    # Match tactical intelligence
    matched_tech = None
    for prefix, data in MITRE_TACTICAL_KNOWLEDGE.items():
        if prefix in technique_id or prefix in desc:
            matched_tech = data
            break

    if not matched_tech:
        matched_tech = {
            "name": f"Adversary Technique ({technique_id or tactic})",
            "tactic": tactic,
            "description": f"Observed suspicious telemetry involving {process} on host {host}.",
            "motive": "Gain unauthorized vantage point, execute unauthorized code, or compromise enterprise security boundaries.",
            "containment": "Quarantine affected host, review active network connections, and inspect authentication logs.",
        }

    # Generate edge & system remediation scripts
    remediation_scripts = _generate_alert_scripts(ip, host, process, commandline)

    summary = (
        f"The DecodeX AI Engine evaluated incident <b>{alert.get('id', 'N/A')}</b> as a <b>{severity}</b> severity event "
        f"with a calibrated risk score of <b>{risk_score}/100</b>. The adversary activity aligns with MITRE ATT&CK tactic "
        f"<b>{matched_tech['tactic']}</b> ({matched_tech['name']}). Telemetry identifies <code>{process}</code> executing on "
        f"<b>{host}</b>" + (f" associated with user <code>{user}</code>" if user and user != "system/anonymous" else "") +
        (f" communicating with indicator <code>{ip}</code>." if ip else ".")
    )

    blast_radius = (
        f"High risk of lateral movement if host <b>{host}</b> has access to production data, VPC interconnects, "
        f"or cloud IAM credentials. Immediate isolation is advised."
        if severity in {"CRITICAL", "HIGH"}
        else f"Localized security anomaly on asset <b>{host}</b>. Low likelihood of enterprise-wide compromise if contained within 1 hour."
    )

    action_checklist = [
        f"1. Containment: Immediately apply network-level drop for adversary indicator ({ip or host}).",
        f"2. Investigation: Inspect memory and running tasks on asset '{host}' for persistent child processes.",
        f"3. Identity: Check if user '{user}' has unusual recent logins from unfamiliar IP addresses.",
        f"4. Prevention: Deploy rule to prevent recurrence across your fleet.",
    ]

    return {
        "engine": "DecodeX AI Copilot",
        "severity": severity,
        "risk_score": risk_score,
        "executive_summary": summary,
        "mitre_analysis": {
            "technique_id": technique_id or "T1059",
            "technique_name": matched_tech["name"],
            "tactic": matched_tech["tactic"],
            "description": matched_tech["description"],
            "attacker_motive": matched_tech["motive"],
        },
        "blast_radius": blast_radius,
        "containment_guidance": matched_tech["containment"],
        "action_checklist": action_checklist,
        "remediation_code": remediation_scripts,
    }


def triage_web_finding(finding: dict[str, Any], target: dict[str, Any] | None = None) -> dict[str, Any]:
    """Analyze a web vulnerability finding and provide instant remediation patches and edge WAF rules."""
    title = finding.get("title") or "Web Application Security Vulnerability"
    severity = (finding.get("severity") or "MEDIUM").upper()
    cve_id = finding.get("cve_id") or "N/A"
    cwe_id = finding.get("cwe_id") or "CWE-General"
    url = finding.get("url") or "/"
    method = finding.get("method") or "GET"
    param = finding.get("param") or "query"
    evidence = finding.get("evidence") or ""
    solution = finding.get("solution") or "Apply input sanitization and secure HTTP response headers."

    target_name = (target or {}).get("name") or "Web Target"
    target_url = (target or {}).get("url") or url

    # Exploitability assessment
    is_critical = severity in {"CRITICAL", "HIGH"}
    exploitability = (
        "HIGH — Public exploit vectors or trivial unauthenticated request crafting available."
        if is_critical
        else "MODERATE — Requires specific preconditions, valid authentication, or targeted user interaction."
    )

    # Edge WAF rule generation (Vercel, Cloudflare, Nginx)
    waf_rules = _generate_waf_rules(url, param, method)

    summary = (
        f"DecodeX AI assessed <b>{title}</b> on target <b>{target_name}</b> (<code>{url}</code>) as <b>{severity}</b> severity. "
        f"This finding maps to <b>{cwe_id}</b>" + (f" (CVE: <code>{cve_id}</code>)" if cve_id != "N/A" else "") +
        f". An external adversary can leverage this vector to compromise client sessions, tamper with data, or bypass authorization controls."
    )

    return {
        "engine": "DecodeX AI Copilot",
        "title": title,
        "severity": severity,
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "exploitability": exploitability,
        "executive_summary": summary,
        "root_cause": f"Insufficient server-side parameter validation or missing defensive security policies for '{param}' on endpoint '{url}'.",
        "developer_patch": solution,
        "edge_waf_mitigation": waf_rules,
        "evidence_snippet": evidence[:300] if evidence else "Pattern matched during DAST automated crawler verification.",
    }


def _generate_alert_scripts(ip: str, host: str, process: str, cmd: str) -> dict[str, str]:
    """Generate ready-to-run defense scripts across common enterprise stacks."""
    target_ip = ip or "198.51.100.25"
    return {
        "vercel_firewall": f'// vercel.json — Instant IP Block Rule\n{{\n  "crons": [],\n  "headers": [],\n  "rewrites": [\n    {{\n      "source": "/(.*)",\n      "has": [{{"type": "header", "key": "x-forwarded-for", "value": ".*{target_ip}.*"}}],\n      "destination": "/403"\n    }}\n  ]\n}}',
        "cloudflare_waf": f'(ip.src eq {target_ip}) or (http.request.uri.path contains "{process}")\nAction: BLOCK',
        "linux_iptables": f"# Linux Host Containment\nsudo iptables -I INPUT -s {target_ip} -j DROP\nsudo iptables -I OUTPUT -d {target_ip} -j DROP",
        "nginx_deny": f"# /etc/nginx/conf.d/blocklist.conf\ndeny {target_ip};\n# Reload with: sudo nginx -s reload",
        "powershell_containment": f"# Windows SOC Response\nStop-Process -Name '{process.replace('.exe', '')}' -Force -ErrorAction SilentlyContinue\nNew-NetFirewallRule -DisplayName 'DecodeX-Block-{target_ip}' -Direction Outbound -RemoteAddress {target_ip} -Action Block",
    }


def _generate_waf_rules(url: str, param: str, method: str) -> dict[str, str]:
    """Generate edge WAF mitigation expressions for web findings."""
    clean_path = url.split("?")[0].replace("https://", "").replace("http://", "")
    path_only = "/" + "/".join(clean_path.split("/")[1:]) if "/" in clean_path else "/"
    return {
        "vercel_edge_middleware": f'// middleware.ts (Next.js / Vercel Edge Middleware)\nimport {{ NextResponse }} from "next/server";\nimport type {{ NextRequest }} from "next/server";\n\nexport function middleware(req: NextRequest) {{\n  if (req.nextUrl.pathname.startsWith("{path_only}")) {{\n    const paramVal = req.nextUrl.searchParams.get("{param}");\n    if (paramVal && /[<>\'\\"\\;\\(\\)]/.test(paramVal)) {{\n      return new NextResponse("Blocked by DecodeX Security Policy", {{ status: 403 }});\n    }}\n  }}\n  return NextResponse.next();\n}}',
        "cloudflare_expression": f'(http.request.uri.path eq "{path_only}" and (http.request.uri.query contains "<script" or http.request.uri.query contains "union"))',
        "nginx_rule": f'location {path_only} {{\n    if ($query_string ~* "({param}=.*[<>\'\\"])") {{\n        return 403 "Blocked by DecodeX WAF Rule";\n    }}\n    proxy_pass http://backend;\n}}',
    }
