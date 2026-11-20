#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT United States
Model Context Protocol (MCP) Security Auditor
Security auditor and permission validator for Model Context Protocol (MCP) servers and tools. Client-side web app and Python CLI.

Standard: NIST AI RMF and Least Privilege Agentic Security Specifications
Repository: https://github.com/TAVARDT-USA/mcp-security-auditor-us
Online Web App: https://tavardt-usa.github.io/mcp-security-auditor-us/
"""

import os
import sys
import json
import re
import argparse

DANGEROUS_SHELLS = ["bash", "sh", "zsh", "powershell", "powershell.exe", "cmd", "cmd.exe"]
ROOT_PATHS = ["/", "\\", "c:\\", "c:/", "d:\\", "d:/", "~", "$home", "%userprofile%"]
SENSITIVE_PATHS = ["/etc", "/var", "/root", ".ssh", ".aws", ".gnupg", "system32", "appdata"]
METADATA_HOSTS = ["metadata.cloud-provider.internal", "metadata.internal", "instance-data.internal", "cloud-metadata.service"]

def analyze_mcp_config(config_data):
    servers = {}
    if "mcpServers" in config_data and isinstance(config_data["mcpServers"], dict):
        servers = config_data["mcpServers"]
    elif isinstance(config_data, dict):
        servers = config_data

    findings = []
    penalty = 0

    for s_name, srv in servers.items():
        if not isinstance(srv, dict):
            continue

        cmd = (srv.get("command") or "").strip().lower()
        args = srv.get("args") or []
        env = srv.get("env") or {}

        # 1. Shell execution
        if cmd in DANGEROUS_SHELLS:
            findings.append({
                "server": s_name,
                "severity": "CRITICAL",
                "category": "Command Execution",
                "title": "Direct Shell Interpreter Execution Detected",
                "detail": "Server executes shell interpreter '{cmd}' directly without container isolation.".replace("{cmd}", srv.get("command", "")),
                "remediation": "Remove direct shell invocation. Run tools in isolated Docker containers with minimal privileges."
            })
            penalty += 35

        # 2. Dynamic command flags
        for arg in args:
            a_str = str(arg).lower()
            if a_str in ["-c", "/c", "-command"] or "invoke-expression" in a_str or "eval(" in a_str:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Command Execution",
                    "title": "Command Arguments with Dynamic Execution Flags",
                    "detail": "Flag '{arg}' detected, enabling arbitrary code evaluation.".replace("{arg}", str(arg)),
                    "remediation": "Remove flags like -c or dynamic eval. Parameterize tools with strict schemas."
                })
                penalty += 25

        # 3. Filesystem mounting
        for arg in args:
            a_str = str(arg).strip().lower()
            if a_str in ROOT_PATHS:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Filesystem Access",
                    "title": "Root Filesystem Directory Mount",
                    "detail": "Path '{path}' grants unrestricted access to the entire host storage.".replace("{path}", str(arg)),
                    "remediation": "Restrict mounts to dedicated, non-sensitive project subdirectories."
                })
                penalty += 35
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Filesystem Access",
                    "title": "Sensitive Operating System Directory Access",
                    "detail": "Server is allowed to access protected files in '{path}'.".replace("{path}", str(arg)),
                    "remediation": "Deny access to SSH keys, credentials, and protected operating system paths."
                })
                penalty += 30

        # 4. Plaintext secrets
        for env_k, env_v in env.items():
            k_lower = env_k.lower()
            v_str = str(env_v or "")
            if any(s_k in k_lower for s_k in ["db_url", "database_url", "conn_str", "postgres", "mysql"]):
                if "password" in v_str.lower() or "://" in v_str:
                    findings.append({
                        "server": s_name,
                        "severity": "HIGH",
                        "category": "Exposed Secrets",
                        "title": "Database Connection String with Plaintext Password",
                        "detail": "Environment variable '{key}' contains exposed connection credentials.".replace("{key}", env_k),
                        "remediation": "Replace with host environment variable reference: ${{ {key} }}.".replace("{key}", env_k)
                    })
                    penalty += 20
            elif any(s_k in k_lower for s_k in ["api_key", "secret", "token", "auth", "private_key"]):
                if not (v_str.startswith("${") and v_str.endswith("}")):
                    findings.append({
                        "server": s_name,
                        "severity": "HIGH",
                        "category": "Exposed Secrets",
                        "title": "Plaintext API Key or Authentication Token Exposed",
                        "detail": "Variable '{key}' contains a hardcoded private token.".replace("{key}", env_k),
                        "remediation": "Use host environment variables: ${{ {key} }}.".replace("{key}", env_k)
                    })
                    penalty += 20

        # 5. Supply chain unpinned packages
        if cmd in ["npx", "uvx", "pipx"]:
            pkg_found = False
            is_pinned = False
            pkg_name = ""
            for a in args:
                a_str = str(a)
                if not a_str.startswith("-"):
                    pkg_found = True
                    pkg_name = a_str
                    if "@" in a_str[1:] or "==" in a_str:
                        is_pinned = True
            if pkg_found and not is_pinned:
                findings.append({
                    "server": s_name,
                    "severity": "MEDIUM",
                    "category": "Supply Chain Security",
                    "title": "Unpinned Remote Package (Supply Chain Risk)",
                    "detail": "Package '{pkg}' is resolved dynamically without an immutable version tag.".replace("{pkg}", pkg_name),
                    "remediation": "Pin exact package version (e.g. {pkg}@1.0.0 or ==1.0.0).".replace("{pkg}", pkg_name)
                })
                penalty += 10

        # 6. SSRF / Metadata
        for arg in args:
            a_str = str(arg)
            if any(mip in a_str for mip in METADATA_HOSTS):
                findings.append({
                    "server": s_name,
                    "severity": "HIGH",
                    "category": "Network & SSRF Prevention",
                    "title": "Potential SSRF or Cloud Metadata Service Access",
                    "detail": "Argument '{target}' points to internal metadata services or protected endpoints.".replace("{target}", a_str),
                    "remediation": "Configure strict domain allowlists and block internal cloud metadata endpoints."
                })
                penalty += 20

    score = max(0, 100 - penalty)
    return {
        "server_count": len(servers),
        "score": score,
        "findings": findings,
        "servers": servers
    }

def harden_config(servers):
    hardened = {"mcpServers": {}}
    for s_name, srv in servers.items():
        if not isinstance(srv, dict):
            continue
        h_cmd = srv.get("command", "")
        h_args = list(srv.get("args") or [])

        # Wrap shells
        if h_cmd.lower() in DANGEROUS_SHELLS:
            h_cmd = "docker"
            h_args = ["run", "--rm", "-i", "--read-only", "--cap-drop=ALL", "sandbox-runner:latest"]

        # Restrict root or critical paths
        cleaned_args = []
        for a in h_args:
            a_str = str(a).strip().lower()
            if a_str in ROOT_PATHS:
                cleaned_args.append("/workspace/sandbox/app-data")
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                cleaned_args.append("/workspace/sandbox/isolated-storage")
            elif any(mh in a_str for mh in METADATA_HOSTS):
                cleaned_args.append("metadata-blocked.internal")
            elif h_cmd in ["npx", "uvx"] and a_str.startswith("@modelcontextprotocol/server-") and "@" not in a_str[1:]:
                cleaned_args.append(str(a) + "@0.6.2")
            else:
                cleaned_args.append(a)

        h_srv = {
            "command": h_cmd,
            "args": cleaned_args
        }

        # Abstract secrets into env vars
        if "env" in srv and isinstance(srv["env"], dict):
            h_env = {}
            for e_k, e_v in srv["env"].items():
                v_str = str(e_v or "")
                if v_str.startswith("${") and v_str.endswith("}"):
                    h_env[e_k] = v_str
                else:
                    h_env[e_k] = "${" + e_k.upper() + "}"
            h_srv["env"] = h_env

        hardened["mcpServers"][s_name] = h_srv
    return hardened

def main():
    parser = argparse.ArgumentParser(
        description="Security Auditor for Model Context Protocol (MCP) Configuration Files."
    )
    parser.add_argument("--file", "-f", required=True, help="Path to mcp.json or AI agent client configuration file")
    parser.add_argument("--strict", action="store_true", help="Strict mode: exit with code 1 if any security findings are detected")
    parser.add_argument("--harden", "-o", help="Export hardened, sanitized JSON configuration file")
    parser.add_argument("--json", action="store_true", help="Output results as structured JSON")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"Error reading JSON from {args.file}: {e}", file=sys.stderr)
        sys.exit(2)

    report = analyze_mcp_config(cfg)

    if args.harden:
        hardened_json = harden_config(report["servers"])
        with open(args.harden, "w", encoding="utf-8") as out_f:
            json.dump(hardened_json, out_f, indent=2)
        print(f"Hardened configuration written successfully to: {args.harden}")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=" * 64)
        print(f"MCP SECURITY AUDIT: TAVARDT United States")
        print(f"Standard: NIST AI RMF and Least Privilege Agentic Security Specifications")
        print(f"Analyzed Servers: {report['server_count']}")
        print(f"Security Score: {report['score']} / 100")
        print(f"Detected Findings: {len(report['findings'])}")
        print("=" * 64)

        if not report["findings"]:
            print("Zero findings detected. Configuration complies with the least-privilege security principle.")
        else:
            for idx, finding in enumerate(report["findings"], 1):
                print(f"[{idx}] [{finding['severity']}] {finding['server']}: {finding['title']}")
                print(f"    Category: {finding['category']}")
                print(f"    Detail: {finding['detail']}")
                print(f"    Remediation: {finding['remediation']}")
                print("-" * 64)

    critical_count = sum(1 for f in report["findings"] if f["severity"] == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)
    if args.strict and report["findings"]:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
