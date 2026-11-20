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
METADATA_IPS = ["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1"]

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
                "title": "Raw Shell Interpreter Execution Detected",
                "detail": "The server invokes '{cmd}' directly without process containment.".replace("{cmd}", srv.get("command", "")),
                "remediation": "Eliminate raw shell invocations. Use sandboxed Docker containers."
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
                    "title": "Arguments Contain Dynamic Command Execution Flags",
                    "detail": "Detected argument '{arg}', enabling arbitrary subshell execution.".replace("{arg}", str(arg)),
                    "remediation": "Remove execution flags such as -c or eval. Enforce strict parameter validation."
                })
                penalty += 25

        # 3. Filesystem mounting
        for arg in args:
            a_str = str(arg).strip().lower()
            if a_str in ROOT_PATHS:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Filesystem Scope",
                    "title": "Root Filesystem Directory Mounting Detected",
                    "detail": "Path '{path}' grants unrestricted read and write permissions to host drive.".replace("{path}", str(arg)),
                    "remediation": "Restrict allowed directory paths to dedicated workspace sandboxes."
                })
                penalty += 35
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Filesystem Scope",
                    "title": "Permitted Access to Sensitive Operating System Paths",
                    "detail": "The server has permission to access sensitive paths in '{path}'.".replace("{path}", str(arg)),
                    "remediation": "Block access to SSH keys and protected OS system folders."
                })
                penalty += 30

        # 4. Exposed secrets in env
        for e_key, e_val in env.items():
            val = str(e_val or "").strip()
            if val.startswith("${") and val.endswith("}"):
                continue

            is_secret_key = bool(re.search(r"token|secret|key|password|passwd|auth|bearer", e_key, re.I))
            is_sensitive_url = bool(re.search(r"postgres:|mongodb:|mysql:|redis:", val, re.I) and "@" in val)
            is_known_prefix = bool(re.match(r"^sk-[a-zA-Z0-9_-]{20,}|^ghp_[a-zA-Z0-9]{20,}|^xoxb-[a-zA-Z0-9-]{20,}|^AKIA[0-9A-Z]{16}", val))

            if is_sensitive_url:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Secret Exposure",
                    "title": "Database Connection String with Plaintext Password",
                    "detail": "Environment variable '{key}' exposes production database credentials.".replace("{key}", e_key),
                    "remediation": "Replace static credentials with an environment variable reference: ${{ {key} }}.".replace("{key}", e_key)
                })
                penalty += 30
            elif is_known_prefix or (is_secret_key and len(val) >= 10):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Secret Exposure",
                    "title": "API Key or Private Token Exposed in Plaintext",
                    "detail": "Environment variable '{key}' contains a plaintext secret key.".replace("{key}", e_key),
                    "remediation": "Store secrets in system environment variables and reference them: ${{ {key} }}.".replace("{key}", e_key)
                })
                penalty += 25

        # 5. Supply chain / unpinned packages
        if cmd in ["npx", "uvx"]:
            pkg_found = False
            is_pinned = False
            pkg_name = ""
            for arg in args:
                a_str = str(arg)
                if a_str == "-y" or a_str.startswith("--"):
                    continue
                if not pkg_found and ("/" in a_str or "-" in a_str or len(a_str) > 2):
                    pkg_found = True
                    pkg_name = a_str
                    if "@" in a_str and a_str.rfind("@") > 0:
                        is_pinned = True
                    if "==" in a_str:
                        is_pinned = True
            if pkg_found and not is_pinned:
                findings.append({
                    "server": s_name,
                    "severity": "MEDIUM",
                    "category": "Supply Chain Security",
                    "title": "Unpinned Remote Package (Supply Chain Risk)",
                    "detail": "Package '{pkg}' is resolved dynamically without an immutable version tag.".replace("{pkg}", pkg_name),
                    "remediation": "Pin an exact immutable version (e.g., {pkg}@1.0.0 or ==1.0.0).".replace("{pkg}", pkg_name)
                })
                penalty += 10

        # 6. SSRF / Metadata
        for arg in args:
            a_str = str(arg)
            if any(mip in a_str for mip in METADATA_IPS):
                findings.append({
                    "server": s_name,
                    "severity": "HIGH",
                    "category": "Network and SSRF",
                    "title": "Potential SSRF or Cloud Metadata Exposure",
                    "detail": "Argument '{target}' points towards loopback interfaces or cloud metadata.".replace("{target}", a_str),
                    "remediation": "Enforce strict domain allowlists and block internal metadata IP addresses."
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
            elif "169.254.169.254" in a_str:
                cleaned_args.append("127.0.0.1:blocked")
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
        description="Security Auditor for Model Context Protocol (MCP) Configuration Manifests."
    )
    parser.add_argument("--file", "-f", required=True, help="Path to mcp.json or claude_desktop_config.json configuration file")
    parser.add_argument("--strict", action="store_true", help="Strict mode: exit with code 1 if any finding is detected")
    parser.add_argument("--harden", "-o", help="Export hardened, sanitized JSON configuration to target path")
    parser.add_argument("--json", action="store_true", help="Output analysis in structured JSON format")

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
        print(f"Hardened configuration successfully written to: {args.harden}")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=" * 64)
        print(f"MCP SECURITY AUDIT: TAVARDT United States")
        print(f"Standard: NIST AI RMF and Least Privilege Agentic Security Specifications")
        print(f"Servers Analyzed: {report['server_count']}")
        print(f"Security Score: {report['score']} / 100")
        print(f"Findings Detected: {len(report['findings'])}")
        print("=" * 64)

        if not report["findings"]:
            print("No vulnerabilities detected. Configuration adheres to the principle of least privilege.")
        else:
            for idx, finding in enumerate(report["findings"], 1):
                print(f"[{idx}] [{finding['severity']}] {finding['server']}: {finding['title']}")
                print(f"    Category: {finding['category']}")
                print(f"    Detail: {finding['detail']}")
                print(f"    Remediation: {finding['remediation']}")
                print("-" * 64)

    # Exit code determination
    critical_count = sum(1 for f in report["findings"] if f["severity"] == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)
    if args.strict and report["findings"]:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
