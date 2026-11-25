# Model Context Protocol (MCP) Security Auditor

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-usa.github.io/mcp-security-auditor-us/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

***

Configuration security auditor and automated hardening engine for Model Context Protocol (MCP) servers and AI client integrations engineered by **TAVARDT**. Inspects client manifests against direct shell interpreters, dangerous volume mounts, plaintext credentials, unpinned dependencies, and cloud metadata SSRF vectors.

***

## Core Capabilities and Defensive Architecture

* **Least-Privilege Manifest Verification**: Audits server definitions within client configuration files against established zero-trust access boundaries.
* **Automated Configuration Hardening**: Generates drop-in sanitized configuration files that isolate shell execution inside read-only containers and abstract credentials.
* **Flexible Pipeline Integration**: Operates as a local terminal auditor, automated CI/CD gating tool with strict exit codes, or JSON reporting engine.

***

## Security Risk Vectors and Operational Impact

Unrestricted MCP server configurations expose host operating systems and local environments to lateral movement, data theft, and unauthorized remote execution. The scanner intercepts six distinct threat vectors to safeguard AI agent environments:

* **Direct Shell Interpreter Execution (`Command Execution`)**: Identifies raw shell commands such as bash, powershell, or cmd running without container sandboxing (-35 penalty points, CRITICAL).
* **Dynamic Execution Flags (`Command Execution`)**: Flags arbitrary code evaluation switches like -c, /c, invoke-expression, or dynamic eval (-25 penalty points, CRITICAL).
* **Root and Sensitive Filesystem Mounting (`Filesystem Access`)**: Blocks full host storage mounts (-35 penalty points) and exposure of sensitive paths such as SSH keys, AWS configs, and system directories (-30 penalty points, CRITICAL).
* **Plaintext Database and API Credentials (`Exposed Secrets`)**: Flags hardcoded database passwords and private API authentication tokens stored without environment variable references (-20 penalty points, HIGH).
* **SSRF and Internal Cloud Metadata Probing (`Network Security`)**: Intercepts arguments pointing to protected cloud instance metadata endpoints and internal service hosts (-20 penalty points, HIGH).
* **Unpinned Remote Package Execution (`Supply Chain Security`)**: Detects npx, uvx, or pipx runners resolving remote tools without immutable version tags (-10 penalty points, MEDIUM).

The security score starts at 100 points and decreases with each detected finding. Zero findings represent full compliance with least-privilege standards, while critical vulnerabilities trigger immediate failure codes in automated environments.

***

## CLI Installation and Execution

Audit configurations locally or integrate automated validation gates using Python standard library tooling:

```bash
# Clone the official repository
git clone https://github.com/TAVARDT-USA/mcp-security-auditor-us.git

# Enter workspace directory
cd mcp-security-auditor-us

# Audit an MCP configuration file
python mcp_security_scanner.py -f mcp.json

# Enforce strict validation mode
python mcp_security_scanner.py -f mcp.json -s

# Generate hardened configuration and export JSON
python mcp_security_scanner.py -f mcp.json -o hardened_mcp.json -j
```

***

## Frequently Asked Technical Questions

### What threat vectors does the MCP security auditor evaluate in server configurations?

The scanner audits configurations against direct shell invocation, dynamic command execution flags, root filesystem mounts, exposed credentials, unpinned packages, and cloud metadata SSRF attempts. Detected security anomalies apply weighted penalty deductions from an initial security score of 100 points.

### How does the scanner mitigate privilege escalation risks from unrestricted directory mounts?

The auditor flags root directory mounts and access to sensitive paths like SSH keys, AWS credentials, and system directories with critical severity. Sanitizing configurations with the -o parameter automatically restricts mounts to isolated sandbox paths under the principle of least privilege.

### Why are dynamic execution flags such as -c or eval considered critical vulnerabilities?

Passing dynamic execution flags allows language model clients or malicious inputs to evaluate arbitrary shell commands on the host environment. Blocking these flags ensures that tools execute strictly predefined, parameterized binaries without arbitrary code interpretation.

### How does the automated configuration hardening feature protect exposed credentials?

The auto-hardening routine generated with the -o option replaces hardcoded connection strings and plain text API keys with host environment variable placeholders. This approach prevents sensitive authentication tokens from leaking into version control repositories or multi-tenant agent logs.

### Can the toolkit enforce security compliance within automated CI/CD pipelines?

The CLI tool evaluates configuration files directly using the -f parameter and supports a strict exit code mode through the -s option. When coupled with the -j flag for JSON structured output, teams can programmatically halt build pipelines if any security violations are found.

***

## Useful Links

* **Corporate Portal:** https://ag.tavardt.com/
* **Diagnostic Suite:** https://tools.tavardt.com/
* **Technical Contact:** https://ag.tavardt.com/contact/

***

### License
Released under the MIT License. See [LICENSE](LICENSE) for full details.

***

© 2026 TAVARDT. All rights reserved.
