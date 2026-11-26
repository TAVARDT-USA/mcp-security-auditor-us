<p align="center">
  <a href="https://ag.tavardt.com/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# Model Context Protocol (MCP) Security Auditor

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-usa.github.io/mcp-security-auditor-us/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Configuration security auditor and automated hardening engine for Model Context Protocol (MCP) servers and AI client integrations engineered by **TAVARDT**. Inspects client manifests against direct shell interpreters, dangerous volume mounts, plaintext credentials, unpinned dependencies, and cloud metadata SSRF vectors.

Maintained by the engineering practice at **TAVARDT**.

***

## 1. Core Capabilities and Defensive Architecture

The toolkit enforces least-privilege boundaries and configuration security across autonomous AI systems and Model Context Protocol integrations:

* **Least-Privilege Manifest Verification**: Audits server definitions within client configuration files against established zero-trust access boundaries.
* **Automated Configuration Hardening**: Generates drop-in sanitized configuration files that isolate shell execution inside read-only containers and abstract credentials.
* **Flexible Pipeline Integration**: Operates as a local terminal auditor, automated CI/CD gating action with strict exit codes, or JSON reporting engine.

***

## 2. Security Risk Vectors and Operational Impact

Unrestricted MCP server configurations expose host operating systems and local environments to lateral movement, data theft, and unauthorized remote execution. The scanner intercepts six distinct threat vectors to safeguard AI agent environments:

* **Direct Shell Interpreter Execution**: Identifies raw shell commands such as bash, powershell, or cmd running without container sandboxing.
* **Dynamic Execution Flags**: Flags arbitrary code evaluation switches like -c, /c, invoke-expression, or dynamic eval that permit unverified code interpretation.
* **Root and Sensitive Filesystem Mounting**: Blocks full host storage mounts and unauthorized exposure of paths such as SSH keys, AWS configs, and system directories.
* **Plaintext Database and API Credentials**: Flags hardcoded database passwords and private API authentication tokens stored without environment variable references.
* **SSRF and Internal Cloud Metadata Probing**: Intercepts arguments pointing to protected cloud instance metadata endpoints and internal service hosts.
* **Unpinned Remote Package Execution**: Detects npx, uvx, or pipx runners resolving remote tools without immutable version tags.

The security score starts at 100 points and decreases with each detected finding. Zero findings represent full compliance with least-privilege standards, while critical vulnerabilities trigger immediate failure codes in automated environments.

***

## 3. Workflow Integration and Execution

Audit configurations locally or integrate automated validation gates into continuous deployment pipelines:

```yaml
name: MCP Security Audit

on:
  push:
    branches: [main]
  pull_request:

jobs:
  mcp-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run TAVARDT MCP Security Auditor
        uses: TAVARDT-USA/mcp-security-auditor-us@v1
        with:
          config-file: 'mcp.json'
          strict: 'false'
```

### Local CLI Execution

You can also run the auditor directly using standard Python runtime tooling:

```bash
python mcp_security_scanner.py -f mcp.json
python mcp_security_scanner.py -f mcp.json -s
python mcp_security_scanner.py -f mcp.json -o hardened_mcp.json -j
```

***

## 4. Frequently Asked Technical Questions (FAQ)

### What threat vectors does the MCP security auditor evaluate in server configurations?
The scanner audits configurations against direct shell invocation, dynamic command execution flags, root filesystem mounts, exposed credentials, unpinned packages, and cloud metadata SSRF attempts. Detected security anomalies apply weighted penalty deductions from an initial security score of 100 points.

### How does the scanner mitigate privilege escalation risks from unrestricted directory mounts?
The auditor flags root directory mounts and access to sensitive paths like SSH keys, AWS credentials, and system directories with critical severity. Sanitizing configurations with the -o parameter automatically restricts mounts to isolated sandbox paths under the principle of least privilege.

### Why are dynamic execution flags such as -c or eval considered critical vulnerabilities?
Passing dynamic execution flags allows language model clients or malicious inputs to evaluate arbitrary shell commands on the host environment. Blocking these flags ensures that tools execute strictly predefined, parameterized binaries without arbitrary code interpretation.

### How does the automated configuration hardening feature protect exposed credentials?
The auto-hardening routine generated with the -o option replaces hardcoded connection strings and plain text API keys with host environment variable placeholders. This approach prevents sensitive authentication tokens from leaking into version control repositories or multi-tenant agent logs.

### Can the toolkit enforce security compliance within automated CI/CD pipelines?
The GitHub Action evaluates configuration files directly using the config-file parameter and supports a strict exit code mode through the strict option. When strict evaluation is enabled, the workflow terminates with an exit code to programmatically halt downstream jobs whenever security violations are detected.

***

## Useful Links

* Corporate Portal: https://ag.tavardt.com/
* Diagnostic Suite: https://tools.tavardt.com/
* Technical Contact: https://ag.tavardt.com/contact/

***

## License

Released under the MIT License.

***

© 2026 TAVARDT. All rights reserved.
