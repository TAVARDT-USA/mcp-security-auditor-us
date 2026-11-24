# Model Context Protocol (MCP) Security Auditor

[![Live Demo](https://img.shields.io/badge/GitHub%20Pages-Live%20Demo-06b6d4?style=for-the-badge)](https://tavardt-usa.github.io/mcp-security-auditor-us/)
[![Standard](https://img.shields.io/badge/Standard-Least%20Privilege-3b82f6?style=for-the-badge)](https://tavardt-usa.github.io/mcp-security-auditor-us/)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Client-Side-10b981?style=for-the-badge)](https://tavardt-usa.github.io/mcp-security-auditor-us/)
[![License](https://img.shields.io/badge/License-MIT-slate?style=for-the-badge)](LICENSE)

Security auditor and permission validator for Model Context Protocol (MCP) servers and tools. Client-side web app and Python CLI.

Engineered for organizations and engineering teams in **United States**, this repository provides a dedicated security suite to inspect, audit, and harden **Model Context Protocol (MCP)** server configurations, enforcing least privilege and sandboxing for autonomous AI agents.

***

## Operational Interfaces

### 1. In-Browser Web Application (GitHub Pages)
Interactive visual interface accessible directly from your browser:
- **Live Demo**: [https://tavardt-usa.github.io/mcp-security-auditor-us/](https://tavardt-usa.github.io/mcp-security-auditor-us/)
- **Privacy by Design**: All processing executes 100% locally in your client JavaScript engine. No configurations, tokens, or paths are ever transmitted to any external server.

### 2. Standalone Python CLI Tool
For automated security gating in CI/CD pipelines, pre-commit hooks, or local workstation auditing:

```bash
# Basic evaluation of an MCP configuration file
python mcp_security_scanner.py -file mcp.json

# Strict mode for CI/CD gates (exits with code 1 upon any finding)
python mcp_security_scanner.py -file mcp.json -strict

# Automatically generate a hardened, sanitized configuration file
python mcp_security_scanner.py -file mcp.json -harden mcp-hardened.json

# Output structured JSON report
python mcp_security_scanner.py -file mcp.json -json
```

***

## Audited Security Vectors

1. **Filesystem Scope & Root Mounts**: Detects unrestricted access to root paths (`/`, `C:\`) and sensitive directories (`/etc`, `~/.ssh`, `System32`).
2. **Arbitrary Command Execution**: Detects raw shell invocations (`bash`, `sh`, `powershell`, `cmd`) and dynamic execution flags (`-c`, `eval`).
3. **Secret & Credential Exposure**: Flags exposed API keys, private tokens, passwords, and database connection strings in plaintext.
4. **Supply Chain & Tool Poisoning**: Enforces strict immutable package version pinning for dynamically resolved tools (`npx`, `uvx`).
5. **SSRF & Private Network Access**: Identifies arguments targeting unauthorized internal network endpoints or loopback interfaces.

***

## GitHub Actions CI/CD Integration

Integrate automated MCP security validation into your continuous deployment workflows:

```yaml
name: MCP Security Gate
on: [push, pull_request]

jobs:
  audit-mcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Run MCP Security Audit
        run: |
          python mcp_security_scanner.py -file config/mcp.json -strict
```

***

## Compliance and Technical Standards

- **Compliance Standard**: NIST AI RMF and Least Privilege Agentic Security Specifications
- **Maintaining Organization**: [TAVARDT-USA](https://github.com/TAVARDT-USA)

## Official Portals

- **Main National Portal**: [Portal Institucional](https://ag.tavardt.com/us/)
- **Tools Hub**: [https://tools.tavardt.com/](https://tools.tavardt.com/)
- **Technical Support Channel**: [Canal de Contato](https://ag.tavardt.com/us/contact/)

***

### License
Released under the MIT License. See [LICENSE](LICENSE) for full details.

***

© 2026 TAVARDT. All rights reserved.
