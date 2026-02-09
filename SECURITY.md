# Security Policy

## Responsible Use

Cepheus is a **defensive security tool** designed for authorized security assessments, penetration testing, red team exercises, and container hardening. It identifies misconfigurations and escape paths so that defenders can remediate them.

**Do not use this tool against systems you do not own or have explicit written authorization to test.**

## Reporting Vulnerabilities

If you discover a security vulnerability in Cepheus itself (e.g., in the enumerator script, the analysis engine, or the PoC templates), please report it responsibly:

1. **Do not** open a public issue.
2. Email the maintainer directly or use GitHub's private vulnerability reporting feature.
3. Include:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

## Scope

The following are **in scope** for security reports:

- Command injection in the CLI or enumerator
- Path traversal in file handling
- Sensitive data exposure (API keys, credentials) in logs or output
- Denial of service via crafted posture JSON input
- Arbitrary code execution through PoC template rendering

The following are **out of scope**:

- The PoC commands themselves (they are intentionally offensive — that's the point)
- Techniques that require local access to the machine running Cepheus
- Social engineering

## LLM Integration Security

When using the optional `--llm` flag, be aware that container posture data (capabilities, mounts, kernel version, etc.) is sent to the configured LLM provider. **Do not use LLM enrichment on posture data from classified or highly sensitive environments** unless your LLM provider meets your organization's data handling requirements.
