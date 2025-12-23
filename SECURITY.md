# Security Policy

## Supported Versions
Scope Finder is provided as-is. Security fixes may be released as tagged versions.

## Reporting a Vulnerability
If you believe you’ve found a security vulnerability, please report it responsibly.

**Please do NOT open a public GitHub issue for security reports.**

Instead, report privately with:
- A clear description of the issue
- Steps to reproduce
- Impact assessment (what an attacker can do)
- Any logs, screenshots, or proof-of-concept details (safe and minimal)

## What to Expect
- We will acknowledge receipt when possible
- We will investigate and, if confirmed, work on a fix
- Once a fix is available, we may publish a security advisory or release notes

## Secure Configuration Recommendations
- Always set a strong `SECRET_KEY` (do not use defaults)
- Do not commit `.env` files to source control
- Run behind a reverse proxy (optional) if exposed beyond localhost
- Restrict access to the application and API to trusted networks
- Use strong admin credentials and rotate API tokens regularly
