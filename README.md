# Scope Finder

Scope Finder is a lightweight asset discovery and port enumeration web app built for security teams, lab environments, and SOC workflows. It provides a clean UI to scan targets (single IP, CIDR, range), view results, export PDF reports, manage users (RBAC), and expose an API for SIEM/SOAR integrations.

> **Responsible Use:** Use Scope Finder only on networks and assets you own or have explicit permission to test.

---

## Features (Extensive)

### Scanning & Enumeration
- Scan targets using:
  - Single IP (e.g., `192.168.1.10`)
  - CIDR (e.g., `192.168.1.0/24`)
  - Range (e.g., `192.168.1.10-20`)
- Port range selection (`min_port`, `max_port`)
- Exclude targets from scan using:
  - IPs, CIDR blocks, and ranges (admin-managed saved exclude lists + ad-hoc excludes)
- Basic banner/service identification (best-effort)
- “Stop Scan” support with partial-result returns (cancelled scan shows partial findings)
- Scan progress endpoint for UI polling (phase/message/time style status)

### Reporting & Audit
- Scan history stored in SQLite
- PDF report download per scan (UI)
- Detailed audit log for key actions (admin)
- Clear “Cancelled” marker for interrupted scans

### Admin & RBAC
- Login + session-based UI access
- Role-based access control:
  - Admin: manage users, IP lists, licenses, API token, audit log
  - User: run scans, view history
- Admin-managed saved lists:
  - Saved Target Ranges
  - Saved Exclude Lists

### API / Integration
- API endpoints for:
  - Start scan
  - Stop scan
  - List scans
  - Get scan detail (JSON results)
- Authentication options:
  - Browser session (web UI)
  - SIEM API token (admin-managed) via:
    - `X-API-Token: <token>`
    - `Authorization: Bearer <token>`
- Designed for SIEM automation workflows (e.g., Wazuh integration scripts / active responses)

### Security & Operational Controls
- API token stored as a hash (token shown once on creation)
- Session idle timeout support (configured in app)
- License gate support for “Community Edition” trials (optional, OSS-friendly)
- Safe defaults and clear warnings for authorized use only

---

## Quick Start (Docker)

### Requirements
- Docker Desktop (Windows/macOS) or Docker Engine (Linux)
- Docker Compose

### Setup
1. Clone the repo:
   ```bash
   git clone https://github.com/<your-username>/scope-finder.git
   cd scope-finder
   ```

2. Create env file:
   ```bash
   cp .env.example .env
   ```

### Edit .env and set a strong secret:
   SECRET_KEY=long-random-secret

3. Start the app:
   ```bash
   docker compose up -d --build
   ```
4. Open:
   <http://localhost:5000>

## Persistence (SQLite)

### The Docker compose file mounts ./data into the container so your database persists:

- ./data/scope_finder.db (or whatever DB_PATH is set to)


## Run Locally (without Docker)
### Requirements

- Python 3.10+ recommended (3.12 works well)

```bash
   python -m venv .venv
    # Windows:
    .venv\Scripts\activate
    # Linux/macOS:
    source .venv/bin/activate

    pip install -r requirements.txt
    set SECRET_KEY=dev-secret  # Windows PowerShell: $env:SECRET_KEY="dev-secret"
    python app.py
```
- Open:
  <http://localhost:5000>

## Configuration

## Environment variables:

- SECRET_KEY (required): Flask session secret

- DB_PATH (optional): SQLite file path (default is internal app default)

## API

- See the in-app API Docs page:

- /api-docs

Example:
```bash
   curl -s -X POST "http://localhost:5000/api/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Token: <your_token_here>" \
  -d '{"target":"192.168.1.0/24","min_port":1,"max_port":1024}'
```

## Security Policy

### Please review:

- `SECURITY.md` for vulnerability reporting

- `DISCLAIMER.md` for authorized-use requirements

## Contributing

- See `CONTRIBUTING.md`.

## License

- Apache License 2.0 — see `LICENSE`.