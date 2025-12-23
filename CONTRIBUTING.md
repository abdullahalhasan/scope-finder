# Contributing to Scope Finder

Thanks for your interest in contributing!

## Ways to Contribute
- Bug reports
- Feature requests
- Documentation improvements
- Code contributions (PRs)
- Test coverage and QA

## Development Setup (Local)
1. Fork and clone the repo
2. Create a virtual environment:
   ```bash
   python -m venv .venv
   ```
3. Activate it:
    
    Windows: 
    ```bash 
    .venv\Scripts\activate
    ```

    Linux/macOS: 
    ```bash 
    source .venv/bin/activate
    ```

4. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

5. Run:
    ```bash
    python app.py
    ```

## Docker Setup
    ```bash
    docker compose up -d --build

## Branching / PR Guidelines
- Create a feature branch:
    ```bash
    git checkout -b feature/my-change
- Keep PRs focused and small when possible

- Include screenshots for UI changes

- Update docs if behavior changes

## Code Style

- Prefer readable, explicit code

- Add comments where logic is non-obvious

- Avoid breaking backward compatibility unless necessary

## Security Issues

- Please do not file public issues for security vulnerabilities.

- See `SECURITY.md`.

