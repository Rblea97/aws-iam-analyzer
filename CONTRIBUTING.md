# Contributing

Thanks for taking a look at `aws-iam-analyzer`. This project is intentionally small and security-focused, so contributions should keep the scanner easy to audit, test, and run with read-only AWS access.

## Local Setup

Use Python 3.12.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e .
```

Confirm the CLI loads:

```powershell
iam-analyzer --help
iam-analyzer scan --help
```

## Development Commands

```powershell
ruff check --select ALL .
mypy --strict src/
pytest --cov=src --cov-report=term-missing
bandit -r src/ -ll
pip-audit
docker build -t aws-iam-analyzer .
```

CI also runs Semgrep, Trivy image scanning, Trivy config scanning, Hadolint, and Gitleaks.

## Adding A Check

1. Confirm the CIS control ID, title, audit procedure, evidence APIs, and remediation language.
2. Add or update metadata in `src/iam_analyzer/checks/registry.py`.
3. Write tests for compliant, failing, and permission-denied or edge-case states.
4. Implement one check function in the relevant `checks` module.
5. Add the function to `src/iam_analyzer/checks/catalog.py`.
6. Update `docs/controls.md`.
7. Update `docs/scanner-iam-policy.json` if the check requires new read-only AWS APIs.

Check functions must accept pre-initialized boto3 clients, return `Finding` objects, and avoid logging or rendering output.

## Security Rules

- Never accept raw AWS credentials as CLI arguments.
- Never log raw AWS credential values, credential reports, or `.env` values.
- Treat AWS resource names as untrusted strings.
- Keep JSON reports permission-restricted because they can reveal account structure.
- Keep tests offline; do not add tests that call real AWS APIs.

## Pull Request Checklist

- [ ] Tests cover new behavior or documentation-only scope is clear.
- [ ] `ruff check --select ALL .` passes.
- [ ] `mypy --strict src/` passes.
- [ ] `pytest --cov=src --cov-report=term-missing` passes.
- [ ] `bandit -r src/ -ll` passes.
- [ ] `pip-audit` passes.
- [ ] Docker image builds.
- [ ] No credential material, account-specific output, or private local files are included.
