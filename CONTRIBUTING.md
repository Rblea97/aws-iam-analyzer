# Contributing

`aws-iam-analyzer` is intentionally small and security-focused. Contributions need to keep the scanner easy to audit, test, and run with read-only AWS access.

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

The workflow config also includes Semgrep, Trivy image scanning, Trivy config scanning, Hadolint, and Gitleaks. Local availability of those tools is environment-dependent unless installed separately.

## Adding A Check

1. Confirm the CIS control ID, title, audit procedure, evidence APIs, and remediation language.
2. Add or update metadata in `src/iam_analyzer/checks/registry.py`.
3. Write tests for compliant, failing, permission-denied, and malformed-evidence states.
4. Implement evidence collection and evaluation in the relevant checks module.
5. Add the function to `src/iam_analyzer/checks/catalog.py`.
6. Update `docs/controls.md` and `docs/control-traceability.md`.
7. Update `docs/scanner-iam-policy.json` if the check requires new read-only AWS APIs.

Check functions accept pre-initialized boto3 clients, return `Finding` objects, and avoid logging or rendering output.

## Security Rules

- Never accept raw AWS credentials as CLI arguments.
- Never log raw AWS credential values, credential reports, or `.env` values.
- Treat AWS resource names as untrusted strings.
- Keep JSON reports permission-restricted because they can reveal account structure.
- Keep tests offline; do not add tests that call real AWS APIs.
- Mark external repository state as `UNVERIFIED` unless there is evidence in repository files.

## Pull Request Checklist

- [ ] Tests cover new behavior, or documentation-only scope is stated.
- [ ] `ruff check --select ALL .` passes locally.
- [ ] `mypy --strict src/` passes locally.
- [ ] `pytest --cov=src --cov-report=term-missing` passes locally.
- [ ] `bandit -r src/ -ll` passes locally.
- [ ] `pip-audit` passes locally.
- [ ] Docker image builds locally when Docker is available.
- [ ] No credential material, account-specific output, or private local files are included.
