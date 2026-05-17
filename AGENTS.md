# AGENTS.md

## Project Context

**Project:** `aws-iam-analyzer`

**Purpose:** Build a Python 3.12 CLI that audits a single AWS account for IAM and CloudTrail posture against CIS AWS Foundations Benchmark v5.0.0 controls, with clearly labeled enterprise CloudTrail hardening checks.

**CIS scope for v1.0:** strict CIS AWS Foundations Benchmark v5.0.0 coverage is limited to the IAM and CloudTrail controls listed below. Candidate IAM controls are tracked separately until their IDs and audit procedures are validated against the authoritative benchmark text.

## Tech Stack

- Python `>=3.12,<3.13`
- Runtime dependencies from `pyproject.toml`: `boto3>=1.41.0`, `typer>=0.25.0`, `pydantic>=2.13.0`, `rich>=15.0.0`, `structlog>=25.0.0`
- Development dependencies from `pyproject.toml`: `moto>=5.1.0`, `pytest>=9.0.0`, `pytest-cov>=7.0.0`, `ruff>=0.14.0`, `mypy>=1.18.0`, `bandit>=1.8.0`, `pip-audit>=2.9.0`
- Docker runtime target: non-root multi-stage image for `iam-analyzer`

Exact transitive dependency pins and hashes are locked in `requirements.lock` during the dependency-lock task. Do not invent or hand-write hashes.

## Working Commands

```text
Test:      pytest --cov=src --cov-report=term-missing
Lint:      ruff check --select ALL .
Type:      mypy --strict src/
SAST:      bandit -r src/ -ll
Audit:     pip-audit
Build:     docker build -t aws-iam-analyzer .
Run local: iam-analyzer scan --profile <profile>
Run Docker: docker run --rm -e AWS_PROFILE=<profile> -v ~/.aws:/home/appuser/.aws:ro aws-iam-analyzer scan
```

## Branch and Commit Rules

- Use GitHub Flow.
- `main` is always deployable.
- Task 1 through Task 4 are the approved baseline commits on `main`; never commit directly to `main` after the first four baseline commits.
- After the baseline commits, use short-lived branches with one of these prefixes: `feat/`, `fix/`, `chore/`, `docs/`, `ci/`, `security/`, `refactor/`, `test/`.
- Use conventional commits in this format: `<type>(<scope>): <short description in imperative mood>`.
- Approved scopes: `cli`, `checks`, `models`, `reporter`, `scanner`, `ci`, `docker`, `deps`, `docs`, `agents`, `tests`, `security`.

## Security Constraints

- Never accept credentials as CLI arguments.
- Never log credential values; log ARNs and account IDs only.
- Output files must be written with `0o600` permissions.
- All boto3 calls must use adaptive retry configuration.
- No check function initializes its own boto3 client.
- Rich output must escape untrusted AWS resource names.
- Use boto3's standard credential chain only.
- Keep AWS credential files and local secrets out of the repository.

## Controls in Scope

**Strict CIS v1.0 controls:**

- `CIS-1.5`
- `CIS-1.6`
- `CIS-1.7`
- `CIS-1.10`
- `CIS-1.14`
- `CIS-1.15`
- `CIS-1.16`
- `CIS-1.19`
- `CIS-1.21`
- `CIS-3.1`
- `CIS-3.2`
- `CIS-3.4`

**Candidate IAM controls:**

- `CIS-1.8-CANDIDATE`
- `CIS-1.11-CANDIDATE`
- `CIS-1.12-CANDIDATE`

Candidate IAM controls require authoritative CIS AWS Foundations Benchmark v5.0.0 validation before strict CIS implementation.

**Enterprise hardening controls:**

- `EHC-CT-1`
- `EHC-CT-2`
- `EHC-CT-3`

Enterprise hardening controls are useful CloudTrail posture checks, but they are not strict CIS findings.

## Architecture Decision Records

- Use an explicit check registry for auditability and predictable control ordering.
- Keep v1.0 single-account only.
- Use the boto3 standard credential chain only; do not accept raw access keys.
- Use a Pydantic v2 strict `Finding` model for validation and JSON-safe serialization.
- Separate Rich stdout reporting from structlog stderr logging.
- Write JSON reports atomically.
- Use a Docker non-root multi-stage runtime.

## Known Limitations and v2.0 Extension Points

- Multi-account `AssumeRole` scanning is out of scope for v1.0.
- Networking checks are out of scope for v1.0.
- Broader S3 checks are out of scope for v1.0.
- Plugin discovery should wait until the core check interface stabilizes.

## Working Agreements

- Keep production code changes out of documentation-only tasks unless required.
- Add tests beside behavior changes.
- Update public docs when setup, usage, architecture, or security posture changes.
- Keep local scratch folders and generated QA artifacts out of commits.
- Review diffs before committing and do not include secrets.
