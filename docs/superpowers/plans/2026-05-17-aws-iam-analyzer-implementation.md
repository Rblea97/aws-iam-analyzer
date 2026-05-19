# aws-iam-analyzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-grade Python 3.12 CLI that audits a single AWS account against CIS AWS Foundations Benchmark v5.0.0 IAM and CloudTrail controls, plus clearly labeled enterprise CloudTrail hardening checks.

**Architecture:** Use a layered CLI architecture: `cli/` orchestrates, `scanner/` owns boto3 session/client execution, `checks/` evaluates one control per function, `models/` validates scan data with Pydantic v2, and `reporter/` renders stdout/JSON output. Check discovery is explicit through a static registry for auditability.

**Tech Stack:** Python 3.12, Typer, boto3/botocore, Pydantic v2, Rich, structlog, pytest, moto, pytest-cov, Ruff, mypy, Bandit, pip-audit, Semgrep, Docker, Trivy, hadolint, gitleaks, GitHub Actions, GHCR.

---

## Scope Check

This specification spans several subsystems. Implement it as staged, independently reviewable slices:

1. Repository baseline and project instructions.
2. Core package, models, registry, logging, and reporters.
3. Scanner session/client orchestration.
4. IAM check suite.
5. CloudTrail and CloudTrail hardening check suite.
6. Docker, CI/CD, documentation, and release workflow.

Each slice must produce testable software and pass the configured gates before the next slice begins.

## File Structure

Create or modify these files:

- `.gitignore`: Python, AWS credential files, local visual scratch, test/cache/build artifacts.
- `README.md`: portfolio-grade project overview, quick start, controls, examples, security notes.
- `ARCHITECTURE.md`: public architecture summary for recruiters and open-source readers.
- `LICENSE`: Apache-2.0 license.
- `pyproject.toml`: package metadata, dependencies, tool config.
- `requirements.lock`: exact dependency pins with hashes.
- `src/iam_analyzer/__init__.py`: package metadata.
- `src/iam_analyzer/cli/__init__.py`: CLI package marker.
- `src/iam_analyzer/cli/app.py`: Typer app entry point and eventual `scan` command.
- `src/iam_analyzer/checks/__init__.py`: check package exports.
- `src/iam_analyzer/checks/iam.py`: IAM CIS check functions.
- `src/iam_analyzer/checks/logging.py`: CloudTrail CIS and enterprise hardening checks.
- `src/iam_analyzer/checks/registry.py`: explicit `CheckSpec` list and control metadata.
- `src/iam_analyzer/models/__init__.py`: model exports.
- `src/iam_analyzer/models/finding.py`: `Finding` model.
- `src/iam_analyzer/models/scan.py`: `ScanMetadata`, `ScanSummary`, `ScanResult`.
- `src/iam_analyzer/models/severity.py`: `Severity`, `FindingStatus`.
- `src/iam_analyzer/reporter/__init__.py`: reporter exports.
- `src/iam_analyzer/reporter/json.py`: atomic JSON report writer.
- `src/iam_analyzer/reporter/terminal.py`: Rich stdout renderer.
- `src/iam_analyzer/scanner/__init__.py`: scanner exports.
- `src/iam_analyzer/scanner/errors.py`: custom scanner exceptions.
- `src/iam_analyzer/scanner/orchestrator.py`: check execution and scan aggregation.
- `src/iam_analyzer/scanner/pagination.py`: shared paginator utility.
- `src/iam_analyzer/scanner/session.py`: boto3 session and client factory.
- `src/iam_analyzer/logging_config.py`: structlog stderr configuration.
- `tests/conftest.py`: test credentials and shared fixtures.
- `tests/cli/test_app.py`: Typer CLI tests.
- `tests/checks/test_iam.py`: IAM check tests.
- `tests/checks/test_logging.py`: CloudTrail check tests.
- `tests/models/test_finding.py`: model validation tests.
- `tests/reporter/test_json.py`: JSON writer tests.
- `tests/reporter/test_terminal.py`: Rich renderer tests.
- `tests/scanner/test_pagination.py`: paginator utility tests.
- `tests/scanner/test_session.py`: credential/session tests.
- `docs/scanner-iam-policy.json`: least-privilege scanner IAM policy.
- `docs/controls.md`: strict CIS and enterprise hardening control catalog.
- `Dockerfile`: pinned multi-stage image.
- `.dockerignore`: container build exclusions.
- `.github/pull_request_template.md`: public PR template.
- `.github/dependabot.yml`: weekly Python and GitHub Actions updates.
- `.github/workflows/ci.yml`: 12-stage quality/security pipeline and GHCR publish.
- `AGENTS.md`: project working agreements after design approval.

## Task 1: Repository Baseline

**Files:**
- Create: `.gitignore`
- Create: `README.md`
- Create: `ARCHITECTURE.md`
- Create: `LICENSE`
- Create: `pyproject.toml`
- Create: `src/iam_analyzer/__init__.py`
- Create: `src/iam_analyzer/cli/__init__.py`
- Create: `src/iam_analyzer/cli/app.py`
- Create directories: `src/iam_analyzer/{cli,checks,models,reporter,scanner}`, `tests`, `docs`, `.github/workflows`

- [ ] **Step 1: Create baseline files**

Use Apache-2.0 for `LICENSE`. Keep `README.md` as a stub with the hero line, warning that implementation is in progress, a link to `ARCHITECTURE.md`, and a security note that credentials are never accepted as CLI arguments because boto3's standard credential chain is used. Add `ARCHITECTURE.md` as a public summary of purpose, v1 scope, module boundaries, credential model, and a link to `docs/superpowers/specs/2026-05-17-aws-iam-analyzer-design.md` as an implementation planning artifact.

Add a minimal importable Typer app stub in `src/iam_analyzer/cli/app.py` so the console script in `pyproject.toml` resolves during baseline checks:

```python
app = typer.Typer(
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="AWS IAM and CloudTrail posture analyzer for CIS AWS Foundations Benchmark v5.0.0.",
)
```

Do not add the `scan` command in Task 1.

`.gitignore` must include:

```gitignore
.venv/
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
coverage.xml
dist/
build/
*.egg-info/
.env
.env.*
.aws/
*.pem
*.key
*.json.tmp
.codex-visuals/
.playwright-mcp/
```

- [ ] **Step 2: Define package metadata**

`pyproject.toml` must define:

```toml
[build-system]
requires = ["hatchling>=1.27.0"]
build-backend = "hatchling.build"

[project]
name = "iam-analyzer"
version = "0.1.0"
description = "AWS IAM and CloudTrail posture analyzer for CIS AWS Foundations Benchmark v5.0.0"
readme = "README.md"
requires-python = ">=3.12,<3.13"
license = "Apache-2.0"
authors = [{ name = "Richie Blea" }]
dependencies = [
  "boto3>=1.41.0",
  "typer>=0.25.0",
  "pydantic>=2.13.0",
  "rich>=15.0.0",
  "structlog>=25.0.0",
]

[project.optional-dependencies]
dev = [
  "moto>=5.1.0",
  "pytest>=9.0.0",
  "pytest-cov>=7.0.0",
  "ruff>=0.14.0",
  "mypy>=1.18.0",
  "bandit>=1.8.0",
  "pip-audit>=2.9.0",
]

[project.scripts]
iam-analyzer = "iam_analyzer.cli.app:app"

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--cov=src --cov-report=term-missing --cov-fail-under=85"

[tool.ruff]
target-version = "py312"
line-length = 100
src = ["src", "tests"]

[tool.ruff.lint]
select = ["ALL"]

[tool.mypy]
python_version = "3.12"
strict = true
packages = ["iam_analyzer"]
```

- [ ] **Step 3: Verify baseline tree**

Run:

```powershell
git status --short --branch
```

Expected:

```text
## No commits yet on main
?? .gitignore
?? ARCHITECTURE.md
?? LICENSE
?? README.md
?? docs/
?? pyproject.toml
?? src/
?? tests/
```

- [ ] **Step 4: Commit baseline**

Run:

```powershell
git add .gitignore ARCHITECTURE.md LICENSE README.md docs pyproject.toml src tests
git commit -m "chore: initial repo setup"
```

Expected: commit succeeds on `main`.

## Task 2: Project AGENTS.md

**Files:**
- Create: `AGENTS.md`

- [ ] **Step 1: Create `AGENTS.md`**

The file must include:

- project name and purpose
- CIS v5.0.0 scope
- strict CIS controls and enterprise hardening controls
- branch strategy and commit format
- working commands
- security constraints
- architecture decision records
- known v2.0 extension points

Working commands must be exactly:

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

- [ ] **Step 2: Commit AGENTS.md**

Run:

```powershell
git add AGENTS.md
git commit -m "chore(agents): create AGENTS.md with project context and working agreements"
```

Expected: second commit on `main`.

## Task 3: Docker and CI Skeletons

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`
- Create: `.github/workflows/ci.yml`
- Create: `.github/pull_request_template.md`
- Create: `.github/dependabot.yml`

- [ ] **Step 1: Add Docker scaffold**

`Dockerfile` must use these structural decisions:

```dockerfile
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:<resolved-digest>
FROM ${PYTHON_IMAGE} AS builder
WORKDIR /build
COPY pyproject.toml requirements.lock ./
COPY src/ ./src/
RUN python -m pip install --upgrade pip \
    && python -m pip install --require-hashes -r requirements.lock \
    && python -m pip wheel --no-deps --wheel-dir /wheels .

FROM ${PYTHON_IMAGE} AS runtime
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin appuser
WORKDIR /app
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels
USER appuser
ENTRYPOINT ["iam-analyzer"]
```

Before implementation, replace `<resolved-digest>` with the current digest for `python:3.12-slim-bookworm` and verify with Trivy.

- [ ] **Step 2: Add `.dockerignore`**

Include:

```dockerignore
.git
.github
.venv
.pytest_cache
.mypy_cache
.ruff_cache
.codex-visuals
.playwright-mcp
tests
docs
*.md
*.tmp
.env
.env.*
.aws
```

- [ ] **Step 3: Add CI skeleton**

`.github/workflows/ci.yml` must define jobs or steps for all gates:

```yaml
name: CI

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  packages: write

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: python -m pip install --require-hashes -r requirements.lock
      - name: Ruff
        run: ruff check --select ALL .
      - name: Mypy
        run: mypy --strict src/
      - name: Pytest
        run: pytest --cov=src --cov-report=xml --cov-fail-under=85
      - name: Bandit
        run: bandit -r src/ -ll
      - name: pip-audit
        run: pip-audit
      - name: Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: "p/python p/security-audit"
      - name: Docker build
        run: docker build -t aws-iam-analyzer:${{ github.sha }} .
      - name: Trivy image
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: aws-iam-analyzer:${{ github.sha }}
          severity: HIGH,CRITICAL
          exit-code: "1"
      - name: Trivy config
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: config
          scan-ref: .
          exit-code: "1"
      - name: Hadolint
        uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
```

Add a separate GHCR publish job gated on `github.ref == 'refs/heads/main'`.

- [ ] **Step 4: Commit Docker scaffold**

Run:

```powershell
git add Dockerfile .dockerignore
git commit -m "chore(docker): add Dockerfile and .dockerignore scaffold"
```

- [ ] **Step 5: Commit CI scaffold**

Run:

```powershell
git add .github
git commit -m "ci: add GitHub Actions pipeline skeleton with all stage definitions"
```

## Task 4: Core Models and Registry

**Files:**
- Create: `src/iam_analyzer/models/severity.py`
- Create: `src/iam_analyzer/models/finding.py`
- Create: `src/iam_analyzer/models/scan.py`
- Create: `src/iam_analyzer/checks/registry.py`
- Test: `tests/models/test_finding.py`

- [ ] **Step 1: Create failing model tests**

Tests must assert:

- unknown control IDs are rejected
- missing remediation is rejected
- caller-supplied `evaluated_at` is rejected
- enum fields reject arbitrary strings
- `model_dump(mode="json")` returns JSON-compatible timestamps

Run:

```powershell
pytest tests/models/test_finding.py -v
```

Expected: tests fail because models do not exist.

- [ ] **Step 2: Implement enums and registry metadata**

`severity.py` defines `Severity` and `FindingStatus`.

`registry.py` defines:

- `ControlMetadata`
- `CONTROL_REGISTRY`
- `STRICT_CIS_CONTROL_IDS`
- `ENTERPRISE_HARDENING_CONTROL_IDS`
- `is_known_control_id(control_id: str) -> bool`

The registry must include every control listed in the approved design spec.

- [ ] **Step 3: Implement Finding model**

`Finding` must use Pydantic v2 strict config, default UTC timestamp, registry validation, and rejection of caller-supplied `evaluated_at`.

- [ ] **Step 4: Implement ScanResult models**

`scan.py` defines metadata, summary, and result models matching the required JSON output shape.

- [ ] **Step 5: Run model tests**

Run:

```powershell
pytest tests/models/test_finding.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit models**

Run:

```powershell
git add src/iam_analyzer/models src/iam_analyzer/checks/registry.py tests/models/test_finding.py
git commit -m "feat(models): add validated finding and scan result models"
```

## Task 5: Logging, JSON Reporter, and Terminal Reporter

**Files:**
- Create: `src/iam_analyzer/logging_config.py`
- Create: `src/iam_analyzer/reporter/json.py`
- Create: `src/iam_analyzer/reporter/terminal.py`
- Test: `tests/reporter/test_json.py`
- Test: `tests/reporter/test_terminal.py`

- [ ] **Step 1: Write reporter tests**

JSON tests must assert:

- top-level keys match the spec
- findings serialize through `model_dump(mode="json")`
- write is atomic through temp file replacement
- final mode is `0o600` on POSIX-compatible filesystems

Terminal tests must assert:

- Rich output includes summary counts
- PASS findings are not mixed into the failure table by default
- zero non-passing findings prints `✓ All evaluated controls passed`
- AWS-derived resource names are escaped before markup rendering

- [ ] **Step 2: Run reporter tests to verify failure**

Run:

```powershell
pytest tests/reporter -v
```

Expected: tests fail because reporter modules do not exist.

- [ ] **Step 3: Implement `logging_config.py`**

Configure structlog with:

- ISO 8601 UTC timestamps
- JSON renderer
- log level filtering
- stderr output
- no stdout logs

- [ ] **Step 4: Implement JSON reporter**

Use a same-directory temp file, write JSON with sorted keys and indentation, call `os.replace`, then set `0o600`.

- [ ] **Step 5: Implement terminal reporter**

Use `rich.console.Console`, `rich.panel.Panel`, `rich.table.Table`, and `rich.markup.escape`. Sort non-passing findings by severity and render PASS count in the summary.

- [ ] **Step 6: Run reporter tests**

Run:

```powershell
pytest tests/reporter -v
```

Expected: all reporter tests pass.

- [ ] **Step 7: Commit reporters**

Run:

```powershell
git add src/iam_analyzer/logging_config.py src/iam_analyzer/reporter tests/reporter
git commit -m "feat(reporter): add Rich terminal and atomic JSON reports"
```

## Task 6: Scanner Session and Pagination

**Files:**
- Create: `src/iam_analyzer/scanner/errors.py`
- Create: `src/iam_analyzer/scanner/pagination.py`
- Create: `src/iam_analyzer/scanner/session.py`
- Test: `tests/scanner/test_pagination.py`
- Test: `tests/scanner/test_session.py`

- [ ] **Step 1: Write scanner tests**

Tests must cover:

- profile regex validation happens in CLI before session creation
- missing credentials raises custom `CredentialError`
- STS identity is called once during startup
- client factory applies adaptive retry config
- paginator utility returns empty list for empty pages
- paginator utility preserves items across multiple pages

- [ ] **Step 2: Run scanner tests to verify failure**

Run:

```powershell
pytest tests/scanner -v
```

Expected: tests fail because scanner modules do not exist.

- [ ] **Step 3: Implement scanner exceptions**

Define:

- `CredentialError`
- `ScannerConnectionError`
- `ScannerConfigurationError`

- [ ] **Step 4: Implement paginator utility**

`PaginatorUtil.paginate(client, operation_name, result_key, **kwargs)` must:

- use `client.get_paginator(operation_name)`
- return an empty list when pages have no `result_key`
- concatenate all page values
- catch pagination `ClientError` only when instructed by the check layer

- [ ] **Step 5: Implement session manager**

`AwsSessionManager` must:

- create exactly one `boto3.Session`
- accept `profile` and `region`
- never accept access keys or secret keys
- call `sts.get_caller_identity()`
- expose `client(service_name: str)`
- apply `Config(retries={"max_attempts": 3, "mode": "adaptive"})`

- [ ] **Step 6: Run scanner tests**

Run:

```powershell
pytest tests/scanner -v
```

Expected: all scanner tests pass.

- [ ] **Step 7: Commit scanner foundation**

Run:

```powershell
git add src/iam_analyzer/scanner tests/scanner
git commit -m "feat(scanner): add credential-safe boto3 session management"
```

## Task 7: CLI Entry Point

**Files:**
- Modify: `src/iam_analyzer/cli/app.py`
- Test: `tests/cli/test_app.py`

- [ ] **Step 1: Write CLI tests**

Tests must assert:

- `iam-analyzer scan --help` mentions CIS AWS Foundations Benchmark v5.0.0
- invalid `--profile ../bad` is rejected
- valid `--profile audit_profile-1` is accepted
- `--exit-code` returns non-zero when HIGH or CRITICAL failures exist
- output file path invokes JSON reporter
- verbose flag configures DEBUG logging

- [ ] **Step 2: Run CLI tests to verify failure**

Run:

```powershell
pytest tests/cli/test_app.py -v
```

Expected: tests fail because the CLI module has only the baseline Typer app metadata and no `scan` command yet.

- [ ] **Step 3: Implement Typer app**

Define `app = typer.Typer(no_args_is_help=True, rich_markup_mode="rich")` and command `scan` with the required options. Use `typer.Exit(code=1)` only when `--exit-code` is set and HIGH/CRITICAL failures exist.

- [ ] **Step 4: Run CLI tests**

Run:

```powershell
pytest tests/cli/test_app.py -v
```

Expected: all CLI tests pass.

- [ ] **Step 5: Commit CLI**

Run:

```powershell
git add src/iam_analyzer/cli tests/cli
git commit -m "feat(cli): add scan command and validation"
```

## Task 8: IAM Checks

**Files:**
- Modify: `src/iam_analyzer/checks/iam.py`
- Modify: `src/iam_analyzer/checks/registry.py`
- Test: `tests/checks/test_iam.py`

- [ ] **Step 1: Write IAM check tests**

For each implemented IAM control, write three tests:

- compliant state returns PASS
- non-compliant state returns FAIL
- permission denied returns MANUAL_CHECK

Use `moto.mock_aws` where the API is supported. Use botocore `Stubber` for IAM operations moto does not fully emulate.

- [ ] **Step 2: Run IAM tests to verify failure**

Run:

```powershell
pytest tests/checks/test_iam.py -v
```

Expected: tests fail because IAM checks are incomplete.

- [ ] **Step 3: Implement IAM checks**

Implement one function per Task 8 IAM control using CIS AWS Foundations Benchmark v5.0.0 numbering validated during implementation:

- `check_cis_1_3_root_access_key_absent`
- `check_cis_1_5_root_hardware_mfa_enabled`
- `check_cis_1_7_password_min_length_14`
- `check_cis_1_8_password_reuse_prevention`
- `check_cis_1_9_console_users_have_mfa`
- `check_cis_1_11_unused_credentials_removed`
- `check_cis_1_13_access_keys_rotated`
- `check_cis_1_14_no_direct_user_policy_attachments`
- `check_cis_1_15_no_admin_wildcard_policies`
- `check_cis_1_16_support_role_exists`
- `check_cis_1_21_cloudshell_full_access_restricted`

Do not reintroduce stale CIS v3.0.0/v1.4.0 numbering for v5.0.0 controls.

- [ ] **Step 4: Run IAM tests**

Run:

```powershell
pytest tests/checks/test_iam.py -v
```

Expected: all IAM check tests pass.

- [ ] **Step 5: Commit IAM checks**

Run:

```powershell
git add src/iam_analyzer/checks/iam.py src/iam_analyzer/checks/registry.py tests/checks/test_iam.py
git commit -m "feat(checks): implement IAM CIS control checks"
```

## Task 9: CloudTrail and Enterprise Hardening Checks

**Files:**
- Modify: `src/iam_analyzer/checks/logging.py`
- Modify: `src/iam_analyzer/checks/registry.py`
- Test: `tests/checks/test_logging.py`

- [ ] **Step 1: Write CloudTrail tests**

For each control, write compliant, non-compliant, and permission-denied tests:

- `CIS-3.1`
- `CIS-3.2`
- `CIS-3.4`
- `CIS-3.5`
- `EHC-CT-1`
- `EHC-CT-2`
- `EHC-CT-3`

Use botocore `Stubber` when moto lacks exact CloudTrail/S3 behavior.

- [ ] **Step 2: Run CloudTrail tests to verify failure**

Run:

```powershell
pytest tests/checks/test_logging.py -v
```

Expected: tests fail because logging checks are incomplete.

- [ ] **Step 3: Implement CloudTrail checks**

Implement:

- `check_cis_3_1_cloudtrail_enabled_all_regions`
- `check_cis_3_2_log_file_validation_enabled`
- `check_cis_3_4_cloudtrail_bucket_access_logging_enabled`
- `check_cis_3_5_cloudtrail_kms_encryption_enabled`
- `check_ehc_ct_1_cloudwatch_logs_integration`
- `check_ehc_ct_2_cloudtrail_bucket_not_public`
- `check_ehc_ct_3_management_event_coverage`

Use CloudTrail client for trail metadata and S3 client for bucket checks. Return `MANUAL_CHECK` when S3 bucket evidence cannot be retrieved.

- [ ] **Step 4: Run CloudTrail tests**

Run:

```powershell
pytest tests/checks/test_logging.py -v
```

Expected: all CloudTrail tests pass.

- [ ] **Step 5: Commit CloudTrail checks**

Run:

```powershell
git add src/iam_analyzer/checks/logging.py src/iam_analyzer/checks/registry.py tests/checks/test_logging.py
git commit -m "feat(checks): implement CloudTrail and hardening checks"
```

## Task 10: Orchestrator and End-to-End Scan Assembly

**Files:**
- Create: `src/iam_analyzer/scanner/orchestrator.py`
- Modify: `src/iam_analyzer/cli/app.py`
- Test: `tests/scanner/test_orchestrator.py`
- Test: `tests/cli/test_app.py`

- [x] **Step 1: Write orchestrator tests**

Tests must assert:

- orchestrator executes every enabled `CheckSpec`
- clients are reused by service name
- controls evaluated list matches registry order
- summary counts include PASS and severity counts
- scan duration is populated
- completion log includes account ID, region, controls evaluated, summary, and duration

- [x] **Step 2: Run orchestrator tests to verify failure**

Run:

```powershell
pytest tests/scanner/test_orchestrator.py -v
```

Expected: tests fail because orchestrator does not exist.

- [x] **Step 3: Implement orchestrator**

Implement `run_scan(session_manager, region) -> ScanResult`. It creates needed service clients once, passes clients into check functions, aggregates findings, and logs one scan completion event.

- [x] **Step 4: Wire CLI to orchestrator**

The CLI calls the session manager, orchestrator, terminal reporter, optional JSON reporter, and exit-code logic.

- [x] **Step 5: Run orchestrator and CLI tests**

Run:

```powershell
pytest tests/scanner/test_orchestrator.py tests/cli/test_app.py -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit orchestrator**

Run:

```powershell
git add src/iam_analyzer/scanner/orchestrator.py src/iam_analyzer/cli/app.py tests/scanner/test_orchestrator.py tests/cli/test_app.py
git commit -m "feat(scanner): orchestrate registry-based account scans"
```

## Task 11: Documentation and Scanner IAM Policy

**Files:**
- Modify: `README.md`
- Create: `docs/scanner-iam-policy.json`
- Create: `docs/controls.md`

- [x] **Step 1: Write scanner IAM policy**

`docs/scanner-iam-policy.json` must include only read/list/get permissions required by implemented checks:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IamAnalyzerReadOnlyAudit",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "iam:GenerateCredentialReport",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListAccessKeys",
        "iam:ListAttachedGroupPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroups",
        "iam:ListGroupsForUser",
        "iam:ListGroupPolicies",
        "iam:ListMFADevices",
        "iam:ListPolicies",
        "iam:ListRoles",
        "iam:ListRolePolicies",
        "iam:ListUsers",
        "iam:ListUserPolicies",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrailStatus",
        "s3:GetBucketAcl",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

- [x] **Step 2: Write controls documentation**

`docs/controls.md` must list each strict CIS control and each enterprise hardening control with:

- ID
- title
- evidence APIs
- severity
- remediation summary
- whether it is strict CIS or enterprise hardening

- [x] **Step 3: Update README**

README must include:

- hero line
- demo status section
- tech stack with reasons
- key features
- quick start local
- quick start Docker
- scanner IAM policy reference
- controls in scope
- example terminal output
- example JSON output
- threat model summary
- architecture summary
- contribution guide for new checks
- license

- [x] **Step 4: Commit docs**

Run:

```powershell
git add README.md docs/scanner-iam-policy.json docs/controls.md
git commit -m "docs: document scanner usage controls and IAM policy"
```

## Task 12: Dependency Lock, Docker Validation, and Full Gates

**Files:**
- Create: `requirements.lock`
- Modify: `Dockerfile`
- Modify: `pyproject.toml`

- [ ] **Step 1: Generate dependency lock with hashes**

Use a deterministic lock generation command available in the environment. Preferred command:

```powershell
uv pip compile pyproject.toml --extra dev --generate-hashes -o requirements.lock
```

If `uv` is unavailable, install and use `pip-tools` in the project virtual environment:

```powershell
python -m pip install pip-tools
python -m piptools compile pyproject.toml --extra dev --generate-hashes -o requirements.lock
```

Expected: `requirements.lock` contains exact versions and hashes.

- [ ] **Step 2: Resolve Docker base digest**

Resolve the current digest for `python:3.12-slim-bookworm`, replace `<resolved-digest>` in `Dockerfile`, and build:

```powershell
docker build -t aws-iam-analyzer .
```

Expected: image builds successfully.

- [ ] **Step 3: Run all local gates**

Run:

```powershell
ruff check --select ALL .
mypy --strict src/
pytest --cov=src --cov-report=term-missing
bandit -r src/ -ll
pip-audit
semgrep --config p/python --config p/security-audit src/
docker build -t aws-iam-analyzer .
trivy image --exit-code 1 --severity HIGH,CRITICAL aws-iam-analyzer
trivy config --exit-code 1 .
hadolint Dockerfile
gitleaks detect --source .
```

Expected:

```text
ruff: 0 findings
mypy: 0 errors
pytest: coverage >= 85%
bandit: 0 MEDIUM/HIGH/CRITICAL findings
pip-audit: 0 known CVEs
semgrep: 0 findings
docker build: success
trivy image: 0 HIGH/CRITICAL CVEs
trivy config: 0 misconfigurations
hadolint: 0 findings
gitleaks: 0 secrets detected
```

- [ ] **Step 4: Commit dependency and Docker finalization**

Run:

```powershell
git add requirements.lock Dockerfile pyproject.toml
git commit -m "build(deps): lock dependencies and finalize container build"
```

## Task 13: GitHub Repository and Branch Protection

**Files:**
- Remote GitHub repository

- [ ] **Step 1: Create GitHub repository**

Use GitHub MCP to create:

```text
Rblea97/aws-iam-analyzer
```

Settings:

- Apache-2.0 license
- public repository unless the owner chooses private
- README from local repo, not generated by GitHub

- [ ] **Step 2: Push `main`**

Run:

```powershell
git remote add origin https://github.com/Rblea97/aws-iam-analyzer.git
git push -u origin main
```

Expected: remote `main` receives the baseline commits.

- [ ] **Step 3: Configure branch protection**

Use GitHub MCP where supported; use GitHub UI or GitHub REST API for settings not exposed by MCP.

Required protection:

- require pull request before merge
- require 1 approval
- require all CI checks
- disallow force pushes
- disallow direct pushes

- [ ] **Step 4: Verify CI**

Confirm all GitHub Actions checks pass on `main`.

## Self-Review

### Spec Coverage

Covered:

- module boundaries
- Finding and ScanResult models
- CIS and enterprise hardening control scope
- check function contract
- credential-safe boto3 session management
- adaptive retry config
- Typer CLI
- Rich terminal output
- atomic JSON output
- Docker design
- CI/CD gate map
- scanner IAM policy
- threat-model mitigations
- GitHub repository workflow

Known implementation dependency:

- Candidate IAM control IDs must be validated against an authoritative CIS v5.0.0 source before strict CIS implementation.

### Placeholder Scan

The plan avoids open-ended implementation gaps. The Docker digest must be resolved during Task 12 because the digest is external and time-sensitive.

### Type Consistency

The planned modules consistently use:

- `Finding`
- `ScanResult`
- `Severity`
- `FindingStatus`
- `PaginatorUtil`
- `AwsSessionManager`
- `CheckSpec`

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-17-aws-iam-analyzer-implementation.md`. Two execution options:

1. **Subagent-Driven (recommended)** - dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** - execute tasks in this session using executing-plans, batch execution with checkpoints.

Recommended choice: Subagent-Driven, because the project has independent slices for models, scanner, checks, reporters, Docker, and docs.
