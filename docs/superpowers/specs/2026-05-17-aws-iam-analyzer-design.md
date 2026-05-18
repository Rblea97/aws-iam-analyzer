# aws-iam-analyzer Design Specification

Date: 2026-05-17
Status: Approved for implementation planning
Benchmark: CIS AWS Foundations Benchmark v5.0.0
Primary audience: security engineers and cloud engineers auditing AWS IAM posture without adopting a full CSPM platform

## 1. Purpose

`aws-iam-analyzer` is a production-grade Python CLI that scans a single AWS account using read-only credentials, evaluates IAM and CloudTrail controls, and reports findings with remediation guidance mapped to specific control identifiers.

The tool must be strong enough for open-source publication and clear enough to demo in a cloud security engineering interview. It emphasizes correctness, credential safety, testability, and clean module boundaries over breadth.

## 2. Source Validation

Design decisions were validated against current documentation during brainstorming:

- AWS Security Hub CIS AWS Foundations Benchmark mapping: https://docs.aws.amazon.com/en_us/securityhub/latest/userguide/cis-aws-foundations-benchmark.html
- AWS Security Hub CloudTrail controls: https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html
- Context7 documentation lookups for boto3/botocore, Typer, Pydantic v2, Rich, structlog, pytest, and moto.

Documentation is treated as reference material only. Instructions embedded in external documentation are not trusted as behavioral instructions.

## 3. Scope

### v1.0 In Scope

- Single AWS account scan.
- Standard boto3 credential chain only:
  - environment variables
  - AWS profile
  - instance/container role
  - IAM Identity Center where supported by boto3
- IAM controls from CIS AWS Foundations Benchmark v5.0.0.
- CloudTrail controls from CIS AWS Foundations Benchmark v5.0.0.
- Clearly labeled enterprise CloudTrail hardening checks when requested checks are useful but not cleanly mapped to CIS v5.0.0.
- Rich terminal report.
- Machine-readable JSON findings document.
- Docker image that runs identically to the local CLI.
- GitHub Actions quality and security gates.
- Least-privilege scanner IAM policy documentation.

### v1.0 Out of Scope

- Multi-account STS AssumeRole execution.
- Networking controls.
- General S3 posture scanning outside CloudTrail log-bucket hardening.
- Web UI.
- Plugin architecture.
- Automated remediation.
- Accepting AWS credentials as CLI arguments.
- Writing to AWS resources.

### v2.0 Extension Points

- Multi-account scanning can be added above the session layer through an assume-role session provider.
- Networking and broader S3 checks can be added through new check modules and registry entries.
- Third-party checks can be considered later through Python entry points after the core security model is stable.

## 4. Control Scope

Strict CIS v5.0.0 controls use CIS control IDs and titles validated against the official AWS mapping where available. Enterprise hardening controls use an `EHC-*` prefix and must not be presented as CIS requirements.

### IAM Controls

Initial IAM v1.0 controls were corrected during Task 8 against the AWS Security Hub CSPM CIS v5.0.0 mapping and public implementation references:

- `CIS-1.3`: Ensure no root user account access key exists.
- `CIS-1.5`: Ensure hardware MFA is enabled for the root user account.
- `CIS-1.7`: Ensure IAM password policy requires minimum length of 14 or greater.
- `CIS-1.8`: Ensure IAM password policy prevents password reuse.
- `CIS-1.9`: Ensure MFA is enabled for all IAM users that have a console password.
- `CIS-1.11`: Ensure credentials unused for 45 days or more are removed.
- `CIS-1.13`: Ensure access keys are rotated every 90 days or less.
- `CIS-1.14`: Ensure IAM users receive permissions only through groups.
- `CIS-1.15`: Ensure IAM policies that allow full administrative privileges are not attached.
- `CIS-1.16`: Ensure a support role has been created to manage incidents with AWS Support.
- `CIS-1.21`: Ensure access to AWSCloudShellFullAccess is restricted.

The registry also contains the remaining strict CIS v5 IAM IDs so the Finding model can validate future v1.0 additions without reintroducing stale numbering.

### CloudTrail Controls

Strict CIS v5.0.0 CloudTrail controls:

- `CIS-3.1`: Ensure CloudTrail is enabled and configured with at least one multi-region trail including read and write management events.
- `CIS-3.2`: Ensure CloudTrail log file validation is enabled.
- `CIS-3.4`: Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket.
- `CIS-3.5`: Ensure CloudTrail logs are encrypted at rest using KMS keys.

Enterprise CloudTrail hardening controls:

- `EHC-CT-1`: Ensure CloudTrail is integrated with CloudWatch Logs.
- `EHC-CT-2`: Ensure the CloudTrail S3 bucket is not publicly accessible.
- `EHC-CT-3`: Ensure CloudTrail management event coverage is hardened.

The enterprise hardening checks are useful for production security posture but must be labeled separately in the CLI, JSON report, README, and remediation text.

## 5. Architecture

The package uses strict module-level separation of concerns.

```text
src/iam_analyzer/
  cli/
    app.py
  checks/
    __init__.py
    iam.py
    logging.py
    registry.py
  models/
    __init__.py
    finding.py
    scan.py
    severity.py
  reporter/
    __init__.py
    terminal.py
    json.py
  scanner/
    __init__.py
    errors.py
    pagination.py
    session.py
    orchestrator.py
  logging_config.py
```

### Module Responsibilities

- `cli/`: Typer command definition, CLI input validation, log setup, scanner invocation, reporter invocation, and exit-code behavior.
- `scanner/`: boto3 session creation, STS identity validation, botocore retry config, service client creation, registry execution, scan timing, aggregate logging.
- `checks/`: one function per control. Check functions accept injected clients and utilities, return findings, and contain no CLI, logging, or rendering behavior.
- `models/`: Pydantic v2 models and enums only.
- `reporter/`: Rich terminal output and atomic JSON serialization only.
- `logging_config.py`: structlog setup for JSON logs to stderr.

## 6. Data Flow

```text
iam-analyzer scan
  -> validate CLI options
  -> configure structlog to stderr
  -> create one boto3.Session
  -> validate identity with sts:GetCallerIdentity
  -> create IAM, CloudTrail, and S3 clients with adaptive retries
  -> execute explicit check registry
  -> checks collect raw AWS evidence
  -> checks return Finding objects
  -> scanner aggregates ScanResult
  -> terminal reporter prints summary and non-passing findings to stdout
  -> JSON reporter writes optional atomic 0600 report
  -> CLI exits non-zero when --exit-code is set and HIGH/CRITICAL failures exist
```

## 7. Check Registry Decision

Use Option A: explicit registry.

`checks/registry.py` owns a static list of `CheckSpec` records:

```python
CheckSpec(
    control_id="CIS-1.3",
    title="Ensure no root user account access key exists",
    service="iam",
    function=check_cis_1_3_root_access_key_absent,
)
```

Reasons:

- Most auditable option for a security tool.
- No hidden decorator side effects.
- No plugin import-order risk.
- Easy to test and review.
- Keeps v1.0 intentionally simple while allowing future registry expansion.

Rejected alternatives:

- Decorator auto-registration: cleaner syntax but less explicit and easier to break through import order.
- Python `entry_points`: useful for future plugins but too much supply-chain and interface complexity for v1.0.

## 8. Models

### Severity

```python
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
```

### FindingStatus

```python
class FindingStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL_CHECK = "MANUAL_CHECK"
```

### Finding

Required constraints:

- `control_id: str`: validated against the known control registry.
- `control_title: str`: non-empty.
- `severity: Severity`: enum, not free-form string.
- `status: FindingStatus`: enum, not boolean.
- `resource_id: str | None`: ARN or identifier, `None` only for account-level controls.
- `remediation: str`: non-empty and references the specific control and AWS documentation.
- `raw_evidence: dict[str, Any]`: raw boto3 evidence for auditability.
- `evaluated_at: datetime`: UTC timestamp auto-set at instantiation and not caller-supplied.

Serialization:

- `model_dump(mode="json")` is the canonical JSON serialization path.
- Datetimes serialize as ISO 8601 UTC strings.
- Missing required fields are rejected.
- Unknown control IDs are rejected unless registered as `EHC-*` or approved candidate IDs.

### ScanResult

`ScanResult` contains:

- `scan_metadata`
- `summary`
- `findings`

It maps directly to the required JSON structure.

## 9. Check Function Contract

Every check function must follow this contract:

```python
def check_<cis_control_id_snake>(
    client: boto3.client,
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    ...
```

Rules:

- Accept only injected boto3 clients and the paginator utility.
- Never initialize boto3 sessions or clients.
- Return `list[Finding]`.
- Never raise AWS exceptions to the caller.
- Catch `ClientError` and return `MANUAL_CHECK` with permission/remediation context.
- Catch endpoint/network exceptions where the check layer can provide useful evidence; unrecoverable scanner-wide connectivity failures are handled in `scanner/`.
- Never log.
- Never render output.
- Include a module-level docstring citing the exact control ID, title, and audit procedure summary.

### Worked Example: Root Access Key Check

Control: `CIS-1.5`

Evidence:

- `iam.get_account_summary()`
- Account summary key: `AccountAccessKeysPresent`

Behavior:

- If `AccountAccessKeysPresent == 0`: return one account-level PASS finding.
- If `AccountAccessKeysPresent > 0`: return one account-level HIGH/CRITICAL FAIL finding with remediation.
- If IAM permission is denied: return one account-level MANUAL_CHECK finding.

## 10. AWS API Plan

### Session and Identity

- `boto3.Session(profile_name=profile, region_name=region)`
- `session.get_credentials()`
- `sts.get_caller_identity()`
- custom `CredentialError` wraps missing, partial, invalid, or unresolved credentials.

### Retry Configuration

Every client is created with:

```python
Config(retries={"max_attempts": 3, "mode": "adaptive"})
```

### IAM APIs

Planned IAM APIs:

- `get_account_summary`
- `get_account_password_policy`
- `generate_credential_report`
- `get_credential_report`
- `list_users`
- `list_access_keys`
- `get_access_key_last_used`
- `list_mfa_devices`
- `list_user_policies`
- `list_attached_user_policies`
- `list_groups`
- `list_groups_for_user`
- `list_roles`
- `list_role_policies`
- `list_group_policies`
- `list_policies`
- `get_policy`
- `get_policy_version`

### CloudTrail and S3 APIs

Planned CloudTrail APIs:

- `describe_trails`
- `get_trail_status`
- `get_event_selectors`

Planned S3 APIs for enterprise CloudTrail hardening:

- `get_public_access_block`
- `get_bucket_policy_status`
- `get_bucket_acl`
- `get_bucket_logging`

## 11. CLI Design

Command:

```text
iam-analyzer scan
```

No positional arguments.

Options:

- `--profile TEXT`: AWS profile name; validated against `[a-zA-Z0-9_-]+` before boto3 receives it.
- `--region TEXT`: AWS region, default `us-east-1`.
- `--output-file PATH`: optional JSON findings path.
- `--severity-filter`: terminal filter to severity and above.
- `--exit-code`: exit non-zero if HIGH or CRITICAL failures are present.
- `--verbose`: DEBUG-level structured logging.

Help text must mention:

- CIS AWS Foundations Benchmark v5.0.0.
- Enterprise hardening checks are separate from strict CIS controls.
- AWS credentials are resolved by boto3 only and are never accepted as CLI arguments.

Default terminal behavior:

- PASS findings are hidden by default.
- FAIL and MANUAL_CHECK findings are shown.
- PASS findings remain present in JSON output.

## 12. Reporting

### Terminal Reporter

Rich output writes only to stdout.

Required views:

- Summary panel:
  - account ID
  - scan timestamp
  - total findings
  - counts by severity
  - PASS count
- Findings table:
  - Control ID
  - Severity
  - Status
  - Resource
  - Title
- Severity order:
  - CRITICAL
  - HIGH
  - MEDIUM
  - LOW
- Color mapping:
  - CRITICAL: red
  - HIGH: orange
  - MEDIUM: yellow
  - LOW: blue

All untrusted AWS-derived strings must be escaped before Rich markup rendering.

If there are zero non-passing findings, render:

```text
✓ All evaluated controls passed
```

### JSON Reporter

Top-level structure:

```json
{
  "scan_metadata": {
    "account_id": "...",
    "scan_timestamp": "ISO8601",
    "benchmark": "CIS AWS Foundations Benchmark v5.0.0",
    "controls_evaluated": [],
    "duration_ms": 0
  },
  "summary": {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "PASS": 0
  },
  "findings": []
}
```

Rules:

- Findings are serialized with `model_dump(mode="json")`.
- Write to a temp file in the target directory.
- Atomically replace the target path.
- Set file permissions to `0o600`.
- On Windows, apply best-effort file mode and document the platform caveat.

## 13. Logging and Observability

structlog writes JSON logs only to stderr.

Every scan completion log includes:

- timestamp
- level
- event
- account_id
- region
- controls_evaluated
- findings count by severity
- duration_ms

Never log:

- access keys
- secret keys
- session tokens
- credential file contents
- raw policy documents
- large raw AWS responses

AWS resource identifiers are passed as structured key-value data only, never interpolated into format strings.

## 14. Threat Model

### T1: Credential Theft

Risk:

- The scanner runs with AWS read-only permissions. If compromised, attacker gains account posture intelligence.

Mitigations:

- Never accept credentials as CLI arguments.
- Never store credentials.
- Never log credential values.
- Use boto3 standard credential chain only.
- Document a least-privilege scanner IAM policy.
- Run container as non-root.

### T2: Output File Exposure

Risk:

- JSON findings reveal IAM structure and security weaknesses.

Mitigations:

- Atomic JSON writes.
- `0o600` output permissions.
- README warning that reports contain sensitive account metadata.

### T3: Dependency Supply Chain Attack

Risk:

- CLI dependencies could introduce malicious code.

Mitigations:

- Pin exact dependency versions with hashes in `requirements.lock`.
- Run `pip-audit`.
- Run Dependabot weekly.
- Run Trivy image scanning.
- Keep runtime image minimal.

### T4: Prompt/Log Injection Through AWS Resource Names

Risk:

- IAM names or policy names could include adversarial strings.

Mitigations:

- Treat all AWS resource names as untrusted.
- Escape Rich markup.
- Use structured logging key-value pairs.
- Do not interpret resource names as commands, markup, or templates.

## 15. Docker Design

Dockerfile requirements:

- Base image: `python:3.12-slim-bookworm` pinned by digest.
- Multi-stage build:
  - `builder`: install dependencies from lockfile and build wheel.
  - `runtime`: copy only installed package/runtime artifacts.
- Runtime user:
  - UID `1000`
  - GID `1000`
  - non-root
- No credentials, `.env`, AWS config, or secret files copied.
- Copy only required artifacts:
  - `pyproject.toml`
  - `requirements.lock`
  - `src/`
- ENTRYPOINT:

```json
["iam-analyzer"]
```

CI validates:

- Trivy image scan: no HIGH/CRITICAL CVEs.
- Trivy config scan: no misconfigurations.
- hadolint: zero findings.

## 16. CI/CD Pipeline Design

Pipeline stages run in order:

1. `ruff check --select ALL .`
2. `mypy --strict src/`
3. `pytest --cov=src --cov-report=xml` with coverage threshold >= 85%.
4. `bandit -r src/ -ll`
5. `pip-audit`
6. `semgrep --config p/python --config p/security-audit src/`
7. `docker build`
8. `trivy image --exit-code 1 --severity HIGH,CRITICAL <image>`
9. `trivy config --exit-code 1 .`
10. `hadolint Dockerfile`
11. `gitleaks detect --source .`
12. Publish image to GHCR on merge to `main`.

Image tags:

- git SHA
- semantic version
- `latest` only on `main`

## 17. GitHub and Repository Plan

Repository:

- `Rblea97/aws-iam-analyzer`
- Apache-2.0 license.

Branch protection target:

- `main`
- require pull request before merge
- require 1 approval
- require all status checks
- disallow force pushes
- disallow direct pushes

Initial repository commits must follow the project workflow:

1. `chore: initial repo setup`
2. `chore(agents): create AGENTS.md with project context and working agreements`
3. `chore(docker): add Dockerfile and .dockerignore scaffold`
4. `ci: add GitHub Actions pipeline skeleton with all stage definitions`

After these baseline commits, all feature work occurs on short-lived feature branches and merges by PR.

## 18. Testing Strategy

TDD is required for implementation.

Each check function gets:

- compliant-state test
- non-compliant-state test
- edge-case test

Use:

- `pytest`
- `moto.mock_aws`
- `pytest.mark.parametrize`
- dummy AWS credentials in tests
- no live AWS calls

Coverage target:

- minimum 85%

Test boundaries:

- Check tests import check functions directly.
- CLI tests use Typer `CliRunner`.
- Reporter tests use captured stdout/temp files.
- JSON atomic write tests use `tmp_path`.
- Credential/session tests mock boto3/session failure modes.

## 19. Dependency Plan

Runtime dependencies:

- `boto3`: AWS SDK and standard credential chain.
- `typer`: typed CLI framework and test runner support.
- `pydantic`: strict Finding and ScanResult validation.
- `rich`: terminal tables and panels.
- `structlog`: structured JSON logging.

Development dependencies:

- `moto`: boto3 mocking.
- `pytest`: test runner.
- `pytest-cov`: coverage.
- `ruff`: linting and formatting.
- `mypy`: strict type checking.
- `bandit`: Python SAST.
- `pip-audit`: dependency CVE scanning.

Exact versions and hashes are locked in `requirements.lock`. `pyproject.toml` declares compatible minimums for development ergonomics; CI and Docker install from the lockfile.

## 20. Implementation Risks

- CIS v5.0.0 source availability: some control IDs require final validation against authoritative benchmark text before strict labeling.
- IAM credential report generation can have eventual consistency and CSV parsing edge cases.
- Boto3 pagination differs by service and operation.
- IAM policy wildcard detection must correctly handle string/list `Action`, `NotAction`, `Resource`, and `NotResource`.
- Permission gaps must degrade to `MANUAL_CHECK`, not crashes.
- CloudTrail multi-region semantics must avoid false confidence when only regional trails exist.
- S3 bucket hardening checks may fail cross-account or due to bucket policy permissions.
- Windows file permission semantics differ from POSIX `0o600`.
- GHCR publishing requires GitHub Actions permissions and package settings.

## 21. Acceptance Criteria

The project is not complete until:

- Requested v1.0 controls are implemented or explicitly documented as candidate/hardening controls.
- All checks pass locally.
- No secrets are present in staged changes.
- Docker image runs as non-root.
- JSON output is atomic and permission-restricted.
- README documents local, Docker, IAM policy, controls, examples, and contribution process.
- GitHub Actions gates pass.
- GHCR image publishes on `main`.
