# Architecture

## Current Architecture

`aws-iam-analyzer` is a Python 3.12 CLI that performs read-only posture checks for one AWS account. The implemented scope is IAM and CloudTrail-focused checks mapped to CIS AWS Foundations Benchmark v5.0.0 where the project has executable evidence collection, plus separately labeled enterprise CloudTrail hardening checks.

The package is organized around a small layered boundary:

- `iam_analyzer.cli`: Typer command surface, option validation, exit-code behavior, and reporter invocation.
- `iam_analyzer.scanner`: boto3 session/client construction, STS caller validation, check orchestration, pagination helpers, and scan summary aggregation.
- `iam_analyzer.checks`: control metadata, executable check catalog, evidence collection, evaluator logic, and finding construction.
- `iam_analyzer.models`: Pydantic models for findings, status/severity enums, scan metadata, schema versioning, and JSON-safe serialization.
- `iam_analyzer.reporter`: Rich terminal rendering and atomic JSON report writing.

The auditable execution source is `src/iam_analyzer/checks/catalog.py`. Registry metadata in `src/iam_analyzer/checks/registry.py` contains both executable controls and registered roadmap controls, but only entries in `CHECK_SPECS` run during a scan.

Check implementation files are split into focused IAM and CloudTrail modules. The public contract remains the catalog: each executable check accepts prebuilt clients and a paginator utility, then returns validated `Finding` objects.

## Data Flow

1. The CLI parses scan options and rejects credential-like profile input.
2. `SessionManager` builds one boto3 session using the standard AWS credential provider chain.
3. Startup validation calls `sts:GetCallerIdentity` and stores the account ID for scan metadata.
4. The scanner orchestrator walks `CHECK_SPECS` in registry order.
5. Service clients are created once per run and reused by checks.
6. Each check collects AWS evidence, normalizes it into JSON-safe structures, evaluates compliance, and creates one or more findings.
7. The orchestrator builds `ScanResult` with metadata, schema version `1.1`, severity counts, and status counts.
8. The terminal reporter renders a human-readable Rich report to stdout.
9. The JSON reporter writes a machine-readable report with owner-only permissions and atomic replacement.

No normal CI path calls live AWS APIs. Tests use local stubs and model-level validation.

## Control Evaluation Lifecycle

Each executable control follows this lifecycle:

1. **Catalog selection:** `CHECK_SPECS` identifies the control ID, title, service boundary, required service clients, and check function.
2. **Evidence collection:** the check calls only prebuilt clients supplied by the scanner layer.
3. **Evidence normalization:** raw AWS responses are converted into JSON-safe evidence for findings.
4. **Pure evaluation where practical:** condition checks are separated from report rendering and from CLI behavior.
5. **Finding construction:** helper functions attach registry titles, severity, status, resource identity when available, remediation, and raw evidence.
6. **Aggregation:** the scanner counts findings by severity and by status. `MANUAL_CHECK` is a status, not a severity downgrade.
7. **Reporting:** terminal and JSON reporters present the same validated model.

Current statuses supported by the model are `PASS`, `FAIL`, `MANUAL_CHECK`, `ERROR`, and `NOT_APPLICABLE`. Existing executable checks primarily emit `PASS`, `FAIL`, and `MANUAL_CHECK`.

## Trust Boundaries

- **AWS credential boundary:** credentials remain inside boto3 and AWS SDK providers. The CLI does not accept raw access keys, secret keys, session tokens, or credential files as arguments.
- **AWS evidence boundary:** IAM, CloudTrail, S3, and STS responses are untrusted input. Resource names, ARNs, and account identifiers can appear in reports and logs.
- **Terminal boundary:** Rich output escapes AWS-derived strings before rendering.
- **Report boundary:** JSON reports are sensitive local artifacts and use owner-only file permissions.
- **Container boundary:** the runtime image runs as a non-root user. Host AWS config is mounted read-only by the operator when Docker is used.
- **Repository boundary:** public demo assets use fictional account data. Real scan output stays outside the repository unless sanitized.

## Data Classification

| Data | Examples | Handling |
| --- | --- | --- |
| Credentials | access keys, session tokens, profile secrets, `.env` values | Not accepted as CLI values, not logged, not committed. |
| Account identifiers | AWS account ID, IAM ARNs, CloudTrail bucket names | Allowed in local reports, treated as sensitive for public sharing. |
| Evidence | credential report fields, policy metadata, CloudTrail settings, S3 policy status | Serialized into reports only after JSON-safe normalization. |
| Public docs/demo data | sample findings, SVG terminal demo, README examples | Uses fictional values only. |
| Operational logs | scan completion metadata and summary counts | Written separately from terminal report through structlog. |

## AWS API Failure Model

The scanner is read-only and permission-sensitive. When AWS denies a required evidence API, a check returns `MANUAL_CHECK` with error evidence instead of silently passing the control.

Expected failure classes:

- Missing AWS credentials or invalid identity: scan startup fails before checks run.
- Permission gaps on a check API: the affected control emits `MANUAL_CHECK`.
- Endpoint/network failures: the affected control emits `MANUAL_CHECK` where handled by the check.
- Malformed or missing evidence: the affected control emits `MANUAL_CHECK` when the check can identify the gap.
- Unexpected programming errors: not treated as compliance results; these fail tests or the CLI run.

Credential report generation uses bounded polling/backoff in the polish branch. Timeout, access denied, and malformed report paths are documented as explicit manual-review outcomes.

## Report Sensitivity Model

JSON reports can expose account structure, IAM user names, ARNs, policy names, CloudTrail bucket names, and control failures. They are local security artifacts, not public evidence.

The JSON writer creates the temporary report path with owner-readable/owner-writable permissions, writes the payload, and atomically replaces the destination. The final path is also restricted to owner read/write where the platform supports POSIX-like file modes.

Schema version `1.1` adds explicit status counts while preserving severity counts:

- Severity buckets: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- Status buckets: `PASS`, `FAIL`, `MANUAL_CHECK`, `ERROR`, `NOT_APPLICABLE`.

Severity describes risk. Status describes evaluation outcome.

## Extension Points

- Add a control by registering metadata, writing tests, implementing a check function, adding it to `CHECK_SPECS`, and updating docs plus the scanner IAM policy.
- Add evidence helpers inside focused check modules when multiple controls share AWS response parsing.
- Add report formats behind the validated `ScanResult` model rather than building parallel result objects.
- Add multi-account scanning above the current check contract by creating scan contexts and per-account orchestration.

## Non-Goals

- The scanner does not mutate AWS resources.
- The scanner does not accept raw AWS credentials.
- The scanner does not perform organization-wide analysis.
- The scanner does not evaluate SCPs, permission boundaries, session policies, resource policies, or all IAM condition semantics.
- The scanner does not execute IAM Access Analyzer.
- CI does not perform live AWS validation.
- The project does not claim complete CIS AWS Foundations Benchmark coverage.

## Known Limitations

- Scope is one AWS account per scan.
- CloudTrail checks are based on evidence visible to the configured region and the current account.
- Admin-policy detection is an obvious-pattern evaluator, not full effective permissions analysis.
- Access Analyzer, AWS Organizations, SCPs, and cross-account trust graph analysis are not implemented.
- Registered roadmap controls are not executable until they have tests, evidence APIs, catalog entries, and scanner policy updates.
- Published GHCR package availability, branch protection, repository settings, and live AWS lab validation are external state and are `UNVERIFIED` from local repository files.

See [docs/limitations.md](docs/limitations.md) for the operational limitations list.

## Future Multi-Account/Multi-Region Direction

Roadmap work can add a typed scan context containing account ID, partition, region set, and assumed-role metadata. Multi-account support belongs above the current check contract: account discovery and role assumption can create per-account scan jobs, while check functions continue to receive prepared clients and typed context.

Roadmap CloudTrail work can make region semantics explicit by scanning enabled regions, normalizing organization trails, and documenting how home-region, multi-region, and global-service-event evidence is reconciled.
