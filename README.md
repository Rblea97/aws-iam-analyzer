# aws-iam-analyzer

[![CI](https://github.com/Rblea97/aws-iam-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Rblea97/aws-iam-analyzer/actions/workflows/ci.yml)
![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB)
![Dockerized](https://img.shields.io/badge/Docker-non--root-2496ED)
![License](https://img.shields.io/badge/License-Apache--2.0-green)

`aws-iam-analyzer` is a read-only Python CLI that audits one AWS account for IAM and CloudTrail posture against implemented CIS AWS Foundations Benchmark v5.0.0 controls and clearly labeled enterprise CloudTrail hardening checks.

![aws-iam-analyzer terminal demo](docs/assets/terminal-demo.svg)

The demo above uses synthetic data and the same Rich renderer used by the CLI. A matching fictional sample report is available at [`docs/examples/sample-findings.json`](docs/examples/sample-findings.json), and the walkthrough is in [`docs/demo.md`](docs/demo.md).

## What This Demonstrates

- Registry-driven IAM and CloudTrail posture checks with explicit control IDs.
- Strict separation between executable CIS findings and additional enterprise hardening findings.
- boto3 standard credential-chain usage without raw credential CLI arguments.
- Pydantic v2 report models, Rich terminal output, atomic JSON reports, and CI-friendly exit codes.
- Repository-configured quality gates for linting, typing, tests, SAST, dependency audit, container scanning, Dockerfile scanning, and leak detection.

External repository settings such as branch protection, published package state, GitHub security settings, and live lab validation are `UNVERIFIED` from local files.

## Key Features

- Scans one AWS account with read-only credentials resolved by boto3.
- Evaluates 15 executable CIS IAM/CloudTrail controls and 3 enterprise CloudTrail hardening controls.
- Preserves severity as risk while reporting status as evaluation outcome.
- Writes JSON output atomically with owner-only permissions because reports can reveal account structure.
- Returns a non-zero exit code when HIGH or CRITICAL findings exist and `--exit-code` is enabled.

## Quick Start

Reviewer path with no AWS account required:

```powershell
git clone https://github.com/Rblea97/aws-iam-analyzer.git
cd aws-iam-analyzer
docker build -t aws-iam-analyzer .
docker run --rm aws-iam-analyzer --help
docker run --rm aws-iam-analyzer scan --help
```

Install and run locally against a lab AWS account:

```powershell
python -m pip install git+https://github.com/Rblea97/aws-iam-analyzer.git
iam-analyzer scan --profile audit-profile --region us-east-1 --output-file findings.json
```

Run with the default boto3 credential chain:

```powershell
iam-analyzer scan --region us-east-1
```

Run as a local gate:

```powershell
iam-analyzer scan --profile audit-profile --severity-filter HIGH --exit-code
```

The CLI never accepts raw AWS credential values or credential files as arguments. Use environment variables, an AWS profile, AWS IAM Identity Center, an instance role, or a container role supported by boto3.

## Docker Usage

Build the image locally:

```powershell
docker build -t aws-iam-analyzer .
```

Run with an AWS profile mounted read-only:

```powershell
docker run --rm -e AWS_PROFILE=audit-profile -v "$env:USERPROFILE\.aws:/home/appuser/.aws:ro" aws-iam-analyzer scan
```

Write a report from inside the container:

```powershell
docker run --rm `
  -e AWS_PROFILE=audit-profile `
  -v "$env:USERPROFILE\.aws:/home/appuser/.aws:ro" `
  aws-iam-analyzer scan --output-file /home/appuser/findings.json
```

For Windows Docker Desktop, writing directly to a bind-mounted host output directory can depend on host filesystem permissions. The portable path is to write inside `/home/appuser` and copy the report out with `docker cp`, or to use a host directory with explicit write permission for the container user.

Do not bake AWS credentials, `.env` files, or local AWS config into the image.

## GHCR Publishing

The GitHub Actions workflow is configured to publish GHCR images on pushes to `main` and version tags after the quality job succeeds. Published package availability is external GitHub state and is `UNVERIFIED` from local repository files.

## Scanner IAM Policy

Attach the policy in [`docs/scanner-iam-policy.json`](docs/scanner-iam-policy.json) to the scanner role or principal used for demos. It documents the intended read/list/get evidence APIs for implemented checks, `iam:GenerateCredentialReport` for IAM credential report generation, and `sts:GetCallerIdentity` for startup validation.

This policy is a scanner policy starting point, not a proven least privilege boundary for every AWS environment. Review it against [`docs/control-traceability.md`](docs/control-traceability.md) and your account controls before using it outside a disposable lab.

## Controls In Scope

The executable v1 scanner evaluates these strict CIS controls:

- `CIS-1.3`, `CIS-1.5`, `CIS-1.7`, `CIS-1.8`, `CIS-1.9`, `CIS-1.11`, `CIS-1.13`, `CIS-1.14`, `CIS-1.15`, `CIS-1.16`, `CIS-1.21`
- `CIS-3.1`, `CIS-3.2`, `CIS-3.4`, `CIS-3.5`

The scanner also evaluates these enterprise hardening controls:

- `EHC-CT-1`, `EHC-CT-2`, `EHC-CT-3`

See [`docs/controls.md`](docs/controls.md) for control titles and scope boundaries. See [`docs/control-traceability.md`](docs/control-traceability.md) for evidence APIs, evaluators, emitted statuses, limitations, and test references.

## Example JSON Output

The public example report uses fictional resources and placeholder account data:

```powershell
Get-Content .\docs\examples\sample-findings.json
```

The schema version `1.1` report shape includes status counts and severity counts:

```json
{
  "scan_metadata": {
    "account_id": "123456789012",
    "schema_version": "1.1",
    "scan_timestamp": "2026-05-19T18:30:00Z",
    "benchmark": "CIS AWS Foundations Benchmark v5.0.0",
    "controls_evaluated": ["CIS-1.13", "CIS-3.1", "CIS-3.2", "EHC-CT-1"],
    "duration_ms": 948
  },
  "summary": {
    "CRITICAL": 0,
    "HIGH": 2,
    "MEDIUM": 0,
    "LOW": 1,
    "PASS": 1,
    "FAIL": 2,
    "MANUAL_CHECK": 1,
    "ERROR": 0,
    "NOT_APPLICABLE": 0
  },
  "findings": [
    {
      "control_id": "CIS-1.13",
      "control_title": "Ensure access keys are rotated every 90 days or less",
      "severity": "HIGH",
      "status": "FAIL",
      "resource_id": "arn:aws:iam::123456789012:user/demo-auditor",
      "remediation": "For CIS-1.13, rotate IAM access keys that are older than 90 days. AWS IAM documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
      "raw_evidence": {
        "source": "fictional-demo-data",
        "user": "demo-auditor",
        "credential_age_days": 127
      },
      "evaluated_at": "2026-05-19T20:46:46.674992Z"
    }
  ]
}
```

## Design Notes

| Concern | Current approach |
| --- | --- |
| CIS coverage traceability | Executable checks live in `CHECK_SPECS`; roadmap controls stay registered but do not appear in reports. |
| Credential handling | Credentials flow through `boto3.Session`; the CLI does not accept raw key material. |
| Human and machine reporting | Rich renders terminal output while Pydantic models serialize the same findings into JSON. |
| Permission gaps | Checks return `MANUAL_CHECK` findings for documented access or evidence gaps where handled. |
| Admin-policy detection | The evaluator covers obvious admin-equivalent managed and inline policy patterns, not full effective permissions. |

## Security Model

| Threat | Mitigation |
| --- | --- |
| Credential disclosure | Credentials are not accepted as CLI arguments, stored by the tool, or logged. boto3 resolves credentials through its standard chain. |
| Sensitive findings exposure | JSON reports are written atomically with owner-only file permissions because they may contain account structure data. |
| Dependency supply chain risk | The workflow config installs from a hash-pinned lockfile and runs dependency and security scanners. |
| AWS resource name injection | Resource identifiers are treated as untrusted data and escaped in Rich output. Logs use structlog fields. |
| Container compromise blast radius | The runtime image uses a non-root user and excludes local docs, tests, AWS credentials, and build tooling. |

## Architecture

The project uses a small layered CLI architecture: `cli` handles Typer options, `scanner` owns boto3 sessions and orchestration, `checks` contains registry-driven control evaluation, `models` validates findings and scan results, and `reporter` renders terminal and JSON output.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for trust boundaries, data flow, report sensitivity, limitations, and extension points.

## Contributing A New Check

1. Add or confirm the control metadata in `src/iam_analyzer/checks/registry.py`.
2. Write focused tests for compliant, failing, and permission-denied or evidence-gap states.
3. Implement a check function under the relevant checks module. The function accepts pre-initialized clients and returns `Finding` objects.
4. Add the check to `src/iam_analyzer/checks/catalog.py` so the scanner orchestrator executes it.
5. Update `docs/controls.md`, `docs/control-traceability.md`, and the scanner IAM policy when the check needs additional read-only evidence APIs.
6. Run the local quality and security gates before opening a PR.

For more detail, see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
