# aws-iam-analyzer

[![CI](https://github.com/Rblea97/aws-iam-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Rblea97/aws-iam-analyzer/actions/workflows/ci.yml)

`aws-iam-analyzer` is a read-only Python CLI that audits AWS IAM and CloudTrail posture against CIS AWS Foundations Benchmark v5.0.0 and produces terminal and JSON findings with remediation guidance.

## Demo Status

This project is a CLI portfolio tool, not a hosted web application. The intended demo path is a local or containerized scan against a lab AWS account using a read-only scanner role.

## Tech Stack

| Technology | Why it is used |
| --- | --- |
| Python 3.12 | Modern standard library, strong typing, and broad cloud tooling support. |
| boto3 | Native AWS SDK and standard credential provider chain. |
| Typer | Type-annotated CLI commands with testable command runners. |
| Pydantic v2 | Strict finding validation and JSON-safe model serialization. |
| Rich | Readable terminal tables and severity-colored summaries. |
| structlog | Structured JSON logs on stderr for automation and audit trails. |
| pytest, moto, pytest-cov | Fast local tests without real AWS API calls. |
| Docker | Reproducible non-root runtime for local and CI usage. |

## Key Features

- Scans a single AWS account with read-only credentials resolved by boto3.
- Evaluates implemented IAM and CloudTrail checks against CIS AWS Foundations Benchmark v5.0.0 control IDs.
- Separates strict CIS findings from enterprise CloudTrail hardening checks.
- Renders a Rich terminal report and writes an atomic JSON findings document with `0o600` permissions.
- Exits non-zero for HIGH or CRITICAL findings when `--exit-code` is enabled, making the tool usable as a CI gate.

## Quick Start

Install from the repository:

```powershell
python -m pip install git+https://github.com/Rblea97/aws-iam-analyzer.git
iam-analyzer scan --profile audit-profile --region us-east-1 --output-file findings.json
```

Run with the default boto3 credential chain:

```powershell
iam-analyzer scan --region us-east-1
```

Run with a severity filter and CI-style exit code:

```powershell
iam-analyzer scan --profile audit-profile --severity-filter HIGH --exit-code
```

The CLI never accepts AWS access keys or temporary credential values as arguments. Use environment variables, an AWS profile, AWS IAM Identity Center, an instance role, or a container role supported by boto3.

## Docker Quick Start

Build the image:

```powershell
docker build -t aws-iam-analyzer .
```

Run with an AWS profile mounted read-only:

```powershell
docker run --rm -e AWS_PROFILE=audit-profile -v "$env:USERPROFILE\.aws:/home/appuser/.aws:ro" aws-iam-analyzer scan
```

For local Docker usage, prefer the read-only AWS profile mount above. In CI or container platforms, inject credentials through the platform's environment or role mechanism and pass only non-sensitive runtime settings on the command line:

```powershell
docker run --rm -e AWS_REGION=us-east-1 aws-iam-analyzer scan
```

Do not bake AWS credentials or local `.env` files into the image.

## Scanner IAM Policy

Attach the policy in [`docs/scanner-iam-policy.json`](docs/scanner-iam-policy.json) to the scanner role or principal used for demos. The policy contains the read/list/get actions required by the currently implemented checks, `iam:GenerateCredentialReport` so the tool can create the IAM credential report when AWS has not generated one yet, and `sts:GetCallerIdentity` for startup validation.

## Controls In Scope

The current scanner evaluates these strict CIS controls:

- `CIS-1.3`, `CIS-1.5`, `CIS-1.7`, `CIS-1.8`, `CIS-1.9`, `CIS-1.11`, `CIS-1.13`, `CIS-1.14`, `CIS-1.15`, `CIS-1.16`, `CIS-1.21`
- `CIS-3.1`, `CIS-3.2`, `CIS-3.4`, `CIS-3.5`

The scanner also evaluates these enterprise hardening controls:

- `EHC-CT-1`, `EHC-CT-2`, `EHC-CT-3`

See [`docs/controls.md`](docs/controls.md) for control titles, evidence APIs, severities, remediation summaries, and registered CIS controls that are not yet wired into scan execution.

## Example Terminal Output

```text
Scan summary: CIS AWS Foundations Benchmark v5.0.0
Account ID    Timestamp             Total  CRITICAL  HIGH  MEDIUM  LOW  PASS
123456789012  2026-05-18T18:00:00Z  18     0         3     6       1    8

Findings requiring attention
Control ID  Severity  Status  Resource  Title
CIS-1.13    HIGH      FAIL    -         Ensure access keys are rotated...
CIS-3.1     HIGH      FAIL    -         Ensure CloudTrail is enabled...

Passing Controls
PASS findings: 8 (collapsed)
```

## Example JSON Output

```json
{
  "scan_metadata": {
    "account_id": "123456789012",
    "scan_timestamp": "2026-05-18T18:00:00Z",
    "benchmark": "CIS AWS Foundations Benchmark v5.0.0",
    "controls_evaluated": ["CIS-1.3", "CIS-1.5", "CIS-3.1"],
    "duration_ms": 842
  },
  "summary": {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 0,
    "PASS": 1
  },
  "findings": [
    {
      "control_id": "CIS-1.13",
      "control_title": "Ensure access keys are rotated every 90 days or less",
      "severity": "HIGH",
      "status": "FAIL",
      "resource_id": null,
      "remediation": "For CIS-1.13, rotate IAM access keys that are older than 90 days. AWS IAM documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
      "raw_evidence": {
        "stale_access_keys": [
          {
            "user": "demo-user",
            "access_key_id": "redacted-access-key-id",
            "age_days": 120
          }
        ]
      },
      "evaluated_at": "2026-05-18T18:00:00Z"
    }
  ]
}
```

## Threat Model Summary

| Threat | Mitigation |
| --- | --- |
| Credential disclosure | Credentials are never accepted as CLI arguments, stored by the tool, or logged. boto3 resolves credentials through its standard chain. |
| Sensitive findings exposure | JSON reports are written atomically and chmodded to `0o600` because they may contain account structure data. |
| Dependency supply chain risk | CI runs pinned dependency installation, `pip-audit`, Semgrep, Bandit, Trivy, Hadolint, and Gitleaks. |
| AWS resource name injection | Resource identifiers are treated as untrusted data and escaped in Rich output. Logs use structlog key-value fields. |

## Architecture

The project uses a small layered CLI architecture: `cli` handles Typer options, `scanner` owns boto3 sessions and orchestration, `checks` contains one check function per control, `models` validates findings and scan results, and `reporter` renders terminal and JSON output. This keeps checks independently testable and leaves room for future multi-account scanning without changing the check contract.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the architecture summary.

## Contributing A New Check

1. Add or confirm the control metadata in `src/iam_analyzer/checks/registry.py`.
2. Write a focused test for the compliant state, failing state, and edge or permission-denied state.
3. Implement one check function in the relevant `checks` module. The function must accept pre-initialized clients and return `Finding` objects.
4. Add the check to `src/iam_analyzer/checks/catalog.py` so the scanner orchestrator executes it.
5. Update `docs/controls.md` and the scanner IAM policy if the check needs additional read-only evidence APIs.
6. Run `ruff`, `mypy`, `pytest`, `bandit`, `pip-audit`, Semgrep, Docker build, Trivy, Hadolint, and Gitleaks before opening a PR.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
