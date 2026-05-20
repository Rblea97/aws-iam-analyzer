# Security Policy

`aws-iam-analyzer` is a defensive cloud security tool. Report suspected vulnerabilities privately so fixes can be prepared before public disclosure.

## Supported Versions

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |

## Reporting A Vulnerability

Use GitHub private vulnerability reporting when available for this repository. If that option is not visible, open a GitHub issue with only a brief non-sensitive summary and request a private contact path.

Do not include exploit details, credential material, account identifiers, or real AWS findings in a public issue.

Include:

- Affected version or commit SHA.
- Component affected, such as CLI input validation, report writing, Docker image, dependency chain, or AWS API handling.
- Reproduction steps using synthetic data where possible.
- Security impact and any observed workaround.

## Security Commitments

- The CLI does not accept raw AWS credential values as command arguments.
- AWS authentication is delegated to boto3's standard credential provider chain.
- JSON reports are created and replaced with owner-only file permissions where the platform supports POSIX-like modes.
- Runtime containers use a non-root user.
- The workflow config includes Ruff, mypy, pytest coverage, Bandit, pip-audit, Semgrep, Docker build, Trivy, Hadolint, and Gitleaks.
- Branch protection and required status-check settings are external GitHub repository state and are `UNVERIFIED` from local files.

## Sensitive Output

Scan reports can contain AWS account IDs, IAM ARNs, user names, policy names, CloudTrail trail metadata, S3 bucket names, and security findings. Treat report files as sensitive local artifacts.

Public screenshots, sample reports, and demos use synthetic AWS account identifiers and fictional resource names. Do not publish real scan reports or lab account structure unless the data has been intentionally sanitized.

## Scanner Policy Boundary

[`docs/scanner-iam-policy.json`](docs/scanner-iam-policy.json) documents the intended read-only scanner permission set for implemented checks. It is not a formal least privilege proof for every AWS environment. Review it against [`docs/control-traceability.md`](docs/control-traceability.md), organization controls, SCPs, permission boundaries, and account-specific guardrails before use outside a disposable lab.
