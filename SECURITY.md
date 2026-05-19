# Security Policy

`aws-iam-analyzer` is a defensive cloud security tool. Please report suspected
vulnerabilities privately so they can be fixed before public disclosure.

## Supported Versions

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |

## Reporting A Vulnerability

Use GitHub private vulnerability reporting when available for this repository.
If that option is not visible, open a GitHub issue with only a brief, non-sensitive
summary and request a private contact path. Do not include exploit details,
credential material, account identifiers, or real AWS findings in a public issue.

Please include:

- Affected version or commit SHA.
- Component affected, such as CLI input validation, report writing, Docker image,
  dependency chain, or AWS API handling.
- Reproduction steps using synthetic data where possible.
- Security impact and any observed workaround.

## Security Commitments

- The CLI does not accept raw AWS credential values as command arguments.
- AWS authentication is delegated to boto3's standard credential provider chain.
- JSON reports are written atomically with owner-only file permissions.
- Runtime containers use a non-root user.
- CI runs linting, typing, tests, SAST, dependency audit, container scanning,
  Dockerfile scanning, and leak detection before merge.

## Demo Data

Public screenshots, sample reports, and demos must use synthetic AWS account
identifiers and fictional resource names. Do not publish real scan reports or
lab account structure unless the data has been intentionally sanitized.
