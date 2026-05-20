# ADR 0003: Report Sensitivity And Redaction

## Status

Accepted.

## Context

Scan reports can expose AWS account IDs, IAM ARNs, user names, policy names, CloudTrail trail metadata, S3 bucket names, and security findings. These values are not credentials, but they can reveal account structure and security posture.

## Decision

JSON reports are treated as sensitive local artifacts. The reporter writes temporary and final report files with owner-only permissions where supported, and public docs use fictional values. Real findings stay out of the repository unless deliberately sanitized.

## Consequences

- Report permissions are part of the security model.
- Public README and demo assets use synthetic data.
- Issue reports and release artifacts must avoid raw account output.
- Redaction remains an operator responsibility for any public sharing.

## Verification Impact

Reporter tests cover JSON shape, atomic replacement, owner-only permissions, overwrite behavior, and cleanup on failure where testable. Documentation names output sensitivity and redaction expectations.
