# Limitations

This document lists operational limits that affect interpretation of `aws-iam-analyzer` results.

## Single-Account Scope

Each scan evaluates one AWS account using the credentials resolved by boto3 for that run. The scanner does not assume roles into additional accounts, enumerate AWS Organizations accounts, or aggregate organization-wide posture.

## CloudTrail Region Semantics

CloudTrail checks evaluate trail evidence visible to the configured scan region and account. Multi-region trails can satisfy controls that require multi-region coverage, but the scanner does not enumerate every enabled AWS Region or reconcile organization trails across accounts.

Region-wide CloudTrail posture outside the configured scan context is not proven by a single run.

## IAM Effective Permissions

Admin-policy detection is an obvious-pattern evaluator. It checks managed and inline policy documents for broad allow patterns such as wildcard action/resource grants and broad `NotAction` allow statements where implemented.

It does not model:

- AWS Organizations SCPs.
- Permissions boundaries.
- Session policies.
- Resource policies.
- Full IAM condition evaluation.
- Cross-account trust paths.
- Service-specific authorization edge cases.

The result is useful evidence, not a complete effective-permissions proof.

## Access Analyzer

The scanner does not execute IAM Access Analyzer. Registered roadmap control `CIS-1.19` is not an executable check until Access Analyzer evidence collection, tests, scanner policy updates, and docs are added.

## CI And Live AWS Validation

Normal CI uses offline tests and local stubs. It does not call live AWS APIs.

Any lab-account scan is operator-run outside CI. Local repository files do not prove that live AWS validation has occurred, so live AWS validation is `UNVERIFIED` unless separate evidence is supplied.

## Scanner IAM Policy

[`docs/scanner-iam-policy.json`](scanner-iam-policy.json) documents the intended scanner permissions for implemented checks plus `iam:GenerateCredentialReport` and `sts:GetCallerIdentity`. Compare it with [`docs/control-traceability.md`](control-traceability.md) during review, especially when new evidence APIs are added.

The policy is a scanner policy starting point, not a least privilege proof. Environments with SCPs, permission boundaries, IAM Identity Center, custom conditions, or centralized logging accounts can require adjustment.

## Output Sensitivity And Redaction

Reports can include AWS account IDs, IAM ARNs, user names, policy names, CloudTrail trail metadata, S3 bucket names, and control failures. Treat JSON reports as sensitive local artifacts.

Public demos, screenshots, resumes, posts, and issue reports need synthetic data or reviewed redaction. Do not publish raw credential reports, real AWS findings, or credential-bearing configuration.

## Registered Roadmap Controls

Some CIS IDs are registered in code but not executable. They exist for metadata continuity and future implementation planning. They do not appear in scan output until they are added to `CHECK_SPECS`.

See [`docs/control-traceability.md`](control-traceability.md) for the executable and roadmap split.
