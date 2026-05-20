# ADR 0001: Single-Account Scope

## Status

Accepted.

## Context

The project is a portfolio-friendly defensive scanner. The first auditable version needs a small trust boundary and offline testability. Multi-account scanning adds role assumption, account discovery, organization permissions, regional fan-out, and more sensitive failure modes.

## Decision

Version 1 scans one AWS account per run using the credentials resolved by boto3. The scanner records the caller account ID from STS and evaluates only the account visible to that identity.

## Consequences

- The CLI stays simple and read-only.
- Findings are easier to interpret because each report has one account context.
- Organization-wide posture, SCP-aware analysis, and delegated administrator patterns remain outside current scope.
- Multi-account support belongs above the existing check contract as future orchestration.

## Verification Impact

Tests use stubbed session managers and service clients. CI does not need AWS Organizations access or live AWS credentials.
