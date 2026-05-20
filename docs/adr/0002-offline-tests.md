# ADR 0002: Offline Tests

## Status

Accepted.

## Context

The scanner interacts with AWS IAM, CloudTrail, S3, and STS APIs. Real AWS calls in CI would require credentials, create flaky environment coupling, and risk exposing account metadata in logs.

## Decision

Normal tests run offline with local stubs, model validation, and deterministic fixtures. Live AWS validation is a manual lab activity outside CI and is `UNVERIFIED` from local repository files.

## Consequences

- CI can run without cloud credentials.
- Tests can cover permission-denied, malformed-evidence, timeout, and edge-case paths deterministically.
- Offline tests do not prove behavior against every live AWS API response variation.
- Lab validation evidence must stay outside the repository unless sanitized.

## Verification Impact

Required gates are local unit, scanner, reporter, CLI, docs, lint, type, SAST, dependency, and container checks. Live AWS validation is documented as a limitation rather than a CI guarantee.
