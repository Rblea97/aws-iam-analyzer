# ADR 0004: Check Evaluator Boundaries

## Status

Accepted.

## Context

Security checks are easiest to audit when evidence collection, normalization, evaluation, and finding construction are visible and testable. Dense scanner code also makes it harder to distinguish CIS findings from hardening guidance.

## Decision

Checks are registry-driven and receive prebuilt service clients from the scanner layer. Check implementations separate evidence collection, JSON-safe normalization, evaluator logic, and finding construction where practical. The catalog remains the source of executable ordering and scope.

## Consequences

- Check functions remain offline-testable with stubbed clients.
- Duplicated finding and error helper logic can move into shared check helpers.
- Manual checks preserve risk severity while using status to describe incomplete evaluation.
- Admin-policy detection remains an obvious-pattern evaluator, not full effective permissions analysis.

## Verification Impact

Unit and stub tests cover evaluator behavior, permission gaps, malformed evidence, and scanner aggregation. Code-shape enforcement belongs in local tests or CI so long functions and dense modules stay visible.
