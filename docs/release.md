# Release Checklist

This project treats a release as both a package milestone and a portfolio demo
checkpoint. Use this checklist before tagging `v0.1.0` or any later version.

## V1 MVP Criteria

- `main` is green in GitHub Actions.
- The README has a synthetic terminal demo, quick-start commands, and clear AWS
  credential guidance.
- `CONTRIBUTING.md`, `docs/controls.md`, `docs/demo.md`, and this release
  checklist match the released behavior.
- The Docker image runs with `--help` locally and from GHCR.
- A lab AWS scan has been tested locally or in Docker with read-only access.
- No real account IDs, ARNs, bucket names, local paths, or credential-bearing
  values are included in committed demo artifacts.

## Release Architecture Summary

The current release scans one AWS account, renders a Rich terminal report, and
writes an atomic JSON report suitable for review or CI artifacts. The scanner
creates one boto3 session per run, validates caller identity with STS, and passes
prebuilt service clients into independently testable check functions.

Strict CIS AWS Foundations Benchmark findings and enterprise CloudTrail
hardening guidance share the same validated Pydantic finding model, but the
control IDs keep benchmark findings distinct from additional hardening checks.
Terminal output uses stdout, while structured logs use stderr.

## Release Commands

Create the V1 tag from an up-to-date `main` checkout after CI is passing:

```powershell
git checkout main
git pull origin main
git tag -a v0.1.0 -m "v0.1.0 - V1 MVP"
git push origin v0.1.0
```

The tag push runs the same quality gates as pull requests. If those gates pass,
the publish job pushes these GHCR tags:

```text
ghcr.io/rblea97/aws-iam-analyzer:<git-sha>
ghcr.io/rblea97/aws-iam-analyzer:sha-<git-sha>
ghcr.io/rblea97/aws-iam-analyzer:v0.1.0
ghcr.io/rblea97/aws-iam-analyzer:0.1.0
ghcr.io/rblea97/aws-iam-analyzer:latest
```

## Demo Validation

Reviewer path with no AWS account:

```powershell
docker pull ghcr.io/rblea97/aws-iam-analyzer:latest
docker run --rm ghcr.io/rblea97/aws-iam-analyzer:latest --help
docker run --rm ghcr.io/rblea97/aws-iam-analyzer:latest scan --help
```

Lab account path:

```powershell
docker run --rm `
  -e AWS_PROFILE=audit-profile `
  -v "$env:USERPROFILE\.aws:/home/appuser/.aws:ro" `
  ghcr.io/rblea97/aws-iam-analyzer:latest scan --region us-east-1
```

If a JSON report is generated during demo prep, keep it outside the repository
unless it has been replaced with fictional values.

## GitHub Release Notes

Suggested title:

```text
v0.1.0 - V1 MVP
```

Suggested notes:

```markdown
## Highlights

- Read-only AWS IAM and CloudTrail posture scanning for a single account.
- Severity-ranked Rich terminal report and JSON findings output.
- 15 executable CIS AWS Foundations Benchmark v5.0.0 controls plus 3 labeled enterprise CloudTrail hardening checks.
- Non-root Docker image published to GHCR.
- CI quality gates for linting, typing, tests, SAST, dependency audit, container scan, Dockerfile scan, and leak detection.

## Demo

- No-AWS reviewer path: `docker run --rm ghcr.io/rblea97/aws-iam-analyzer:latest --help`
- Lab account path: mount an AWS profile read-only and run `iam-analyzer scan`.

## Notes

This release is a portfolio-grade MVP. Multi-account scanning and additional CIS sections are planned v2 extension points.
```
