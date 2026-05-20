# Release Checklist

This project treats a release as both a package milestone and a portfolio demo checkpoint. Use this checklist before tagging `v0.1.0` or any later version.

## V1 MVP Criteria

- GitHub Actions quality workflow passes for the release commit. Local repository files cannot verify current remote CI state: `UNVERIFIED`.
- The README has a synthetic terminal demo, quick-start commands, and clear AWS credential guidance.
- `ARCHITECTURE.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/controls.md`, `docs/control-traceability.md`, `docs/limitations.md`, `docs/demo.md`, and this checklist match released behavior.
- The Docker image runs with `--help` locally.
- GHCR publishing is configured in `.github/workflows/ci.yml`; published package availability is external state and `UNVERIFIED`.
- Lab AWS scan validation is operator-run and not part of CI. If performed, keep evidence outside the repository unless sanitized.
- No real account IDs, ARNs, bucket names, local paths, or credential-bearing values are included in committed demo artifacts.

## Release Architecture Summary

The current release scans one AWS account, renders a Rich terminal report, and writes an atomic JSON report suitable for local review or CI artifacts. The scanner creates one boto3 session per run, validates caller identity with STS, and passes prebuilt service clients into check functions.

Strict CIS AWS Foundations Benchmark findings and enterprise CloudTrail hardening findings share the same validated Pydantic model, but control IDs keep benchmark checks distinct from additional hardening checks. Terminal output uses stdout, while structured logs use stderr.

Schema version `1.1` includes severity counts and status counts so `MANUAL_CHECK` findings remain visible as evaluation gaps.

## Release Commands

Create the V1 tag from an up-to-date `main` checkout after local validation and remote CI verification:

```powershell
git checkout main
git pull origin main
git tag -a v0.1.0 -m "v0.1.0 - V1 MVP"
git push origin v0.1.0
```

The workflow config runs the same quality job for pull requests, pushes to `main`, and version tags. The publish job is configured to push these GHCR tags on eligible `main` and tag pushes after the quality job succeeds:

```text
ghcr.io/rblea97/aws-iam-analyzer:<git-sha>
ghcr.io/rblea97/aws-iam-analyzer:sha-<git-sha>
ghcr.io/rblea97/aws-iam-analyzer:v0.1.0
ghcr.io/rblea97/aws-iam-analyzer:0.1.0
ghcr.io/rblea97/aws-iam-analyzer:latest
```

Actual package publication is `UNVERIFIED` from local files.

## Demo Validation

Reviewer path with no AWS account:

```powershell
docker build -t aws-iam-analyzer .
docker run --rm aws-iam-analyzer --help
docker run --rm aws-iam-analyzer scan --help
```

Lab account path:

```powershell
docker run --rm `
  -e AWS_PROFILE=audit-profile `
  -v "$env:USERPROFILE\.aws:/home/appuser/.aws:ro" `
  aws-iam-analyzer scan --region us-east-1
```

If a JSON report is generated during demo prep, keep it outside the repository unless it has been replaced with fictional values.

## GitHub Release Notes

Suggested title:

```text
v0.1.0 - V1 MVP
```

Suggested notes:

```markdown
## Highlights

- Read-only AWS IAM and CloudTrail posture scanning for one account.
- Severity-ranked Rich terminal report and JSON findings output.
- 15 executable CIS AWS Foundations Benchmark v5.0.0 controls plus 3 labeled enterprise CloudTrail hardening checks.
- Non-root Docker runtime image.
- Workflow-configured quality gates for linting, typing, tests, SAST, dependency audit, container scan, Dockerfile scan, and leak detection.

## Demo

- No-AWS reviewer path: build the Docker image locally and run `aws-iam-analyzer --help`.
- Lab account path: mount an AWS profile read-only and run `iam-analyzer scan`.

## Notes

This release is a portfolio MVP. Multi-account scanning, Access Analyzer integration, and additional CIS sections are roadmap items.
```
