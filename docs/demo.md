# Demo Walkthrough

This project is a CLI scanner, not a hosted web application. The safest public demo path uses synthetic sample data for screenshots and JSON examples, then a lab AWS account for live validation when credentials are available.

## Public Demo Assets

- Terminal renderer output: [`docs/assets/terminal-demo.svg`](assets/terminal-demo.svg)
- Sample JSON report: [`docs/examples/sample-findings.json`](examples/sample-findings.json)

Both assets use fictional resources and placeholder account data. They are generated from the same Pydantic models and Rich terminal renderer used by the production CLI, but they do not come from a real AWS account.

## Reviewer Commands

Run these commands without AWS credentials:

```powershell
docker build -t aws-iam-analyzer .
docker run --rm aws-iam-analyzer --help
docker run --rm aws-iam-analyzer scan --help
Get-Content .\docs\examples\sample-findings.json
```

## Lab Account Scan

Before scanning a real AWS account, attach [`docs/scanner-iam-policy.json`](scanner-iam-policy.json) to a lab scanner role or IAM principal.

Run locally:

```powershell
iam-analyzer scan --profile audit-profile --region us-east-1 --output-file findings.json
```

Run in Docker:

```powershell
docker run --rm `
  -e AWS_PROFILE=audit-profile `
  -v "$env:USERPROFILE\.aws:/home/appuser/.aws:ro" `
  aws-iam-analyzer scan --output-file /home/appuser/findings.json
```

On Windows Docker Desktop, host bind-mounted output directories can be sensitive to filesystem permissions for the non-root container user. If a direct bind-mounted `/reports` path fails, write to `/home/appuser/findings.json` inside the container and copy the file out with `docker cp`.

## Public Sharing Rules

- Do not publish real AWS account IDs, IAM ARNs, credential identifiers, credential report rows, or CloudTrail bucket names.
- Redact or replace real resource identifiers before using output in screenshots, resumes, or posts.
- Prefer synthetic examples for public README assets.
- Keep real scan output local unless it belongs to a disposable lab account and has been reviewed for sensitive identifiers.
