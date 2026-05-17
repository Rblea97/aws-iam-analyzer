# aws-iam-analyzer

AWS IAM and CloudTrail posture analyzer for CIS AWS Foundations Benchmark v5.0.0.

Status: implementation in progress.

Architecture: [ARCHITECTURE.md](ARCHITECTURE.md)

Security note: credentials are never accepted as CLI arguments. The analyzer uses the standard boto3 credential chain only.
