# Architecture

## Purpose

aws-iam-analyzer is a Python CLI that will inspect AWS IAM and CloudTrail posture against CIS AWS Foundations Benchmark v5.0.0 controls. The project is designed as a small, auditable portfolio tool: clear inputs, explicit checks, structured findings, and reports that can be reviewed without exposing credentials.

## v1 Scope

Version 1 focuses on read-only AWS account analysis for IAM password policy, credential hygiene, root account exposure, MFA posture, and CloudTrail logging controls. The CLI will collect account metadata through boto3, evaluate checks locally, and write a JSON report suitable for review or CI artifacts.

## Module Boundaries

- `iam_analyzer.cli`: Typer command surface and user-facing options.
- `iam_analyzer.scanner`: boto3 session handling and scan orchestration.
- `iam_analyzer.checks`: individual CIS and hardening checks with explicit control metadata.
- `iam_analyzer.models`: Pydantic models for findings, scan metadata, summaries, and severities.
- `iam_analyzer.reporter`: report writers, starting with atomic JSON output.

## Credential Model

The analyzer never accepts AWS credentials as CLI arguments and should not log credential-bearing values. Authentication uses the standard boto3 credential provider chain, including environment variables, shared config files, AWS SSO, instance profiles, and other AWS-supported sources.
