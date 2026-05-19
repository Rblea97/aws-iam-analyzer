# Controls

This page documents the controls registered for `aws-iam-analyzer` and the subset currently evaluated by the scanner orchestrator.

`Strict CIS` controls map to CIS AWS Foundations Benchmark v5.0.0 IDs. `Enterprise hardening` controls are useful CloudTrail checks that are intentionally not reported as CIS findings.

## Currently Evaluated Controls

| ID | Title | Category | Evidence APIs | Severity | Remediation summary |
| --- | --- | --- | --- | --- | --- |
| CIS-1.3 | Ensure no root user account access key exists | Strict CIS | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | HIGH | Delete root access keys and use IAM roles or users for operational access. |
| CIS-1.5 | Ensure hardware MFA is enabled for the root user account | Strict CIS | `iam:GetAccountSummary`, `iam:ListVirtualMFADevices` | HIGH | Enable a hardware MFA device for the root user account. |
| CIS-1.7 | Ensure IAM password policy requires minimum length of 14 or greater | Strict CIS | `iam:GetAccountPasswordPolicy` | MEDIUM | Set the IAM account password policy minimum length to 14 or greater. |
| CIS-1.8 | Ensure IAM password policy prevents password reuse | Strict CIS | `iam:GetAccountPasswordPolicy` | MEDIUM | Set IAM password reuse prevention to at least 24 remembered passwords. |
| CIS-1.9 | Ensure MFA is enabled for all IAM users that have a console password | Strict CIS | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | HIGH | Enable MFA for every IAM user with console access. |
| CIS-1.11 | Ensure credentials unused for 45 days or more are removed | Strict CIS | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | MEDIUM | Remove or disable IAM credentials unused for 45 days or more. |
| CIS-1.13 | Ensure access keys are rotated every 90 days or less | Strict CIS | `iam:ListUsers`, `iam:ListAccessKeys` | HIGH | Rotate active IAM access keys older than 90 days. |
| CIS-1.14 | Ensure IAM users receive permissions only through groups | Strict CIS | `iam:ListUsers`, `iam:ListUserPolicies`, `iam:ListAttachedUserPolicies` | MEDIUM | Remove direct user policies and grant permissions through IAM groups. |
| CIS-1.15 | Ensure IAM policies that allow full administrative privileges are not attached | Strict CIS | `iam:ListPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion` | HIGH | Detach or replace policies that allow `Action: "*"` on `Resource: "*"`. |
| CIS-1.16 | Ensure a support role has been created to manage incidents with AWS Support | Strict CIS | `iam:ListEntitiesForPolicy` | LOW | Create an incident response role with the `AWSSupportAccess` policy. |
| CIS-1.21 | Ensure access to AWSCloudShellFullAccess is restricted | Strict CIS | `iam:ListEntitiesForPolicy` | MEDIUM | Detach `AWSCloudShellFullAccess` from identities that do not require it. |
| CIS-3.1 | Ensure CloudTrail is enabled and configured with at least one multi-Region trail | Strict CIS | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors` | HIGH | Configure a multi-Region CloudTrail trail that logs global service events and read/write management events. |
| CIS-3.2 | Ensure CloudTrail log file validation is enabled | Strict CIS | `cloudtrail:DescribeTrails` | MEDIUM | Enable CloudTrail log file validation on every trail. |
| CIS-3.4 | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket | Strict CIS | `cloudtrail:DescribeTrails`, `s3:GetBucketLogging` | MEDIUM | Enable S3 server access logging on every bucket that stores CloudTrail logs. |
| CIS-3.5 | Ensure CloudTrail logs are encrypted at rest using KMS keys | Strict CIS | `cloudtrail:DescribeTrails` | MEDIUM | Configure CloudTrail to encrypt log files with an AWS KMS key. |
| EHC-CT-1 | Ensure CloudTrail is integrated with CloudWatch Logs | Enterprise hardening | `cloudtrail:DescribeTrails` | LOW | Send CloudTrail events to CloudWatch Logs for operational monitoring. |
| EHC-CT-2 | Ensure the CloudTrail S3 bucket is not publicly accessible | Enterprise hardening | `cloudtrail:DescribeTrails`, `s3:GetBucketPolicyStatus`, `s3:GetBucketPublicAccessBlock` | HIGH | Remove public access from the CloudTrail log bucket and enable S3 Block Public Access. |
| EHC-CT-3 | Ensure CloudTrail management event coverage is hardened | Enterprise hardening | `cloudtrail:DescribeTrails`, `cloudtrail:GetEventSelectors` | MEDIUM | Include read and write management events without excluded management event sources. |

## Registered Strict CIS Controls Not Yet Evaluated

The following CIS v5.0.0 controls are registered in code for model validation and roadmap continuity, but they are not included in the executable `CHECK_SPECS` catalog yet. They should not appear in scan output until a dedicated check function and tests are added. The evidence APIs listed here are planned implementation inputs and are not part of the scanner IAM policy until the checks are implemented.

| ID | Title | Category | Evidence APIs | Severity | Remediation summary |
| --- | --- | --- | --- | --- | --- |
| CIS-1.4 | Ensure MFA is enabled for the root user account | Strict CIS | Planned: `iam:GetAccountSummary` | HIGH | Enable MFA for the root user account before reporting this control. |
| CIS-1.6 | Eliminate use of the root user for administrative and daily tasks | Strict CIS | Planned: `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | HIGH | Remove routine root usage and reserve root for account-only break-glass tasks. |
| CIS-1.10 | Do not create access keys during initial setup for IAM users with a console password | Strict CIS | Planned: `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | MEDIUM | Remove access keys created during initial IAM user setup for console users. |
| CIS-1.12 | Ensure there is only one active access key for any single IAM user | Strict CIS | Planned: `iam:ListUsers`, `iam:ListAccessKeys` | MEDIUM | Deactivate or delete excess active access keys so each IAM user has no more than one active key. |
| CIS-1.17 | Ensure IAM instance roles are used for AWS resource access from instances | Strict CIS | Planned: `ec2:DescribeRegions`, `ec2:DescribeInstances`, `iam:GetInstanceProfile` | MEDIUM | Attach IAM instance profiles to EC2 workloads instead of distributing long-lived credentials. |
| CIS-1.18 | Ensure that all expired SSL/TLS certificates stored in IAM are removed | Strict CIS | Planned: `iam:ListServerCertificates`, `iam:GetServerCertificate` | LOW | Delete expired IAM server certificates or migrate certificate management to AWS Certificate Manager. |
| CIS-1.19 | Ensure that IAM External Access Analyzer is enabled for all regions | Strict CIS | Planned: `ec2:DescribeRegions`, `access-analyzer:ListAnalyzers` | MEDIUM | Enable IAM Access Analyzer in every enabled AWS Region. |
| CIS-1.20 | Ensure IAM users are managed centrally via identity federation or AWS Organizations | Strict CIS | Planned: `iam:ListUsers`, `organizations:DescribeOrganization` | MEDIUM | Manage human access through a central identity provider or AWS Organizations rather than standalone IAM users. |
