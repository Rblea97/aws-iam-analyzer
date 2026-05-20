# Control Traceability

This matrix maps executable checks to evidence sources, evaluator boundaries, emitted statuses, known limitations, and tests. The executable source of truth is `src/iam_analyzer/checks/catalog.py`.

The repository does not include the authoritative CIS AWS Foundations Benchmark text. Control IDs and titles are tracked in the registry, but exact benchmark prose is `UNVERIFIED` from local files.

## Executable Checks

| Check ID | Control/source | Evidence source/API | Evaluator | Statuses emitted | Known limitations | Tests |
|---|---|---|---|---|---|---|
| `CIS-1.3` | Strict CIS v5.0.0: no root access key | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | Credential report root row evaluator | `PASS`, `FAIL`, `MANUAL_CHECK` | Depends on credential report availability and root row identity; no fictional root ARN fallback. | `tests/checks/test_iam.py::test_cis_1_3_*` |
| `CIS-1.5` | Strict CIS v5.0.0: root hardware MFA | `iam:GetAccountSummary`, `iam:ListVirtualMFADevices` | Root MFA summary plus assigned virtual MFA device check | `PASS`, `FAIL`, `MANUAL_CHECK` | Infers hardware MFA from account MFA enabled with no root virtual MFA device; AWS device-type nuance is limited by available IAM APIs. | `tests/checks/test_iam.py::test_cis_1_5_*` |
| `CIS-1.7` | Strict CIS v5.0.0: password minimum length | `iam:GetAccountPasswordPolicy` | Password policy `MinimumPasswordLength` comparison | `PASS`, `FAIL`, `MANUAL_CHECK` | No account password policy is treated as non-compliant. | `tests/checks/test_iam.py::test_cis_1_7_*` |
| `CIS-1.8` | Strict CIS v5.0.0: password reuse prevention | `iam:GetAccountPasswordPolicy` | Password policy `PasswordReusePrevention` comparison | `PASS`, `FAIL`, `MANUAL_CHECK` | No account password policy is treated as non-compliant. | `tests/checks/test_iam.py::test_cis_1_8_*` |
| `CIS-1.9` | Strict CIS v5.0.0: console users have MFA | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | Credential report console-password and MFA fields | `PASS`, `FAIL`, `MANUAL_CHECK` | Depends on credential report freshness and IAM field semantics. | `tests/checks/test_iam.py::test_cis_1_9_*` |
| `CIS-1.11` | Strict CIS v5.0.0: unused credentials removed | `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | Credential age evaluator for passwords and access keys | `PASS`, `FAIL`, `MANUAL_CHECK` | Uses credential report timestamps; never-used credentials fall back to creation/change dates where available. | `tests/checks/test_iam.py::test_cis_1_11_*` |
| `CIS-1.13` | Strict CIS v5.0.0: access keys rotated | `iam:ListUsers`, `iam:ListAccessKeys` | Active access key age evaluator | `PASS`, `FAIL`, `MANUAL_CHECK` | Uses key creation date, not last-used intent; root access keys are covered separately by `CIS-1.3`. | `tests/checks/test_iam.py::test_cis_1_13_*` |
| `CIS-1.14` | Strict CIS v5.0.0: user permissions through groups | `iam:ListUsers`, `iam:ListUserPolicies`, `iam:ListAttachedUserPolicies` | Direct user inline/attached policy detector | `PASS`, `FAIL`, `MANUAL_CHECK` | Does not judge whether direct grants are temporary or justified. | `tests/checks/test_iam.py::test_cis_1_14_*` |
| `CIS-1.15` | Strict CIS v5.0.0: no attached admin policies | `iam:ListPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListUsers`, `iam:ListUserPolicies`, `iam:GetUserPolicy`, `iam:ListGroups`, `iam:ListGroupPolicies`, `iam:GetGroupPolicy`, `iam:ListRoles`, `iam:ListRolePolicies`, `iam:GetRolePolicy` | Obvious-pattern policy document evaluator for managed and inline user/group/role policies | `PASS`, `FAIL`, `MANUAL_CHECK` | Not full effective-permissions analysis; does not model SCPs, boundaries, conditions, sessions, resource policies, or Access Analyzer. | `tests/checks/test_iam.py::test_cis_1_15_*`, `test_policy_document_evaluator_*` |
| `CIS-1.16` | Strict CIS v5.0.0: support role exists | `iam:ListEntitiesForPolicy` for `AWSSupportAccess` | AWS managed support policy role attachment check | `PASS`, `FAIL`, `MANUAL_CHECK` | Detects policy attachment, not incident process maturity or role trust correctness. | `tests/checks/test_iam.py::test_cis_1_16_*` |
| `CIS-1.21` | Strict CIS v5.0.0: restrict CloudShell full access | `iam:ListEntitiesForPolicy` for `AWSCloudShellFullAccess` | Managed policy attachment check across users, roles, groups | `PASS`, `FAIL`, `MANUAL_CHECK` | Flags any attachment; it does not evaluate business justification. | `tests/checks/test_iam.py::test_cis_1_21_*` |
| `CIS-3.1` | Strict CIS v5.0.0: multi-region CloudTrail enabled | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors` | Multi-region, global service event, logging status, and management event coverage evaluator | `PASS`, `FAIL`, `MANUAL_CHECK` | Evaluates visible trail metadata from the configured account/region; organization-wide CloudTrail coverage is not proven. | `tests/checks/test_logging.py::test_cis_3_1_*` |
| `CIS-3.2` | Strict CIS v5.0.0: log file validation enabled | `cloudtrail:DescribeTrails` | Trail metadata `LogFileValidationEnabled` evaluator | `PASS`, `FAIL`, `MANUAL_CHECK` | Fails when no trails are visible; does not verify delivered digest files. | `tests/checks/test_logging.py::test_cis_3_2_*` |
| `CIS-3.4` | Strict CIS v5.0.0: S3 access logging on CloudTrail bucket | `cloudtrail:DescribeTrails`, `s3:GetBucketLogging` | CloudTrail bucket discovery plus S3 logging config evaluator | `PASS`, `FAIL`, `MANUAL_CHECK` | Checks bucket logging configuration, not whether logs are delivered or retained. | `tests/checks/test_logging.py::test_cis_3_4_*` |
| `CIS-3.5` | Strict CIS v5.0.0: CloudTrail KMS encryption | `cloudtrail:DescribeTrails` | Trail metadata `KmsKeyId` presence evaluator | `PASS`, `FAIL`, `MANUAL_CHECK` | Checks a KMS key reference, not key policy strength or key rotation posture. | `tests/checks/test_logging.py::test_cis_3_5_*` |
| `EHC-CT-1` | Enterprise hardening: CloudWatch Logs integration | `cloudtrail:DescribeTrails` | Trail metadata CloudWatch Logs log group ARN evaluator | `PASS`, `FAIL`, `MANUAL_CHECK` | Hardening check only; not a strict CIS finding. Does not validate CloudWatch log delivery. | `tests/checks/test_logging.py::test_ehc_ct_1_*` |
| `EHC-CT-2` | Enterprise hardening: CloudTrail bucket not public | `cloudtrail:DescribeTrails`, `s3:GetBucketPolicyStatus`, `s3:GetBucketPublicAccessBlock` | S3 policy status and block public access evaluator | `PASS`, `FAIL`, `MANUAL_CHECK` | Hardening check only; does not parse every bucket policy statement. | `tests/checks/test_logging.py::test_ehc_ct_2_*` |
| `EHC-CT-3` | Enterprise hardening: management event coverage hardened | `cloudtrail:DescribeTrails`, `cloudtrail:GetEventSelectors` | Event selector and advanced event selector evaluator | `PASS`, `FAIL`, `MANUAL_CHECK` | Hardening check only; evaluates management event selectors visible to the current account/region. | `tests/checks/test_logging.py::test_ehc_ct_3_*` |

## Manual-Check Behavior

`MANUAL_CHECK` is an evaluation status. It does not reduce severity. A high-risk control can remain `HIGH` while reporting `MANUAL_CHECK` when evidence is unavailable, malformed, or blocked by permissions.

Schema version `1.1` exposes status counts separately from severity counts so manual checks remain visible in terminal and JSON summaries.

## Registered Roadmap Controls

These strict CIS IDs are registered but not executable: `CIS-1.4`, `CIS-1.6`, `CIS-1.10`, `CIS-1.12`, `CIS-1.17`, `CIS-1.18`, `CIS-1.19`, and `CIS-1.20`.

Roadmap controls have no emitted statuses and no scan output until implementation adds evidence APIs, tests, catalog entries, docs, and scanner policy permissions.
