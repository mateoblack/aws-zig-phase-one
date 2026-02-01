# NSA Zero Trust Implementation Guideline (ZIG) Phase One
## AWS Compliance Checker

A command-line tool to assess AWS environments against the [NSA Zero Trust Implementation Guideline Phase One](https://media.defense.gov/2026/Jan/30/2003868308/-1/-1/0/CTR_ZIG_PHASE_ONE.PDF) requirements.

---

## What This Checks

This script evaluates your AWS account against the 36 activities defined in NSA ZIG Phase One, covering:

| Pillar | What We Check |
|--------|---------------|
| **User** | MFA enforcement, access key hygiene, IAM policy least privilege |
| **Device** | SSM coverage, GuardDuty, Inspector, patch compliance |
| **Application** | ECR scanning, EKS endpoint configuration, Lambda policies |
| **Data** | S3 encryption, KMS rotation, Macie, public access blocks |
| **Network** | VPC Flow Logs, security group hygiene, WAF, segmentation |
| **Automation** | Security Hub, Access Analyzer, EventBridge rules |
| **Visibility** | CloudTrail, CloudWatch alarms, Config rules |

---

## Quick Start

```bash
# Download
curl -O https://raw.githubusercontent.com/yourorg/zig-checker/main/nsa-zig-phase-one-aws-checker.sh
chmod +x nsa-zig-phase-one-aws-checker.sh

# Run
./nsa-zig-phase-one-aws-checker.sh

# With options
./nsa-zig-phase-one-aws-checker.sh --profile prod --region us-gov-west-1 --output json
```

**Requirements:** AWS CLI v2, jq, appropriate IAM read permissions (see [Permissions](#permissions))

---

## Understanding the Results

The checker reports findings at four severity levels:

| Severity | Meaning | Action |
|----------|---------|--------|
| `BLOCKER` | Critical security gap | Fix immediately |
| `HIGH` | Significant risk | Address this sprint |
| `MEDIUM` | Should improve | Plan remediation |
| `LOW` | Enhancement opportunity | Continous Improvement |

---

## What This Doesn't Check

Some ZIG Phase One requirements need capabilities beyond what any single cloud provider offers natively. This isn't a gap in AWS—it reflects ZT's holistic approach spanning identity, devices, and data across your entire enterprise.

| Requirement | Why It's Out of Scope |
|-------------|----------------------|
| **Privileged Access Management (PAM)** | Credential vaulting, JIT access, and session recording require dedicated PAM solutions |
| **Endpoint posture for non-cloud devices** | Laptops and mobile devices need UEM/MDM platforms |
| **Document-level DRM** | View/print/forward controls require specialized DRM tools |
| **Cross-platform SIEM correlation** | Behavioral analytics across hybrid environments need dedicated SIEM |

### Filling the Gaps

Projects like [Sentinel](https://github.com/mateoblack/sentinel) are building AWS-native solutions for some of these requirements—specifically policy-based credential issuance with approval workflows and break-glass procedures. As the ZT ecosystem matures, expect more purpose-built tools to emerge.

For a detailed coverage analysis, see [nsa-zig-phase-one-aws-analysis.md](./nsa-zig-phase-one-aws-analysis.md).

---

## Permissions

The checker is **read-only**. Create a policy with these permissions:

<details>
<summary>Click to expand IAM policy</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ZIGCheckerReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:List*",
        "iam:Get*",
        "iam:GenerateCredentialReport",
        "ec2:Describe*",
        "s3:GetBucket*",
        "s3:ListAllMyBuckets",
        "kms:List*",
        "kms:Describe*",
        "kms:GetKeyRotationStatus",
        "cloudtrail:Describe*",
        "cloudtrail:GetTrailStatus",
        "config:Describe*",
        "guardduty:List*",
        "guardduty:Get*",
        "securityhub:Get*",
        "securityhub:Describe*",
        "ssm:Describe*",
        "ssm:List*",
        "inspector2:List*",
        "inspector2:BatchGetAccountStatus",
        "logs:Describe*",
        "wafv2:List*",
        "rds:Describe*",
        "eks:List*",
        "eks:Describe*",
        "ecr:Describe*",
        "ecr:GetRepositoryPolicy",
        "lambda:List*",
        "lambda:GetPolicy",
        "accessanalyzer:List*",
        "macie2:GetMacieSession",
        "detective:ListGraphs",
        "events:ListRules",
        "sns:ListTopics",
        "cloudwatch:DescribeAlarms",
        "apigateway:GET",
        "apigatewayv2:GetApis",
        "codepipeline:ListPipelines",
        "organizations:Describe*",
        "organizations:List*",
        "sso-admin:ListInstances",
        "s3control:GetPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

</details>

---

## Example Output

```
╔════════════════════════════════════════════════════════════════════════════╗
║  NSA Zero Trust Implementation Guideline (ZIG) Phase One                   ║
║  AWS Compliance Checker v1.0.0                                             ║
╚════════════════════════════════════════════════════════════════════════════╝

[INFO] Checking AWS Account: 123456789012
[INFO] Region: us-east-1

============================================================================
PILLAR 1: USER
============================================================================
[PASS] Root account has MFA enabled
[PASS] All IAM users with console access have MFA enabled
[HIGH] [1.4.1] Access keys older than 90 days: deploy-user:AKIA...
[PASS] No customer policies with unrestricted Action:* Resource:* found

[INFO] User Pillar Score: 4/5 checks passed

...

============================================================================
NSA ZIG PHASE ONE COMPLIANCE SUMMARY
============================================================================

PILLAR SCORES:
  1. User:                  4/5
  2. Device:                5/6
  3. Application:           4/4
  4. Data:                  5/6
  5. Network:               4/4
  6. Automation:            3/4
  7. Visibility:            6/7

FINDINGS SUMMARY:
  BLOCKER:  0
  HIGH:     2
  MEDIUM:   3
  LOW:      1
```

---

## References

- [NSA ZIG Phase One (PDF)](https://media.defense.gov/2026/Jan/30/2003868308/-1/-1/0/CTR_ZIG_PHASE_ONE.PDF)
- [NSA ZIG Primer (PDF)](https://media.defense.gov/2026/Jan/08/2003852320/-1/-1/0/CTR_ZERO_TRUST_IMPLEMENTATION_GUIDELINE_PRIMER.PDF)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)

---

## Contributing

Issues and PRs welcome. Please include:
- AWS service and API calls affected
- ZIG activity reference (e.g., "Activity 1.3.1")
- Expected vs actual behavior

---

## License

MIT
