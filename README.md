# NSA Zero Trust Implementation Guideline (ZIG) Phase One
## AWS GovCloud Compliance Checker

> ⚠️ **Status: Beta** - Checks are based on AWS CLI output and NSA ZIG Phase One requirements. Validate findings before using for formal compliance reporting. If you notice any issues, please [open an issue](https://github.com/mateoblack/aws-zig-phase-one/issues) for fastest resolution—fixes will be implemented within 24 hours until stable.

Assess your AWS GovCloud environment against the [NSA Zero Trust Implementation Guideline Phase One](https://media.defense.gov/2026/Jan/30/2003868308/-1/-1/0/CTR_ZIG_PHASE_ONE.PDF) requirements.

> **Scope:** This tool targets **AWS GovCloud (US)** regions. Service availability and endpoints are GovCloud-specific.

---

## What This Checks

Evaluates 36 activities across the 7 ZIG pillars using GovCloud-available services:

| Pillar | Checks |
|--------|--------|
| **User** | MFA enforcement, access key age, IAM policy hygiene |
| **Device** | SSM coverage, GuardDuty, Inspector, patch compliance |
| **Application** | ECR scanning, EKS configuration, Lambda policies |
| **Data** | S3 encryption, KMS rotation, public access blocks |
| **Network** | VPC Flow Logs, security groups, WAF, Network Firewall |
| **Automation** | Security Hub, Access Analyzer, EventBridge |
| **Visibility** | CloudTrail, CloudWatch, Config |

---

## Quick Start

```bash
# Download
curl -O https://github.com/mateoblack/aws-zig-phase-one/blob/main/aws-zig-phase-one-checker.sh
chmod +x aws-zig-phase-one-checker.sh

# Run against GovCloud
./aws-zig-phase-one-checker.sh --profile govcloud --region us-gov-west-1

# Generate JSON report
./aws-zig-phase-one-checker.sh --profile govcloud --region us-gov-west-1 --output json
```

**Requirements:** AWS CLI v2, jq, IAM read permissions ([see full list](#permissions))

### Recommendation 

>Single account? 

Run the script directly from your terminal.

>Multi-account org? 

Deploy the CDK stack to your security account, use StackSets to push ZigCheckerRole to members, and run org-wide assessments on a schedule.

---

## Understanding Results

| Severity | Meaning | Action |
|----------|---------|--------|
| `BLOCKER` | Critical security gap | Fix immediately |
| `HIGH` | Significant risk | Address this sprint |
| `MEDIUM` | Should improve | Plan remediation |
| `LOW` | Enhancement opportunity | Backlog |

See [examples/example-output.txt](./examples/example-output.txt) for sample output.

---

## Beyond Native AWS

Zero Trust spans identity, devices, data, and networks across your entire enterprise—not just cloud workloads. Some ZIG requirements need capabilities that complement any cloud provider's native tooling:

| Requirement | What AWS Provides | Ecosystem Solutions |
|-------------|-------------------|---------------------|
| **PAM / JIT Access** | IAM roles, Secrets Manager | [Sentinel](https://github.com/mateoblack/sentinel) (WIP), self research required |
| **Device Posture** | SSM for EC2 | AWS Verified Access, self research required |
| **Unified Policy** | IAM + SCPs + resource policies | [Sentinel](https://github.com/mateoblack/sentinel) (WIP) when enabled with aws orgs, self research required |
| **SIEM Correlation** | Security Hub | self research required|

**The ecosystem is maturing rapidly** Projects like [Sentinel](https://github.com/mateoblack/sentinel) provide policy-based credential issuance with approval workflows and break-glass—filling the PAM gap with patterns purpose-built for AWS. As of 01-FEB-2026 Sentinel is still in Work-In-Progress(WIP) status.

For detailed coverage analysis, see [aws-zig-phase-one-analysis.md](./aws-zig-phase-one-analysis.md).

---

## Permissions

Read-only access required:

<details>
<summary>IAM Policy (click to expand)</summary>

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

## References

- [NSA ZIG Phase One](https://media.defense.gov/2026/Jan/30/2003868308/-1/-1/0/CTR_ZIG_PHASE_ONE.PDF)
- [NSA ZIG Primer](https://media.defense.gov/2026/Jan/08/2003852320/-1/-1/0/CTR_ZERO_TRUST_IMPLEMENTATION_GUIDELINE_PRIMER.PDF)
- [AWS GovCloud Services](https://aws.amazon.com/govcloud-us/details/)
- [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)

---

## Contributing

PRs welcome. Include:
- ZIG activity reference (e.g., "Activity 1.3.1")
- AWS service/API affected
- GovCloud availability confirmation

## License

MIT
