# NSA Zero Trust Implementation Guideline Phase One
## AWS GovCloud (US) Coverage Analysis

**Document Version:** 1.1  
**Date:** February 2026  
**Reference:** NSA CTR_ZIG_PHASE_ONE (U/OO/107297-26)  
**Scope:** AWS GovCloud (US-East) and AWS GovCloud (US-West) Regions

---

## About This Document

This analysis evaluates NSA ZIG Phase One requirements specifically against **AWS GovCloud (US)** service availability. GovCloud is an isolated AWS partition designed for U.S. government workloads requiring FedRAMP High, ITAR, and DoD IL2-IL5 compliance.

Some AWS services available in commercial regions are not yet available in GovCloud. This document accounts for those differences.

> **Reference:** [AWS GovCloud Services](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/using-services.html)

---

## Executive Summary

The NSA ZIG Phase One defines **36 activities** across **7 pillars**. In AWS GovCloud (US):

| Coverage Level | Activity Count | Percentage |
|----------------|----------------|------------|
| ✅ Full Native Coverage | 18 | 50% |
| ⚠️ Partial Coverage | 12 | 33% |
| ❌ Requires 3rd Party | 6 | 17% |

Key GovCloud-specific gaps:
- **Amazon Macie** is NOT available in GovCloud — data classification requires alternatives
- **IAM Access Analyzer policy generation** is not supported in GovCloud
- Some Security Hub integrations have limited availability

---

## GovCloud Service Availability Summary

### Services AVAILABLE in GovCloud (US)

| Service | ZIG Activities Supported |
|---------|-------------------------|
| IAM, IAM Identity Center | 1.3.1, 1.5.1, 1.7.1 |
| GuardDuty | 2.7.1, 7.2.1, 7.5.1 |
| Security Hub | 6.5.2, 7.2.4 |
| Inspector (v2) | 2.5.1, 3.3.2 |
| CloudTrail | 7.1.2 |
| Config | 7.3.1 |
| Systems Manager | 2.1.2, 2.5.1, 2.6.1, 2.6.2 |
| KMS | 4.5.1 |
| WAF | 5.4.1 |
| Detective | 7.5.1 |
| Verified Access | 2.4.1, 2.7.1 |
| EventBridge | 6.7.1 |
| Step Functions | 6.5.2 |
| Secrets Manager | 1.4.1 |

### Services NOT AVAILABLE in GovCloud (US)

| Service | Impact | Alternative |
|---------|--------|-------------|
| **Amazon Macie** | Cannot auto-classify S3 data (4.3.1, 4.6.1) | Trellix DLP, Forcepoint, manual classification |
| **IAM Access Analyzer policy generation** | Cannot auto-generate least-privilege policies | Manual policy review, Cloud Custodian |

---

## Coverage Matrix by Pillar (GovCloud-Adjusted)

### Pillar 1: User (5 Activities)

| Activity | Description | GovCloud Coverage | Notes |
|----------|-------------|-------------------|-------|
| 1.3.1 | MFA and IdP | ✅ **Full** | IAM Identity Center available in GovCloud |
| 1.4.1 | PAM Part 1 | ⚠️ **Partial** | Secrets Manager available; no full PAM vault |
| 1.5.1 | Identity Lifecycle | ⚠️ **Partial** | IAM Identity Center lifecycle available |
| 1.7.1 | Deny by Default | ✅ **Full** | IAM, SCPs, resource policies all available |
| 1.8.1 | Continuous Auth | ⚠️ **Partial** | Session policies only; no behavioral auth |

**GovCloud Notes:**
- IAM Identity Center (SSO) is available in GovCloud
- MFA devices supported: hardware TOTP, virtual MFA apps
- Cannot delegate access between GovCloud and commercial accounts

---

### Pillar 2: Device (6 Activities)

| Activity | Description | GovCloud Coverage | Notes |
|----------|-------------|-------------------|-------|
| 2.1.2 | Device Inventory | ✅ **Full** | SSM Fleet Manager available |
| 2.4.1 | Deny Device by Default | ✅ **Full** | Security Groups, NACLs, Verified Access |
| 2.5.1 | Vulnerability/Patch | ✅ **Full** | SSM Patch Manager, Inspector v2 available |
| 2.6.1 | UEM/MDM | ⚠️ **Partial** | SSM for EC2 only; no mobile MDM |
| 2.6.2 | EDM Part 1 | ⚠️ **Partial** | SSM State Manager available |
| 2.7.1 | EDR/C2C | ⚠️ **Partial** | GuardDuty available; Verified Access for posture |

**GovCloud Notes:**
- AWS Verified Access is available in GovCloud for device trust
- GuardDuty Runtime Monitoring available for EKS/ECS/EC2

---

### Pillar 3: Application and Workload (6 Activities)

| Activity | Description | GovCloud Coverage | Notes |
|----------|-------------|-------------------|-------|
| 3.2.1 | DevSecOps Part 1 | ✅ **Full** | CodePipeline, CodeBuild available |
| 3.2.2 | DevSecOps Part 2 | ⚠️ **Partial** | CodeGuru not available in GovCloud |
| 3.3.1 | Approved Binaries | ⚠️ **Partial** | ECR, Signer available; no binary allow-listing |
| 3.3.2 | Vuln Mgmt Part 1 | ✅ **Full** | Inspector v2 available |
| 3.4.1 | Resource Auth Part 1 | ✅ **Full** | Resource policies, VPC endpoints |
| 3.4.3 | SDC Auth Part 1 | ✅ **Full** | Lambda, EKS IRSA available |

**GovCloud Notes:**
- Amazon ECR is available with image scanning
- AWS Signer available for code signing
- CodeGuru Reviewer/Profiler NOT available in GovCloud

---

### Pillar 4: Data (6 Activities)

| Activity | Description | GovCloud Coverage | Notes |
|----------|-------------|-------------------|-------|
| 4.2.1 | Data Tagging Standards | ✅ **Full** | Resource tags, Tag Editor |
| 4.2.2 | Interoperability | ✅ **Full** | S3 Object Lambda, EventBridge |
| 4.3.1 | Data Classification | ❌ **Gap** | **Macie NOT available in GovCloud** |
| 4.4.3 | File Activity Monitoring | ✅ **Full** | S3 access logs, CloudTrail data events |
| 4.5.1 | DRM Part 1 | ⚠️ **Partial** | S3 Object Lock, KMS; no document DRM |
| 4.6.1 | DLP Enforcement | ❌ **Gap** | **Macie NOT available**; S3 Block Public Access only |

**GovCloud Notes:**
- **CRITICAL:** Amazon Macie is NOT available in GovCloud regions
- Data classification must use third-party tools or manual processes
- Consider: Trellix DLP, Forcepoint, McAfee, or custom Lambda-based classification

---

### Pillar 5: Network and Environment (4 Activities)

| Activity | Description | GovCloud Coverage | Notes |
|----------|-------------|-------------------|-------|
| 5.1.2 | Granular Access Rules | ✅ **Full** | Security Groups, NACLs, VPC Flow Logs |
| 5.2.2 | SDN Infrastructure | ✅ **Full** | VPC, Transit Gateway, PrivateLink |
| 5.3.1 | Macro-Segmentation | ✅ **Full** | VPCs, subnets, Network Firewall |
| 5.4.1 | Micro-Segmentation | ⚠️ **Partial** | Security groups; Network Firewall available |

**GovCloud Notes:**
- AWS Network Firewall is available in GovCloud
- Transit Gateway available for multi-VPC architectures
- VPC Flow Logs support all formats

---

### Pillar 6: Automation and Orchestration (4 Activities)

| Activity | Description | GovCloud Coverage | Notes |
|----------|-------------|-------------------|-------|
| 6.1.2 | Access Profile/PDP | ⚠️ **Partial** | IAM + Verified Access; no unified PDP |
| 6.5.2 | SOAR | ⚠️ **Partial** | Security Hub + EventBridge; Step Functions |
| 6.6.2 | API Standardization | ✅ **Full** | API Gateway available |
| 6.7.1 | Workflow Enrichment | ⚠️ **Partial** | Step Functions, EventBridge available |

**GovCloud Notes:**
- Security Hub available with some integration limitations
- Amazon Verified Permissions available for fine-grained authorization
- Step Functions available for workflow automation

---

### Pillar 7: Visibility and Analytics (5 Activities)

| Activity | Description | GovCloud Coverage | Notes |
|----------|-------------|-------------------|-------|
| 7.1.2 | Log Parsing | ✅ **Full** | CloudWatch Logs Insights |
| 7.2.1 | Threat Alerting | ✅ **Full** | CloudWatch Alarms, GuardDuty |
| 7.2.4 | Asset/Alert Correlation | ⚠️ **Partial** | Security Hub; Detective available |
| 7.3.1 | Analytics Tools | ✅ **Full** | CloudWatch, Config, Athena |
| 7.5.1 | CTI Part 1 | ⚠️ **Partial** | GuardDuty threat feeds; Detective available |

**GovCloud Notes:**
- Amazon Detective is available in GovCloud
- Security Hub cross-region aggregation limited to GovCloud regions only
- Amazon Security Lake available for centralized security data

---

## GovCloud-Specific Recommendations

### For Data Classification (Macie Gap)

Since Macie is not available in GovCloud, consider:

| Option | Pros | Cons |
|--------|------|------|
| **Custom Lambda + Comprehend** | AWS-native, serverless | Requires development |
| **Manual Classification** | No tools needed | Doesn't scale |

### For Policy Generation (Access Analyzer Gap)

Since IAM Access Analyzer policy generation is not supported:

| Option | Description |
|--------|-------------|
| **Manual IAM review** | Quarterly access reviews |

---

## Third-Party Solutions for GovCloud

These solutions are FedRAMP authorized and commonly used in GovCloud:

| Gap Area | FedRAMP Authorized Options |
|----------|---------------------------|
| PAM | self research required |
| UEM/MDM | self research required |
| DLP/Classification | self research required |
| SIEM | self research required |
| SOAR | self research required |

---

## Ecosystem Projects

The ecosystem is maturing rapidly projects like [Sentinel](https://github.com/mateoblack/sentinel) provide policy-based credential issuance with approval workflows and break-glass—filling the PAM gap with patterns purpose-built for AWS. As of 01-FEB-2026 Sentinel is still in Work-In-Progress status.
---

## Running the Compliance Checker

The checker script accounts for GovCloud service availability:

```bash
# For GovCloud West
./aws-zig-phase-one-checker.sh --profile govcloud --region us-gov-west-1

# For GovCloud East  
./aws-zig-phase-one-checker.sh --profile govcloud --region us-gov-east-1

# Generate JSON report
./aws-zig-phase-one-checker.sh --profile govcloud --region us-gov-west-1 --output json
```

**Note:** The checker will skip Macie checks in GovCloud regions and flag them as requiring third-party solutions.

---

## References

- [AWS GovCloud Services List](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/using-services.html)
- [NSA ZIG Phase One (PDF)](https://media.defense.gov/2026/Jan/30/2003868308/-1/-1/0/CTR_ZIG_PHASE_ONE.PDF)
- [Security Hub GovCloud Limitations](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/govcloud-ash.html)
- [FedRAMP Marketplace](https://marketplace.fedramp.gov/)
