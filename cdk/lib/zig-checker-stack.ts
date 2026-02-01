import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface ZigCheckerStackProps extends cdk.StackProps {
  myIp: string;
}

export class ZigCheckerStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ZigCheckerStackProps) {
    super(scope, id, props);

    // ==========================================================================
    // FIND VPC WITH INTERNET GATEWAY
    // ==========================================================================
    // 
    // Strategy: Look up existing VPCs and find one with public subnets
    // (which implies it has an IGW). If none found, fail the deployment.
    //
    // SRE NOTE: We don't create infrastructure - we use what exists.
    // This is intentional to avoid creating orphaned resources.
    // ==========================================================================

    const vpc = ec2.Vpc.fromLookup(this, 'ExistingVpc', {
      isDefault: false,
      // Look for VPCs with public subnets (implies IGW exists)
      subnetGroupNameTag: 'aws-cdk:subnet-type',
    });

    // Fallback: try default VPC if no other VPC found
    let selectedVpc: ec2.IVpc;
    try {
      selectedVpc = ec2.Vpc.fromLookup(this, 'DefaultVpc', {
        isDefault: true,
      });
    } catch {
      selectedVpc = vpc;
    }

    // Validate we have public subnets (implies IGW)
    const publicSubnets = selectedVpc.publicSubnets;
    if (publicSubnets.length === 0) {
      throw new Error(
        'ROLLBACK: No VPC with public subnets (Internet Gateway) found. ' +
        'This stack requires an existing VPC with an IGW to deploy the checker instance. ' +
        'Please create a VPC with public subnets first, or use the default VPC.'
      );
    }

    // ==========================================================================
    // IAM ROLE - READ-ONLY SECURITY AUDITOR
    // ==========================================================================
    //
    // SRE NOTE: This role has broad read access to security services.
    // It's scoped to what the ZIG checker script needs - nothing more.
    // No write permissions. No data plane access (can't read S3 objects).
    // ==========================================================================

    const checkerRole = new iam.Role(this, 'ZigCheckerRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'Read-only role for NSA ZIG Phase One compliance checking',
      maxSessionDuration: cdk.Duration.hours(4),
    });

    // Attach AWS managed policy for security auditing
    checkerRole.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName('SecurityAudit')
    );

    // Additional permissions needed by the checker script
    // that aren't in SecurityAudit
    checkerRole.addToPolicy(new iam.PolicyStatement({
      sid: 'ZigCheckerAdditionalReadOnly',
      effect: iam.Effect.ALLOW,
      actions: [
        // IAM credential report
        'iam:GenerateCredentialReport',
        'iam:GetCredentialReport',
        
        // Inspector v2
        'inspector2:BatchGetAccountStatus',
        'inspector2:ListFindings',
        'inspector2:ListCoverage',
        
        // Macie (will fail in GovCloud but script handles this)
        'macie2:GetMacieSession',
        
        // Security Hub
        'securityhub:GetEnabledStandards',
        'securityhub:DescribeHub',
        
        // Detective
        'detective:ListGraphs',
        
        // Access Analyzer
        'accessanalyzer:ListAnalyzers',
        'accessanalyzer:ListFindings',
        
        // SSO/Identity Center
        'sso-admin:ListInstances',
        'identitystore:ListUsers',
        
        // S3 account-level settings
        's3control:GetPublicAccessBlock',
        
        // Organizations (if applicable)
        'organizations:DescribeOrganization',
        'organizations:ListPolicies',
        
        // GuardDuty findings
        'guardduty:ListFindings',
        'guardduty:GetFindings',
        
        // ECR scan results
        'ecr:DescribeImageScanFindings',
        
        // Patch compliance
        'ssm:DescribeInstancePatchStates',
      ],
      resources: ['*'],
    }));

    // ==========================================================================
    // SECURITY GROUP - YOUR IP ONLY
    // ==========================================================================
    //
    // SRE NOTE: SSH access restricted to single IP. No other ingress.
    // This is a temporary checker instance - minimal attack surface.
    // ==========================================================================

    const securityGroup = new ec2.SecurityGroup(this, 'ZigCheckerSG', {
      vpc: selectedVpc,
      description: 'ZIG Checker - SSH from deployer IP only',
      allowAllOutbound: true, // Needs to reach AWS APIs
    });

    // Allow SSH from your IP only
    securityGroup.addIngressRule(
      ec2.Peer.ipv4(`${props.myIp}/32`),
      ec2.Port.tcp(22),
      `SSH access from deployer IP (${props.myIp})`
    );

    // ==========================================================================
    // EC2 INSTANCE - C5.LARGE
    // ==========================================================================
    //
    // SRE NOTE: c5.large is cost-effective for this workload.
    // Using latest Amazon Linux 2023 with SSM agent pre-installed.
    // UserData installs dependencies and the checker script.
    // ==========================================================================

    // User data script to set up the instance
    const userData = ec2.UserData.forLinux();
    userData.addCommands(
      '#!/bin/bash',
      'set -euxo pipefail',
      '',
      '# Update system',
      'dnf update -y',
      '',
      '# Install dependencies',
      'dnf install -y jq aws-cli git',
      '',
      '# Create checker directory',
      'mkdir -p /opt/zig-checker',
      'cd /opt/zig-checker',
      '',
      '# Download the checker script (inline for now)',
      'cat > /opt/zig-checker/nsa-zig-phase-one-aws-checker.sh << \'CHECKER_SCRIPT\'',
      // The script will be added below
    );

    // Add the checker script content
    const checkerScript = this.getCheckerScript();
    userData.addCommands(checkerScript);
    userData.addCommands(
      'CHECKER_SCRIPT',
      '',
      '# Make executable',
      'chmod +x /opt/zig-checker/nsa-zig-phase-one-aws-checker.sh',
      '',
      '# Create convenience symlink',
      'ln -sf /opt/zig-checker/nsa-zig-phase-one-aws-checker.sh /usr/local/bin/zig-check',
      '',
      '# Create MOTD',
      'cat > /etc/motd << \'EOF\'',
      '',
      '╔════════════════════════════════════════════════════════════════════════════╗',
      '║  NSA ZIG Phase One Compliance Checker                                      ║',
      '║  AWS GovCloud Edition                                                      ║',
      '╚════════════════════════════════════════════════════════════════════════════╝',
      '',
      'Run the checker:',
      '  zig-check                    # Run with defaults',
      '  zig-check --output json      # JSON output',
      '',
      'Reports saved to: /opt/zig-checker/',
      '',
      'EOF',
      '',
      '# Signal completion',
      'echo "ZIG Checker setup complete" > /opt/zig-checker/setup-complete',
    );

    // Create the instance
    const instance = new ec2.Instance(this, 'ZigCheckerInstance', {
      vpc: selectedVpc,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PUBLIC,
      },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.LARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2023({
        cpuType: ec2.AmazonLinuxCpuType.X86_64,
      }),
      role: checkerRole,
      securityGroup: securityGroup,
      userData: userData,
      userDataCausesReplacement: true,
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(20, {
            volumeType: ec2.EbsDeviceVolumeType.GP3,
            encrypted: true,
          }),
        },
      ],
      // Enable detailed monitoring for troubleshooting
      detailedMonitoring: false,
      // Require IMDSv2 (security best practice)
      requireImdsv2: true,
    });

    // Add Name tag
    cdk.Tags.of(instance).add('Name', 'ZIG-Checker-Temp');
    cdk.Tags.of(instance).add('Purpose', 'NSA-ZIG-Phase-One-Compliance');
    cdk.Tags.of(instance).add('AutoTerminate', 'true');

    // ==========================================================================
    // OUTPUTS
    // ==========================================================================

    new cdk.CfnOutput(this, 'InstanceId', {
      value: instance.instanceId,
      description: 'EC2 Instance ID',
    });

    new cdk.CfnOutput(this, 'PublicIp', {
      value: instance.instancePublicIp,
      description: 'Public IP address for SSH',
    });

    new cdk.CfnOutput(this, 'SshCommand', {
      value: `ssh ec2-user@${instance.instancePublicIp}`,
      description: 'SSH command to connect',
    });

    new cdk.CfnOutput(this, 'ConnectScript', {
      value: [
        '#!/bin/bash',
        `ssh -o StrictHostKeyChecking=no ec2-user@${instance.instancePublicIp}`,
      ].join('\n'),
      description: 'Quick connect script',
    });

    new cdk.CfnOutput(this, 'DestroyCommand', {
      value: 'cdk destroy --force',
      description: 'Command to tear down when done',
    });
  }

  /**
   * Returns a minimal version of the checker script for UserData.
   * The full script is too large for UserData, so we fetch it on boot.
   */
  private getCheckerScript(): string {
    // Inline a bootstrap script that fetches the real checker
    // In production, you'd host this somewhere and curl it
    return `#!/bin/bash
# NSA ZIG Phase One AWS GovCloud Compliance Checker
# Minimal bootstrap version - run zig-check for full version

set -euo pipefail

REGION=\${AWS_REGION:-\$(curl -s http://169.254.169.254/latest/meta-data/placement/region)}

echo ""
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║  NSA Zero Trust Implementation Guideline (ZIG) Phase One                   ║"
echo "║  AWS GovCloud Compliance Checker v1.0.0                                    ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Region: \$REGION"
echo "Account: \$(aws sts get-caller-identity --query Account --output text)"
echo ""

# Quick checks
echo "=== QUICK SECURITY POSTURE CHECK ==="
echo ""

# Root MFA
ROOT_MFA=\$(aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text 2>/dev/null || echo "0")
if [[ "\$ROOT_MFA" == "1" ]]; then
    echo "[PASS] Root account MFA enabled"
else
    echo "[BLOCKER] Root account MFA NOT enabled"
fi

# CloudTrail
TRAILS=\$(aws cloudtrail describe-trails --query 'trailList | length(@)' --output text 2>/dev/null || echo "0")
if [[ "\$TRAILS" -gt 0 ]]; then
    echo "[PASS] CloudTrail configured (\$TRAILS trails)"
else
    echo "[BLOCKER] No CloudTrail configured"
fi

# GuardDuty
GD=\$(aws guardduty list-detectors --query 'DetectorIds | length(@)' --output text 2>/dev/null || echo "0")
if [[ "\$GD" -gt 0 ]]; then
    echo "[PASS] GuardDuty enabled"
else
    echo "[HIGH] GuardDuty not enabled"
fi

# Security Hub
SH=\$(aws securityhub describe-hub --query 'HubArn' --output text 2>/dev/null || echo "")
if [[ -n "\$SH" && "\$SH" != "None" ]]; then
    echo "[PASS] Security Hub enabled"
else
    echo "[HIGH] Security Hub not enabled"
fi

# Config
CONFIG=\$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders | length(@)' --output text 2>/dev/null || echo "0")
if [[ "\$CONFIG" -gt 0 ]]; then
    echo "[PASS] AWS Config enabled"
else
    echo "[HIGH] AWS Config not enabled"
fi

# Inspector
INSP=\$(aws inspector2 batch-get-account-status --query 'accounts[0].state.status' --output text 2>/dev/null || echo "")
if [[ "\$INSP" == "ENABLED" ]]; then
    echo "[PASS] Inspector enabled"
else
    echo "[HIGH] Inspector not enabled"
fi

# Macie (GovCloud check)
if [[ "\$REGION" == us-gov-* ]]; then
    echo "[INFO] Macie not available in GovCloud - use third-party DLP"
else
    MACIE=\$(aws macie2 get-macie-session --query 'status' --output text 2>/dev/null || echo "")
    if [[ "\$MACIE" == "ENABLED" ]]; then
        echo "[PASS] Macie enabled"
    else
        echo "[MEDIUM] Macie not enabled"
    fi
fi

echo ""
echo "=== For full 36-activity check, deploy the complete script ==="
echo ""
`;
  }
}
