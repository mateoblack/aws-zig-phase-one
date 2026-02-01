# ZIG Checker CDK Deployment

Deploy a temporary EC2 instance to run NSA ZIG Phase One compliance checks against your AWS GovCloud account.

## What This Creates

| Resource | Description |
|----------|-------------|
| **EC2 Instance** | c5.large with Amazon Linux 2023 |
| **Security Group** | SSH from your IP only (port 22) |
| **IAM Role** | Read-only security auditor permissions |

## Prerequisites

- AWS CLI configured with GovCloud credentials
- Node.js 18+
- CDK CLI (`npm install -g aws-cdk`)

## Quick Start

```bash
# 1. Deploy (auto-detects your IP)
./scripts/deploy.sh

# 2. Connect
./scripts/connect.sh --wait

# 3. Run the checker (on the instance)
zig-check

# 4. Destroy when done
./scripts/destroy.sh
```

## Manual Deployment

```bash
# Install dependencies
npm install

# Deploy with your IP
cdk deploy -c myIp=$(curl -s ifconfig.me)

# Or specify IP explicitly
cdk deploy -c myIp=203.0.113.50
```

## Security Notes

- **SSH access is restricted to your IP only** — no one else can connect
- **IAM role is read-only** — cannot modify any resources
- **IMDSv2 required** — protects against SSRF attacks
- **EBS encrypted** — data at rest protection
- **No key pair created** — use SSM

## Instance Setup

The instance comes pre-configured with:
- AWS CLI v2
- jq
- The ZIG checker script at `/opt/zig-checker/`
- Convenience command: `zig-check`

## Connecting Without SSH Key

use SSM Session Manager:

```bash
aws ssm start-session --target <instance-id>
```

## Troubleshooting

### "No VPC with public subnets found"

The stack requires a VPC with an Internet Gateway. Either:
1. Use the default VPC (has IGW by default)
2. Create a VPC with public subnets

### "Connection refused"

Wait for the instance to fully boot:
```bash
./scripts/connect.sh --wait
```

### Stack stuck in CREATE_IN_PROGRESS

Check CloudFormation events:
```bash
aws cloudformation describe-stack-events --stack-name ZigCheckerStack
```

## Cost

- **c5.large**: ~$0.085/hour (GovCloud pricing may vary)
- **EBS**: 20GB gp3 ~$1.60/month
- **Remember to destroy when done!**

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Your VPC (with IGW)                     │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                   Public Subnet                       │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │              EC2 Instance (c5.large)            │  │  │
│  │  │  ┌─────────────────────────────────────────────┐│  │  │
│  │  │  │  ZIG Checker Script                        ││  │  │
│  │  │  │  - Calls AWS APIs (read-only)              ││  │  │
│  │  │  │  - Generates compliance report             ││  │  │
│  │  │  └─────────────────────────────────────────────┘│  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │           ▲                                           │  │
│  │           │ SSH (port 22)                             │  │
│  │           │ YOUR IP ONLY                              │  │
│  └───────────┼───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
               │
        ┌──────┴──────┐
        │   Your IP   │
        │ (deployer)  │
        └─────────────┘
```

## Files

```
zig-checker-cdk/
├── bin/
│   └── app.ts           # CDK app entry point
├── lib/
│   └── zig-checker-stack.ts  # Main stack definition
├── scripts/
│   ├── deploy.sh        # Deploy the stack
│   ├── connect.sh       # SSH to instance
│   └── destroy.sh       # Tear down
├── cdk.json             # CDK configuration
├── package.json         # Dependencies
├── tsconfig.json        # TypeScript config
└── README.md            # This file
```
