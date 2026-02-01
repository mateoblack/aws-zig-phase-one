#!/bin/bash
#
# connect.sh - Connect to the ZIG Checker EC2 instance
#
# Usage: ./connect.sh [--wait]
#
# Options:
#   --wait    Wait for instance to be ready before connecting
#

set -euo pipefail

STACK_NAME="ZigCheckerStack"
WAIT_FOR_READY=false

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --wait)
            WAIT_FOR_READY=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Get instance IP from CloudFormation outputs
echo "Getting instance details from CloudFormation..."

PUBLIC_IP=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='PublicIp'].OutputValue" \
    --output text 2>/dev/null)

if [[ -z "$PUBLIC_IP" || "$PUBLIC_IP" == "None" ]]; then
    echo "ERROR: Could not find instance. Is the stack deployed?"
    echo ""
    echo "Deploy with:"
    echo "  cd cdk && npm install && cdk deploy -c myIp=\$(curl -s ifconfig.me)"
    exit 1
fi

INSTANCE_ID=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue" \
    --output text 2>/dev/null)

echo "Instance ID: $INSTANCE_ID"
echo "Public IP:   $PUBLIC_IP"
echo ""

# Wait for instance to be ready if requested
if [[ "$WAIT_FOR_READY" == "true" ]]; then
    echo "Waiting for instance to be running..."
    aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"
    
    echo "Waiting for instance status checks..."
    aws ec2 wait instance-status-ok --instance-ids "$INSTANCE_ID"
    
    echo "Waiting for SSH to be available..."
    for i in {1..30}; do
        if nc -z -w5 "$PUBLIC_IP" 22 2>/dev/null; then
            echo "SSH is ready!"
            break
        fi
        echo "  Attempt $i/30 - waiting..."
        sleep 5
    done
fi

echo ""
echo "Connecting to ZIG Checker instance..."
echo "==========================================="
echo ""

# Connect with reasonable SSH options
exec ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    -o ServerAliveInterval=60 \
    "ec2-user@$PUBLIC_IP"
