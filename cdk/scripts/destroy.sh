#!/bin/bash
#
# destroy.sh - Tear down the ZIG Checker stack
#
# Usage: ./destroy.sh [--force]
#

set -euo pipefail

FORCE=false

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --force|-f)
            FORCE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo ""
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║  NSA ZIG Phase One Compliance Checker - Teardown                           ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Get instance info for confirmation
INSTANCE_ID=$(aws cloudformation describe-stacks \
    --stack-name "ZigCheckerStack" \
    --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue" \
    --output text 2>/dev/null || echo "")

if [[ -z "$INSTANCE_ID" || "$INSTANCE_ID" == "None" ]]; then
    echo "No stack found. Nothing to destroy."
    exit 0
fi

echo "This will destroy:"
echo "  - EC2 Instance: $INSTANCE_ID"
echo "  - Security Group"
echo "  - IAM Role"
echo ""

if [[ "$FORCE" != "true" ]]; then
    read -p "Are you sure? [y/N] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo "Destroying stack..."
npx cdk destroy --force

echo ""
echo "Stack destroyed."
echo ""
