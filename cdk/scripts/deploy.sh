#!/bin/bash
#
# deploy.sh - Deploy the ZIG Checker stack
#
# Usage: ./deploy.sh [--ip <your-ip>]
#
# If no IP provided, auto-detects your public IP.
#

set -euo pipefail

MY_IP=""

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --ip)
            MY_IP="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Auto-detect IP if not provided
if [[ -z "$MY_IP" ]]; then
    echo "Detecting your public IP..."
    MY_IP=$(curl -s --max-time 5 ifconfig.me || curl -s --max-time 5 icanhazip.com || curl -s --max-time 5 api.ipify.org)
    
    if [[ -z "$MY_IP" ]]; then
        echo "ERROR: Could not detect your public IP"
        echo "Please provide it manually: ./deploy.sh --ip YOUR_IP"
        exit 1
    fi
fi

echo ""
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║  NSA ZIG Phase One Compliance Checker - Deployment                         ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Your IP: $MY_IP"
echo "Region:  ${AWS_REGION:-${CDK_DEFAULT_REGION:-us-gov-west-1}}"
echo ""

# Confirm
read -p "Deploy instance with SSH access from $MY_IP? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Install dependencies if needed
if [[ ! -d "node_modules" ]]; then
    echo "Installing dependencies..."
    npm install
fi

# Build TypeScript
echo "Building..."
npm run build

# Bootstrap CDK if needed (first time only)
if ! aws cloudformation describe-stacks --stack-name CDKToolkit &>/dev/null; then
    echo "Bootstrapping CDK..."
    npx cdk bootstrap
fi

# Deploy
echo "Deploying..."
npx cdk deploy -c myIp="$MY_IP" --require-approval never

echo ""
echo "==========================================="
echo "Deployment complete!"
echo ""
echo "Connect with:"
echo "  ./scripts/connect.sh"
echo ""
echo "Or wait for full setup:"
echo "  ./scripts/connect.sh --wait"
echo ""
echo "When done, destroy with:"
echo "  ./scripts/destroy.sh"
echo ""
