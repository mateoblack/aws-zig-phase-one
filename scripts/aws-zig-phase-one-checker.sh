#!/opt/homebrew/bin/bash
#
# NSA Zero Trust Implementation Guideline (ZIG) Phase One - AWS Compliance Checker
# Version: 1.1
# Date: January 2026
#
# PURPOSE: Assess AWS GovCloud (US) environments against NSA ZIG Phase One requirements
# SCOPE: 36 activities across 7 pillars (User, Device, Application/Workload, Data, 
#        Network/Environment, Automation/Orchestration, Visibility/Analytics)
#
# GOVCLOUD NOTE: This script accounts for GovCloud service availability differences.
#                Macie is NOT available in GovCloud - the script will flag this appropriately.
#
# USAGE: ./nsa-zig-phase-one-aws-checker.sh [--profile <aws-profile>] [--region <region>] [--output <json|text>]
#
# GOVCLOUD REGIONS:
#   us-gov-west-1 (GovCloud West)
#   us-gov-east-1 (GovCloud East)
#
# OUTPUT SEVERITY LEVELS:
#   BLOCKER  - Will cause incidents / critical security gap
#   HIGH     - Significant risk, needs immediate attention
#   MEDIUM   - Should be addressed in near term
#   LOW      - Improvement opportunity
#   PASS     - Requirement met
#   N/A      - Not applicable or cannot be checked via CLI
#
# ============================================================================
# SRE REVIEW NOTES:
# ============================================================================
# OPERATIONAL HAZARDS IDENTIFIED:
# - Rate limiting: AWS API calls are rate limited. Script uses delays where needed.
# - Blast radius: Read-only checks, no modifications to AWS resources.
# - Timeout: Some checks may timeout on large environments. Default timeout: 300s
# - Dependencies: Requires aws-cli v2, jq, and appropriate IAM permissions.
#
# PERMISSIONS REQUIRED (Least Privilege):
# - iam:List*, iam:Get*, iam:GenerateCredentialReport
# - ec2:Describe*
# - s3:GetBucketEncryption, s3:GetBucketLogging, s3:GetBucketPolicy, s3:ListAllMyBuckets
# - kms:List*, kms:Describe*, kms:GetKeyPolicy
# - cloudtrail:Describe*, cloudtrail:GetTrailStatus
# - config:Describe*
# - guardduty:List*, guardduty:Get*
# - securityhub:Get*, securityhub:Describe*
# - organizations:Describe*, organizations:List*
# - ssm:Describe*, ssm:List*
# - wafv2:List*, wafv2:Get*
# - elasticloadbalancing:Describe*
# - rds:Describe*
# - logs:Describe*, logs:FilterLogEvents
# - sns:List*, sns:Get*
# - sqs:List*, sqs:Get*
# - lambda:List*, lambda:Get*
# - eks:List*, eks:Describe*
# - ecr:Describe*, ecr:Get*
# - inspector2:List*, inspector2:Get*
# - access-analyzer:List*
# ============================================================================

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================
SCRIPT_VERSION="1.0.0"
TIMEOUT_SECONDS=300
RATE_LIMIT_DELAY=0.2  # seconds between API calls to avoid throttling
OUTPUT_FORMAT="${OUTPUT_FORMAT:-text}"
AWS_PROFILE="${AWS_PROFILE:-default}"
AWS_REGION="${AWS_REGION:-us-gov-west-1}"  # Default to GovCloud West
REPORT_FILE="zig-phase-one-report-$(date +%Y%m%d-%H%M%S).json"
DEBUG="${DEBUG:-false}"

# Color codes for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            AWS_PROFILE="$2"
            shift 2
            ;;
        --region)
            AWS_REGION="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --debug)
            DEBUG="true"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--profile <aws-profile>] [--region <region>] [--output <json|text>] [--debug]"
            echo ""
            echo "NSA Zero Trust Implementation Guideline Phase One - AWS Compliance Checker"
            echo ""
            echo "Options:"
            echo "  --profile    AWS CLI profile to use (default: default)"
            echo "  --region     AWS region to check (default: us-east-1)"
            echo "  --output     Output format: json or text (default: text)"
            echo "  --debug      Enable debug mode (show all AWS commands and errors)"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

export AWS_PROFILE AWS_REGION

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
declare -a FINDINGS=()
declare -A PILLAR_SCORES

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_finding() {
    local severity="$1"
    local activity="$2"
    local message="$3"
    local remediation="${4:-}"
    
    case $severity in
        BLOCKER)
            echo -e "${RED}[BLOCKER]${NC} [$activity] $message"
            ;;
        HIGH)
            echo -e "${RED}[HIGH]${NC} [$activity] $message"
            ;;
        MEDIUM)
            echo -e "${YELLOW}[MEDIUM]${NC} [$activity] $message"
            ;;
        LOW)
            echo -e "${CYAN}[LOW]${NC} [$activity] $message"
            ;;
    esac
    
    FINDINGS+=("{\"severity\":\"$severity\",\"activity\":\"$activity\",\"message\":\"$message\",\"remediation\":\"$remediation\"}")
}

aws_cmd() {
    # Wrapper for AWS CLI with rate limiting and error handling
    sleep "$RATE_LIMIT_DELAY"
    # Use gtimeout on macOS (from coreutils), timeout on Linux
    local timeout_cmd="timeout"
    command -v gtimeout &>/dev/null && timeout_cmd="gtimeout"
    
    if [[ "$DEBUG" == "true" ]]; then
        echo -e "${CYAN}[DEBUG] Running: aws $*${NC}" >&2
        local result
        local exit_code
        result=$($timeout_cmd "$TIMEOUT_SECONDS" aws "$@" 2>&1) && exit_code=$? || exit_code=$?
        if [[ $exit_code -ne 0 ]]; then
            echo -e "${RED}[DEBUG] Command failed (exit $exit_code): $result${NC}" >&2
            echo ""
        else
            echo -e "${GREEN}[DEBUG] Command succeeded${NC}" >&2
            echo "$result"
        fi
    else
        $timeout_cmd "$TIMEOUT_SECONDS" aws "$@" 2>/dev/null || echo ""
    fi
}

check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo "ERROR: Required dependency '$1' not found. Please install it."
        exit 1
    fi
}

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================
preflight_checks() {
    log_info "Running pre-flight checks..."
    
    check_dependency "aws"
    check_dependency "jq"
    
    # Verify AWS credentials
    if ! aws sts get-caller-identity &>/dev/null; then
        echo "ERROR: AWS credentials not configured or invalid"
        exit 1
    fi
    
    ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
    log_info "Checking AWS Account: $ACCOUNT_ID"
    log_info "Region: $AWS_REGION"
    log_info "Profile: $AWS_PROFILE"
    echo ""
}

# ============================================================================
# PILLAR 1: USER
# Activity 1.3.1 - Organizational MFA and IdP
# Activity 1.4.1 - Privileged Access Management
# Activity 1.5.1 - Identity Lifecycle Management
# Activity 1.7.1 - Deny User by Default Policy
# Activity 1.8.1 - Single Authentication
# ============================================================================

check_pillar_1_user() {
    echo ""
    echo "============================================================================"
    echo "PILLAR 1: USER"
    echo "============================================================================"
    
    local pass_count=0
    local total_checks=0
    
    # -------------------------------------------------------------------------
    # Activity 1.3.1 - MFA Enforcement
    # -------------------------------------------------------------------------
    log_info "Checking Activity 1.3.1 - MFA and IdP..."
    
    # Check if MFA is enabled for root account
    ((total_checks++)) || true || true
    local root_mfa
    root_mfa=$(aws_cmd iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text)
    if [[ "$root_mfa" == "1" ]]; then
        log_pass "Root account has MFA enabled"
        ((pass_count++)) || true || true
    else
        log_finding "BLOCKER" "1.3.1" "Root account does NOT have MFA enabled" \
            "Enable MFA on root account immediately: aws iam create-virtual-mfa-device"
    fi
    
    # Check for IAM users without MFA
    ((total_checks++)) || true
    local users_without_mfa=()
    # Generate credential report
    aws_cmd iam generate-credential-report >/dev/null
    sleep 3  # Wait for report generation
    local cred_report
    cred_report=$(aws_cmd iam get-credential-report --query 'Content' --output text 2>/dev/null | base64 -d 2>/dev/null || echo "")
    
    if [[ -n "$cred_report" ]]; then
        while IFS=, read -r user arn creation_date password_enabled password_last_used password_last_changed password_next_rotation mfa_active access_key_1 access_key_2 rest; do
            # Skip header and root
            [[ "$user" == "user" || "$user" == "<root_account>" ]] && continue
            if [[ "$password_enabled" == "true" && "$mfa_active" == "false" ]]; then
                users_without_mfa+=("$user")
            fi
        done <<< "$cred_report"
        
        if [[ ${#users_without_mfa[@]} -gt 0 ]]; then
            log_finding "HIGH" "1.3.1" "IAM users without MFA: ${users_without_mfa[*]}" \
                "Enforce MFA via IAM policies or AWS Organizations SCP"
        else
            log_pass "All IAM users with console access have MFA enabled"
            ((pass_count++)) || true
        fi
    else
        log_finding "MEDIUM" "1.3.1" "Could not generate credential report to check MFA status" ""
    fi
    
    # Check for IAM Identity Center (SSO) - the preferred IdP
    ((total_checks++)) || true
    local sso_instances
    sso_instances=$(aws_cmd sso-admin list-instances --query 'Instances[0].InstanceArn' --output text 2>/dev/null || echo "")
    if [[ -n "$sso_instances" && "$sso_instances" != "None" ]]; then
        log_pass "AWS IAM Identity Center (SSO) is configured"
        ((pass_count++)) || true
        
        # Check MFA settings in Identity Center
        local identity_store_id
        identity_store_id=$(aws_cmd sso-admin list-instances --query 'Instances[0].IdentityStoreId' --output text 2>/dev/null || echo "")
        log_info "  Identity Store ID: $identity_store_id"
    else
        log_finding "MEDIUM" "1.3.1" "AWS IAM Identity Center (SSO) is not configured - using local IAM" \
            "Consider enabling IAM Identity Center for centralized identity management"
    fi
    
    # -------------------------------------------------------------------------
    # Activity 1.4.1 - Privileged Access Management
    # -------------------------------------------------------------------------
    log_info "Checking Activity 1.4.1 - Privileged Access Management..."
    
    # Check for users with admin access
    ((total_checks++)) || true
    local admin_users=()
    local iam_users
    iam_users=$(aws_cmd iam list-users --query 'Users[].UserName' --output text)
    for user in $iam_users; do
        local attached_policies
        attached_policies=$(aws_cmd iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyArn' --output text)
        if echo "$attached_policies" | grep -q "arn:aws:iam::aws:policy/AdministratorAccess"; then
            admin_users+=("$user")
        fi
    done
    
    if [[ ${#admin_users[@]} -gt 3 ]]; then
        log_finding "HIGH" "1.4.1" "Excessive admin users detected (${#admin_users[@]}): ${admin_users[*]}" \
            "Implement PAM solution and reduce permanent admin access"
    elif [[ ${#admin_users[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "1.4.1" "Users with AdministratorAccess: ${admin_users[*]}" \
            "Consider using JIT access or role assumption instead of permanent admin"
        ((pass_count++)) || true
    else
        log_pass "No IAM users with direct AdministratorAccess policy"
        ((pass_count++)) || true
    fi
    
    # Check for long-lived access keys (>90 days)
    ((total_checks++)) || true
    local old_keys=()
    local current_date
    current_date=$(date +%s)
    local ninety_days=$((90 * 24 * 60 * 60))
    
    for user in $iam_users; do
        local keys
        keys=$(aws_cmd iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[?Status==`Active`].[AccessKeyId,CreateDate]' --output text)
        while read -r key_id create_date; do
            [[ -z "$key_id" ]] && continue
            local key_date
            key_date=$(date -d "$create_date" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "$create_date" +%s 2>/dev/null || echo "0")
            if [[ $((current_date - key_date)) -gt $ninety_days ]]; then
                old_keys+=("$user:$key_id")
            fi
        done <<< "$keys"
    done
    
    if [[ ${#old_keys[@]} -gt 0 ]]; then
        log_finding "HIGH" "1.4.1" "Access keys older than 90 days: ${old_keys[*]}" \
            "Rotate or delete old access keys: aws iam update-access-key --status Inactive"
    else
        log_pass "No access keys older than 90 days"
        ((pass_count++)) || true
    fi
    
    # -------------------------------------------------------------------------
    # Activity 1.5.1 - Identity Lifecycle Management
    # -------------------------------------------------------------------------
    log_info "Checking Activity 1.5.1 - Identity Lifecycle Management..."
    
    # Check for unused IAM users (no activity in 90 days)
    ((total_checks++)) || true
    local inactive_users=()
    if [[ -n "$cred_report" ]]; then
        while IFS=, read -r user arn creation_date password_enabled password_last_used rest; do
            [[ "$user" == "user" || "$user" == "<root_account>" ]] && continue
            if [[ "$password_last_used" != "N/A" && "$password_last_used" != "no_information" && -n "$password_last_used" ]]; then
                local last_used_date
                last_used_date=$(date -d "$password_last_used" +%s 2>/dev/null || echo "0")
                if [[ $last_used_date -gt 0 && $((current_date - last_used_date)) -gt $ninety_days ]]; then
                    inactive_users+=("$user")
                fi
            fi
        done <<< "$cred_report"
    fi
    
    if [[ ${#inactive_users[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "1.5.1" "Users inactive for 90+ days (no password use): ${inactive_users[*]}" \
            "Review and decommission unused accounts per ILM policy"
    else
        log_pass "No users inactive for 90+ days found"
        ((pass_count++)) || true
    fi
    
    # -------------------------------------------------------------------------
    # Activity 1.7.1 - Deny User by Default Policy
    # -------------------------------------------------------------------------
    log_info "Checking Activity 1.7.1 - Deny by Default Policy..."
    
    # Check for overly permissive IAM policies (Action: "*")
    ((total_checks++)) || true
    local permissive_policies=()
    local customer_policies
    customer_policies=$(aws_cmd iam list-policies --scope Local --query 'Policies[].Arn' --output text)
    for policy_arn in $customer_policies; do
        local version_id
        version_id=$(aws_cmd iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text)
        local policy_doc
        policy_doc=$(aws_cmd iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' --output json)
        if echo "$policy_doc" | grep -q '"Action":\s*"\*"' || echo "$policy_doc" | grep -q '"Action":\s*\["\*"\]'; then
            if echo "$policy_doc" | grep -q '"Resource":\s*"\*"'; then
                permissive_policies+=("$(basename "$policy_arn")")
            fi
        fi
    done
    
    if [[ ${#permissive_policies[@]} -gt 0 ]]; then
        log_finding "HIGH" "1.7.1" "Overly permissive policies (Action:* Resource:*): ${permissive_policies[*]}" \
            "Implement least privilege - replace wildcards with specific actions/resources"
    else
        log_pass "No customer policies with unrestricted Action:* Resource:* found"
        ((pass_count++)) || true
    fi
    
    # Check for SCPs (Organization-level deny policies)
    ((total_checks++)) || true
    local org_id
    org_id=$(aws_cmd organizations describe-organization --query 'Organization.Id' --output text 2>/dev/null || echo "")
    if [[ -n "$org_id" && "$org_id" != "None" ]]; then
        local scp_count
        scp_count=$(aws_cmd organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies | length(@)' --output text 2>/dev/null || echo "0")
        if [[ "$scp_count" -gt 1 ]]; then
            log_pass "AWS Organizations with SCPs detected ($scp_count policies)"
            ((pass_count++)) || true
        else
            log_finding "MEDIUM" "1.7.1" "Only default SCP - no custom deny policies" \
                "Implement SCPs for deny-by-default at organization level"
        fi
    else
        log_finding "LOW" "1.7.1" "AWS Organizations not enabled - cannot enforce org-level deny policies" \
            "Consider enabling AWS Organizations for centralized policy control"
    fi
    
    PILLAR_SCORES["USER"]="$pass_count/$total_checks"
    echo ""
    log_info "User Pillar Score: $pass_count/$total_checks checks passed"
}

# ============================================================================
# PILLAR 2: DEVICE
# Activity 2.1.2 - NPE and PKI, Device Under Management
# Activity 2.4.1 - Deny Device by Default Policy
# Activity 2.5.1 - Asset, Vulnerability, and Patch Management
# Activity 2.6.1 - Unified Endpoint Device Management
# Activity 2.6.2 - Enterprise Device Management Part 1
# Activity 2.7.1 - EDR Tools and C2C Integration
# ============================================================================

check_pillar_2_device() {
    echo ""
    echo "============================================================================"
    echo "PILLAR 2: DEVICE"
    echo "============================================================================"
    
    local pass_count=0
    local total_checks=0
    
    # -------------------------------------------------------------------------
    # Activity 2.1.2 - Device Inventory / NPE Management
    # -------------------------------------------------------------------------
    log_info "Checking Activity 2.1.2 - Device Inventory..."
    
    # Check if Systems Manager is tracking instances
    ((total_checks++)) || true
    local ssm_managed_count
    ssm_managed_count=$(aws_cmd ssm describe-instance-information --query 'InstanceInformationList | length(@)' --output text || echo "0")
    local ec2_running_count
    ec2_running_count=$(aws_cmd ec2 describe-instances --filters "Name=instance-state-name,Values=running" --query 'Reservations[*].Instances | length([*])' --output text | awk '{sum+=$1}END{print sum}' || echo "0")
    
    if [[ "$ssm_managed_count" -gt 0 ]]; then
        if [[ "$ec2_running_count" -gt 0 && "$ssm_managed_count" -lt "$ec2_running_count" ]]; then
            log_finding "HIGH" "2.1.2" "Only $ssm_managed_count of $ec2_running_count EC2 instances managed by SSM" \
                "Install SSM agent on all instances for device management"
        else
            log_pass "SSM managing $ssm_managed_count instances"
            ((pass_count++)) || true
        fi
    else
        if [[ "$ec2_running_count" -gt 0 ]]; then
            log_finding "BLOCKER" "2.1.2" "No instances managed by Systems Manager" \
                "Deploy SSM agent to all EC2 instances for device inventory and management"
        else
            log_pass "No EC2 instances running - SSM check N/A"
            ((pass_count++)) || true
        fi
    fi
    
    # -------------------------------------------------------------------------
    # Activity 2.4.1 - Deny Device by Default
    # -------------------------------------------------------------------------
    log_info "Checking Activity 2.4.1 - Deny Device by Default..."
    
    # Check default security groups (should have no inbound rules)
    ((total_checks++)) || true
    local permissive_default_sgs=()
    local vpcs
    vpcs=$(aws_cmd ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text)
    for vpc in $vpcs; do
        local default_sg
        default_sg=$(aws_cmd ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc" "Name=group-name,Values=default" --query 'SecurityGroups[0].GroupId' --output text)
        if [[ -n "$default_sg" && "$default_sg" != "None" ]]; then
            local inbound_rules
            inbound_rules=$(aws_cmd ec2 describe-security-groups --group-ids "$default_sg" --query 'SecurityGroups[0].IpPermissions | length(@)' --output text)
            if [[ "$inbound_rules" -gt 0 ]]; then
                permissive_default_sgs+=("$default_sg ($vpc)")
            fi
        fi
    done
    
    if [[ ${#permissive_default_sgs[@]} -gt 0 ]]; then
        log_finding "HIGH" "2.4.1" "Default security groups with inbound rules: ${permissive_default_sgs[*]}" \
            "Remove all rules from default SGs and use explicit SGs for resources"
    else
        log_pass "Default security groups have no inbound rules"
        ((pass_count++)) || true
    fi
    
    # Check for 0.0.0.0/0 inbound rules
    ((total_checks++)) || true
    local open_sgs=()
    local all_sgs
    all_sgs=$(aws_cmd ec2 describe-security-groups --query 'SecurityGroups[].GroupId' --output text)
    for sg in $all_sgs; do
        local has_open
        has_open=$(aws_cmd ec2 describe-security-groups --group-ids "$sg" \
            --query 'SecurityGroups[0].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`) || contains(Ipv6Ranges[].CidrIpv6, `::/0`)] | length(@)' --output text)
        if [[ "$has_open" -gt 0 ]]; then
            open_sgs+=("$sg")
        fi
    done
    
    if [[ ${#open_sgs[@]} -gt 5 ]]; then
        log_finding "HIGH" "2.4.1" "${#open_sgs[@]} security groups allow 0.0.0.0/0 inbound" \
            "Review and restrict security groups to specific CIDR ranges"
    elif [[ ${#open_sgs[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "2.4.1" "Security groups with 0.0.0.0/0 inbound: ${open_sgs[*]}" \
            "Ensure these are intentional (ALB, CloudFront origins, etc.)"
    else
        log_pass "No security groups with unrestricted 0.0.0.0/0 inbound"
        ((pass_count++)) || true
    fi
    
    # -------------------------------------------------------------------------
    # Activity 2.5.1 - Vulnerability and Patch Management
    # -------------------------------------------------------------------------
    log_info "Checking Activity 2.5.1 - Vulnerability and Patch Management..."
    
    # Check if AWS Inspector is enabled
    ((total_checks++)) || true
    local inspector_status
    inspector_status=$(aws_cmd inspector2 batch-get-account-status --query 'accounts[0].state.status' --output text 2>/dev/null || echo "")
    if [[ "$inspector_status" == "ENABLED" ]]; then
        log_pass "AWS Inspector is enabled"
        ((pass_count++)) || true
        
        # Check for critical findings
        local critical_findings
        critical_findings=$(aws_cmd inspector2 list-findings \
            --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}]}' \
            --query 'findings | length(@)' --output text 2>/dev/null || echo "0")
        if [[ "$critical_findings" -gt 0 ]]; then
            log_finding "HIGH" "2.5.1" "$critical_findings critical vulnerabilities detected by Inspector" \
                "Review and remediate critical findings: aws inspector2 list-findings"
        fi
    else
        log_finding "HIGH" "2.5.1" "AWS Inspector is not enabled" \
            "Enable Inspector for vulnerability scanning: aws inspector2 enable"
    fi
    
    # Check SSM Patch Manager compliance
    ((total_checks++)) || true
    local noncompliant_instances
    noncompliant_instances=$(aws_cmd ssm describe-instance-patch-states \
        --query 'InstancePatchStates[?MissingCount > `0` || FailedCount > `0`] | length(@)' --output text 2>/dev/null || echo "0")
    if [[ "$noncompliant_instances" -gt 0 ]]; then
        log_finding "HIGH" "2.5.1" "$noncompliant_instances instances have missing or failed patches" \
            "Review patch compliance: aws ssm describe-instance-patch-states"
    else
        log_pass "All managed instances are patch compliant"
        ((pass_count++)) || true
    fi
    
    # -------------------------------------------------------------------------
    # Activity 2.6.1/2.6.2 - Endpoint Management
    # -------------------------------------------------------------------------
    log_info "Checking Activity 2.6.1/2.6.2 - Endpoint Management..."
    
    # Check SSM State Manager associations
    ((total_checks++)) || true
    local state_mgr_assocs
    state_mgr_assocs=$(aws_cmd ssm list-associations --query 'Associations | length(@)' --output text || echo "0")
    if [[ "$state_mgr_assocs" -gt 0 ]]; then
        log_pass "SSM State Manager has $state_mgr_assocs configuration associations"
        ((pass_count++)) || true
    else
        log_finding "MEDIUM" "2.6.1" "No SSM State Manager associations configured" \
            "Configure State Manager for endpoint configuration management"
    fi
    
    # -------------------------------------------------------------------------
    # Activity 2.7.1 - EDR Integration
    # -------------------------------------------------------------------------
    log_info "Checking Activity 2.7.1 - EDR Integration..."
    
    # Check GuardDuty (AWS's threat detection)
    ((total_checks++)) || true
    local gd_detector_id
    gd_detector_id=$(aws_cmd guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null || echo "")
    if [[ -n "$gd_detector_id" && "$gd_detector_id" != "None" ]]; then
        local gd_status
        gd_status=$(aws_cmd guardduty get-detector --detector-id "$gd_detector_id" --query 'Status' --output text 2>/dev/null || echo "")
        if [[ "$gd_status" == "ENABLED" ]]; then
            log_pass "GuardDuty is enabled (detector: $gd_detector_id)"
            ((pass_count++)) || true
            
            # Check for high/critical findings
            local high_findings
            high_findings=$(aws_cmd guardduty list-findings --detector-id "$gd_detector_id" \
                --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
                --query 'FindingIds | length(@)' --output text 2>/dev/null || echo "0")
            if [[ "$high_findings" -gt 0 ]]; then
                log_finding "HIGH" "2.7.1" "$high_findings high/critical GuardDuty findings detected" \
                    "Review findings: aws guardduty get-findings --detector-id $gd_detector_id"
            fi
        else
            log_finding "HIGH" "2.7.1" "GuardDuty detector exists but is not enabled" \
                "Enable GuardDuty: aws guardduty update-detector --detector-id $gd_detector_id --enable"
        fi
    else
        log_finding "BLOCKER" "2.7.1" "GuardDuty is not enabled" \
            "Enable GuardDuty for threat detection: aws guardduty create-detector --enable"
    fi
    
    PILLAR_SCORES["DEVICE"]="$pass_count/$total_checks"
    echo ""
    log_info "Device Pillar Score: $pass_count/$total_checks checks passed"
}

# ============================================================================
# PILLAR 3: APPLICATION AND WORKLOAD
# Activity 3.2.1/3.2.2 - DevSecOps Software Factory
# Activity 3.3.1 - Approved Binaries and Code
# Activity 3.3.2 - Vulnerability Management Program Part 1
# Activity 3.4.1 - Resource Authorization Part 1
# Activity 3.4.3 - SDC Resource Authorization Part 1
# ============================================================================

check_pillar_3_application() {
    echo ""
    echo "============================================================================"
    echo "PILLAR 3: APPLICATION AND WORKLOAD"
    echo "============================================================================"
    
    local pass_count=0
    local total_checks=0
    
    # -------------------------------------------------------------------------
    # Activity 3.2.1/3.2.2 - DevSecOps
    # -------------------------------------------------------------------------
    log_info "Checking Activity 3.2.1/3.2.2 - DevSecOps Practices..."
    
    # Check for ECR image scanning
    ((total_checks++)) || true
    local ecr_repos
    ecr_repos=$(aws_cmd ecr describe-repositories --query 'repositories[].repositoryName' --output text 2>/dev/null || echo "")
    if [[ -n "$ecr_repos" ]]; then
        local repos_without_scan=()
        for repo in $ecr_repos; do
            local scan_config
            scan_config=$(aws_cmd ecr describe-repositories --repository-names "$repo" \
                --query 'repositories[0].imageScanningConfiguration.scanOnPush' --output text 2>/dev/null || echo "false")
            if [[ "$scan_config" != "true" ]]; then
                repos_without_scan+=("$repo")
            fi
        done
        
        if [[ ${#repos_without_scan[@]} -gt 0 ]]; then
            log_finding "HIGH" "3.2.1" "ECR repos without scan-on-push: ${repos_without_scan[*]}" \
                "Enable image scanning: aws ecr put-image-scanning-configuration --scan-on-push"
        else
            log_pass "All ECR repositories have scan-on-push enabled"
            ((pass_count++)) || true
        fi
    else
        log_info "No ECR repositories found - check N/A"
        ((pass_count++)) || true
    fi
    
    # Check for CodePipeline/CodeBuild (CI/CD)
    ((total_checks++)) || true
    local pipelines
    pipelines=$(aws_cmd codepipeline list-pipelines --query 'pipelines | length(@)' --output text 2>/dev/null || echo "0")
    if [[ "$pipelines" -gt 0 ]]; then
        log_pass "CodePipeline detected with $pipelines pipelines"
        ((pass_count++)) || true
    else
        log_finding "LOW" "3.2.1" "No CodePipeline detected - verify CI/CD is implemented elsewhere" ""
    fi
    
    # -------------------------------------------------------------------------
    # Activity 3.3.1/3.3.2 - Vulnerability Management
    # -------------------------------------------------------------------------
    log_info "Checking Activity 3.3.1/3.3.2 - Software Risk Management..."
    
    # Check ECR vulnerability findings
    ((total_checks++)) || true
    if [[ -n "$ecr_repos" ]]; then
        local total_critical=0
        for repo in $ecr_repos; do
            local critical
            critical=$(aws_cmd ecr describe-image-scan-findings --repository-name "$repo" \
                --image-id imageTag=latest \
                --query 'imageScanFindings.findingSeverityCounts.CRITICAL' --output text 2>/dev/null || echo "0")
            [[ "$critical" == "None" ]] && critical=0
            total_critical=$((total_critical + critical))
        done
        
        if [[ "$total_critical" -gt 0 ]]; then
            log_finding "HIGH" "3.3.2" "$total_critical critical vulnerabilities in ECR images" \
                "Review and patch container images"
        else
            log_pass "No critical vulnerabilities in latest ECR images"
            ((pass_count++)) || true
        fi
    else
        ((pass_count++)) || true
    fi
    
    # -------------------------------------------------------------------------
    # Activity 3.4.1/3.4.3 - Resource Authorization
    # -------------------------------------------------------------------------
    log_info "Checking Activity 3.4.1/3.4.3 - Resource Authorization..."
    
    # Check Lambda function resource policies
    ((total_checks++)) || true
    local lambda_functions
    lambda_functions=$(aws_cmd lambda list-functions --query 'Functions[].FunctionName' --output text 2>/dev/null || echo "")
    local public_lambdas=()
    for func in $lambda_functions; do
        local policy
        policy=$(aws_cmd lambda get-policy --function-name "$func" --query 'Policy' --output text 2>/dev/null || echo "")
        if echo "$policy" | grep -q '"Principal":\s*"\*"'; then
            public_lambdas+=("$func")
        fi
    done
    
    if [[ ${#public_lambdas[@]} -gt 0 ]]; then
        log_finding "HIGH" "3.4.1" "Lambda functions with public access: ${public_lambdas[*]}" \
            "Review and restrict Lambda resource policies"
    else
        log_pass "No Lambda functions with unrestricted public access"
        ((pass_count++)) || true
    fi
    
    # Check EKS cluster endpoint access
    ((total_checks++)) || true
    local eks_clusters
    eks_clusters=$(aws_cmd eks list-clusters --query 'clusters' --output text 2>/dev/null || echo "")
    local public_eks=()
    for cluster in $eks_clusters; do
        local public_access
        public_access=$(aws_cmd eks describe-cluster --name "$cluster" \
            --query 'cluster.resourcesVpcConfig.endpointPublicAccess' --output text 2>/dev/null || echo "")
        local private_access
        private_access=$(aws_cmd eks describe-cluster --name "$cluster" \
            --query 'cluster.resourcesVpcConfig.endpointPrivateAccess' --output text 2>/dev/null || echo "")
        if [[ "$public_access" == "True" && "$private_access" != "True" ]]; then
            public_eks+=("$cluster")
        fi
    done
    
    if [[ ${#public_eks[@]} -gt 0 ]]; then
        log_finding "HIGH" "3.4.3" "EKS clusters with only public endpoint: ${public_eks[*]}" \
            "Enable private endpoint and restrict public access"
    else
        if [[ -n "$eks_clusters" ]]; then
            log_pass "EKS clusters have private endpoint enabled"
        else
            log_info "No EKS clusters found - check N/A"
        fi
        ((pass_count++)) || true
    fi
    
    PILLAR_SCORES["APPLICATION"]="$pass_count/$total_checks"
    echo ""
    log_info "Application Pillar Score: $pass_count/$total_checks checks passed"
}

# ============================================================================
# PILLAR 4: DATA
# Activity 4.2.1 - Data Tagging Standards
# Activity 4.2.2 - Interoperability Standards
# Activity 4.3.1 - Data Tagging and Classification
# Activity 4.4.3 - File Activity Monitoring Part 1
# Activity 4.5.1 - Data Rights Management Part 1
# Activity 4.6.1 - Implement Enforcement Points
# ============================================================================

check_pillar_4_data() {
    echo ""
    echo "============================================================================"
    echo "PILLAR 4: DATA"
    echo "============================================================================"
    
    local pass_count=0
    local total_checks=0
    
    # -------------------------------------------------------------------------
    # Activity 4.2.1/4.3.1 - Data Tagging and Classification
    # -------------------------------------------------------------------------
    log_info "Checking Activity 4.2.1/4.3.1 - Data Classification..."
    
    # Check if Macie is enabled (NOT available in GovCloud)
    ((total_checks++)) || true
    if [[ "$AWS_REGION" == us-gov-* ]]; then
        log_finding "MEDIUM" "4.3.1" "Amazon Macie is NOT available in GovCloud regions" \
            "Use third-party DLP (Trellix, Forcepoint) or manual classification for data discovery"
    else
        local macie_status
        macie_status=$(aws_cmd macie2 get-macie-session --query 'status' --output text 2>/dev/null || echo "")
        if [[ "$macie_status" == "ENABLED" ]]; then
            log_pass "Amazon Macie is enabled for data classification"
            ((pass_count++)) || true
        else
            log_finding "MEDIUM" "4.3.1" "Amazon Macie is not enabled" \
                "Enable Macie for automated data discovery and classification"
        fi
    fi
    
    # -------------------------------------------------------------------------
    # Activity 4.4.3 - File Activity Monitoring
    # -------------------------------------------------------------------------
    log_info "Checking Activity 4.4.3 - File Activity Monitoring..."
    
    # Check S3 bucket logging
    ((total_checks++)) || true
    local buckets
    buckets=$(aws_cmd s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null || echo "")
    local buckets_without_logging=()
    for bucket in $buckets; do
        local logging
        logging=$(aws_cmd s3api get-bucket-logging --bucket "$bucket" --query 'LoggingEnabled.TargetBucket' --output text 2>/dev/null || echo "")
        if [[ -z "$logging" || "$logging" == "None" ]]; then
            buckets_without_logging+=("$bucket")
        fi
    done
    
    if [[ ${#buckets_without_logging[@]} -gt 0 ]]; then
        log_finding "HIGH" "4.4.3" "S3 buckets without access logging: ${buckets_without_logging[*]}" \
            "Enable S3 server access logging for audit trails"
    else
        log_pass "All S3 buckets have access logging enabled"
        ((pass_count++)) || true
    fi
    
    # -------------------------------------------------------------------------
    # Activity 4.5.1 - Data Rights Management / Encryption
    # -------------------------------------------------------------------------
    log_info "Checking Activity 4.5.1 - Data Protection..."
    
    # Check S3 default encryption
    ((total_checks++)) || true
    local unencrypted_buckets=()
    for bucket in $buckets; do
        local encryption
        encryption=$(aws_cmd s3api get-bucket-encryption --bucket "$bucket" \
            --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
            --output text 2>/dev/null || echo "")
        if [[ -z "$encryption" || "$encryption" == "None" ]]; then
            unencrypted_buckets+=("$bucket")
        fi
    done
    
    if [[ ${#unencrypted_buckets[@]} -gt 0 ]]; then
        log_finding "BLOCKER" "4.5.1" "S3 buckets without default encryption: ${unencrypted_buckets[*]}" \
            "Enable default encryption: aws s3api put-bucket-encryption"
    else
        log_pass "All S3 buckets have default encryption enabled"
        ((pass_count++)) || true
    fi
    
    # Check RDS encryption
    ((total_checks++)) || true
    local rds_instances
    rds_instances=$(aws_cmd rds describe-db-instances --query 'DBInstances[].DBInstanceIdentifier' --output text 2>/dev/null || echo "")
    local unencrypted_rds=()
    for db in $rds_instances; do
        local encrypted
        encrypted=$(aws_cmd rds describe-db-instances --db-instance-identifier "$db" \
            --query 'DBInstances[0].StorageEncrypted' --output text 2>/dev/null || echo "")
        if [[ "$encrypted" != "True" ]]; then
            unencrypted_rds+=("$db")
        fi
    done
    
    if [[ ${#unencrypted_rds[@]} -gt 0 ]]; then
        log_finding "BLOCKER" "4.5.1" "RDS instances without encryption: ${unencrypted_rds[*]}" \
            "Enable encryption (requires snapshot restore for existing instances)"
    else
        if [[ -n "$rds_instances" ]]; then
            log_pass "All RDS instances have encryption enabled"
        else
            log_info "No RDS instances found - check N/A"
        fi
        ((pass_count++)) || true
    fi
    
    # Check KMS key rotation
    ((total_checks++)) || true
    local kms_keys
    kms_keys=$(aws_cmd kms list-keys --query 'Keys[].KeyId' --output text 2>/dev/null || echo "")
    local keys_without_rotation=()
    for key in $kms_keys; do
        local key_spec
        key_spec=$(aws_cmd kms describe-key --key-id "$key" --query 'KeyMetadata.KeySpec' --output text 2>/dev/null || echo "")
        # Only check SYMMETRIC_DEFAULT keys (asymmetric keys don't support rotation)
        if [[ "$key_spec" == "SYMMETRIC_DEFAULT" ]]; then
            local rotation
            rotation=$(aws_cmd kms get-key-rotation-status --key-id "$key" --query 'KeyRotationEnabled' --output text 2>/dev/null || echo "")
            if [[ "$rotation" != "True" ]]; then
                keys_without_rotation+=("$key")
            fi
        fi
    done
    
    if [[ ${#keys_without_rotation[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "4.5.1" "${#keys_without_rotation[@]} KMS keys without automatic rotation" \
            "Enable key rotation: aws kms enable-key-rotation"
    else
        log_pass "All symmetric KMS keys have rotation enabled"
        ((pass_count++)) || true
    fi
    
    # -------------------------------------------------------------------------
    # Activity 4.6.1 - DLP Enforcement Points
    # -------------------------------------------------------------------------
    log_info "Checking Activity 4.6.1 - Data Loss Prevention..."
    
    # Check S3 Block Public Access
    ((total_checks++)) || true
    local public_access_blocks
    public_access_blocks=$(aws_cmd s3control get-public-access-block --account-id "$ACCOUNT_ID" \
        --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null || echo "{}")
    
    if echo "$public_access_blocks" | jq -e '.BlockPublicAcls == true and .IgnorePublicAcls == true and .BlockPublicPolicy == true and .RestrictPublicBuckets == true' >/dev/null 2>&1; then
        log_pass "Account-level S3 Block Public Access is fully enabled"
        ((pass_count++)) || true
    else
        log_finding "HIGH" "4.6.1" "Account-level S3 Block Public Access is not fully enabled" \
            "Enable all settings: aws s3control put-public-access-block"
    fi
    
    PILLAR_SCORES["DATA"]="$pass_count/$total_checks"
    echo ""
    log_info "Data Pillar Score: $pass_count/$total_checks checks passed"
}

# ============================================================================
# PILLAR 5: NETWORK AND ENVIRONMENT
# Activity 5.1.2 - Granular Access Rules Part 2
# Activity 5.2.2 - SDN Programmable Infrastructure
# Activity 5.3.1 - Datacenter Macro-Segmentation
# Activity 5.4.1 - Micro-Segmentation
# ============================================================================

check_pillar_5_network() {
    echo ""
    echo "============================================================================"
    echo "PILLAR 5: NETWORK AND ENVIRONMENT"
    echo "============================================================================"
    
    local pass_count=0
    local total_checks=0
    
    # -------------------------------------------------------------------------
    # Activity 5.1.2 - Granular Access Rules
    # -------------------------------------------------------------------------
    log_info "Checking Activity 5.1.2 - Granular Access Rules..."
    
    # Check VPC Flow Logs
    ((total_checks++)) || true
    local vpcs_without_flow_logs=()
    for vpc in $(aws_cmd ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text); do
        local flow_logs
        flow_logs=$(aws_cmd ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" \
            --query 'FlowLogs | length(@)' --output text 2>/dev/null || echo "0")
        if [[ "$flow_logs" -eq 0 ]]; then
            vpcs_without_flow_logs+=("$vpc")
        fi
    done
    
    if [[ ${#vpcs_without_flow_logs[@]} -gt 0 ]]; then
        log_finding "HIGH" "5.1.2" "VPCs without flow logs: ${vpcs_without_flow_logs[*]}" \
            "Enable VPC Flow Logs for network visibility: aws ec2 create-flow-logs"
    else
        log_pass "All VPCs have flow logs enabled"
        ((pass_count++)) || true
    fi
    
    # -------------------------------------------------------------------------
    # Activity 5.2.2/5.3.1 - Network Segmentation
    # -------------------------------------------------------------------------
    log_info "Checking Activity 5.2.2/5.3.1 - Network Segmentation..."
    
    # Check for Network ACLs
    ((total_checks++)) || true
    local nacl_count
    nacl_count=$(aws_cmd ec2 describe-network-acls --query 'NetworkAcls | length(@)' --output text || echo "0")
    if [[ "$nacl_count" -gt 1 ]]; then
        log_pass "Network ACLs in use ($nacl_count NACLs)"
        ((pass_count++)) || true
    else
        log_finding "MEDIUM" "5.3.1" "Only default NACLs - no macro-segmentation" \
            "Implement custom NACLs for network segmentation"
    fi
    
    # Check for multiple subnets (tiered architecture)
    ((total_checks++)) || true
    local subnet_count
    subnet_count=$(aws_cmd ec2 describe-subnets --query 'Subnets | length(@)' --output text || echo "0")
    local public_subnets
    public_subnets=$(aws_cmd ec2 describe-subnets --filters "Name=map-public-ip-on-launch,Values=true" \
        --query 'Subnets | length(@)' --output text || echo "0")
    local private_subnets=$((subnet_count - public_subnets))
    
    if [[ "$private_subnets" -gt 0 && "$public_subnets" -gt 0 ]]; then
        log_pass "Tiered network: $public_subnets public, $private_subnets private subnets"
        ((pass_count++)) || true
    else
        log_finding "MEDIUM" "5.3.1" "Network not properly tiered (public/private separation)" \
            "Implement public/private subnet architecture"
    fi
    
    # -------------------------------------------------------------------------
    # Activity 5.4.1 - Micro-Segmentation
    # -------------------------------------------------------------------------
    log_info "Checking Activity 5.4.1 - Micro-Segmentation..."
    
    # Check for security group diversity (micro-segmentation indicator)
    ((total_checks++)) || true
    local sg_count
    sg_count=$(aws_cmd ec2 describe-security-groups --query 'SecurityGroups | length(@)' --output text || echo "0")
    local ec2_count
    ec2_count=$(aws_cmd ec2 describe-instances --filters "Name=instance-state-name,Values=running" --query 'Reservations[*].Instances | [*] | length(@)' --output text || echo "0")
    
    if [[ "$ec2_count" -gt 0 && "$sg_count" -gt "$ec2_count" ]]; then
        log_pass "Good security group diversity ($sg_count SGs for $ec2_count instances)"
        ((pass_count++)) || true
    elif [[ "$ec2_count" -gt 0 ]]; then
        log_finding "MEDIUM" "5.4.1" "Low security group diversity ($sg_count SGs for $ec2_count instances)" \
            "Implement more granular security groups per application/tier"
    else
        log_pass "No EC2 instances - micro-segmentation check N/A"
        ((pass_count++)) || true
    fi
    
    # Check for WAF
    ((total_checks++)) || true
    local waf_acls
    waf_acls=$(aws_cmd wafv2 list-web-acls --scope REGIONAL --query 'WebACLs | length(@)' --output text 2>/dev/null || echo "0")
    local waf_cf_acls
    waf_cf_acls=$(aws_cmd wafv2 list-web-acls --scope CLOUDFRONT --region us-east-1 --query 'WebACLs | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$waf_acls" -gt 0 || "$waf_cf_acls" -gt 0 ]]; then
        log_pass "WAF is configured ($waf_acls regional, $waf_cf_acls CloudFront ACLs)"
        ((pass_count++)) || true
    else
        log_finding "HIGH" "5.4.1" "No WAF Web ACLs configured" \
            "Implement AWS WAF for application layer protection"
    fi
    
    PILLAR_SCORES["NETWORK"]="$pass_count/$total_checks"
    echo ""
    log_info "Network Pillar Score: $pass_count/$total_checks checks passed"
}

# ============================================================================
# PILLAR 6: AUTOMATION AND ORCHESTRATION
# Activity 6.1.2 - Organization Access Profile
# Activity 6.5.2 - SOAR Tools
# Activity 6.6.2 - Standardized API Calls Part 1
# Activity 6.7.1 - Workflow Enrichment Part 1
# ============================================================================

check_pillar_6_automation() {
    echo ""
    echo "============================================================================"
    echo "PILLAR 6: AUTOMATION AND ORCHESTRATION"
    echo "============================================================================"
    
    local pass_count=0
    local total_checks=0
    
    # -------------------------------------------------------------------------
    # Activity 6.1.2 - Access Profiles / Policy Decision Points
    # -------------------------------------------------------------------------
    log_info "Checking Activity 6.1.2 - Access Profiles..."
    
    # Check IAM Access Analyzer
    ((total_checks++)) || true
    local analyzers
    analyzers=$(aws_cmd accessanalyzer list-analyzers --query 'analyzers[?status==`ACTIVE`] | length(@)' --output text 2>/dev/null || echo "0")
    if [[ "$analyzers" -gt 0 ]]; then
        log_pass "IAM Access Analyzer is active ($analyzers analyzers)"
        ((pass_count++)) || true
        
        # Check for findings
        local analyzer_findings
        analyzer_findings=$(aws_cmd accessanalyzer list-findings --analyzer-arn "$(aws_cmd accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text)" \
            --query 'findings[?status==`ACTIVE`] | length(@)' --output text 2>/dev/null || echo "0")
        if [[ "$analyzer_findings" -gt 0 ]]; then
            log_finding "MEDIUM" "6.1.2" "$analyzer_findings active Access Analyzer findings" \
                "Review external access findings: aws accessanalyzer list-findings"
        fi
    else
        log_finding "HIGH" "6.1.2" "IAM Access Analyzer is not enabled" \
            "Enable Access Analyzer to identify external access"
    fi
    
    # -------------------------------------------------------------------------
    # Activity 6.5.2 - SOAR / Security Hub
    # -------------------------------------------------------------------------
    log_info "Checking Activity 6.5.2 - Security Orchestration..."
    
    # Check Security Hub
    ((total_checks++)) || true
    local securityhub_status
    securityhub_status=$(aws_cmd securityhub describe-hub --query 'HubArn' --output text 2>/dev/null || echo "")
    if [[ -n "$securityhub_status" && "$securityhub_status" != "None" ]]; then
        log_pass "Security Hub is enabled"
        ((pass_count++)) || true
        
        # Check enabled standards
        local standards
        standards=$(aws_cmd securityhub get-enabled-standards --query 'StandardsSubscriptions | length(@)' --output text 2>/dev/null || echo "0")
        if [[ "$standards" -gt 0 ]]; then
            log_info "  $standards security standards enabled"
        else
            log_finding "MEDIUM" "6.5.2" "Security Hub enabled but no standards activated" \
                "Enable AWS Foundational Security Best Practices standard"
        fi
    else
        log_finding "HIGH" "6.5.2" "Security Hub is not enabled" \
            "Enable Security Hub for security orchestration and findings aggregation"
    fi
    
    # Check for EventBridge rules (automation)
    ((total_checks++)) || true
    local event_rules
    event_rules=$(aws_cmd events list-rules --query 'Rules | length(@)' --output text 2>/dev/null || echo "0")
    if [[ "$event_rules" -gt 0 ]]; then
        log_pass "EventBridge has $event_rules rules configured"
        ((pass_count++)) || true
    else
        log_finding "LOW" "6.7.1" "No EventBridge rules - limited event-driven automation" \
            "Implement EventBridge rules for automated security responses"
    fi
    
    # -------------------------------------------------------------------------
    # Activity 6.6.2 - API Gateway / Standardization
    # -------------------------------------------------------------------------
    log_info "Checking Activity 6.6.2 - API Standardization..."
    
    # Check API Gateway REST APIs
    ((total_checks++)) || true
    local rest_apis
    rest_apis=$(aws_cmd apigateway get-rest-apis --query 'items | length(@)' --output text 2>/dev/null || echo "0")
    local http_apis
    http_apis=$(aws_cmd apigatewayv2 get-apis --query 'Items | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$rest_apis" -gt 0 || "$http_apis" -gt 0 ]]; then
        log_pass "API Gateway in use ($rest_apis REST, $http_apis HTTP APIs)"
        ((pass_count++)) || true
        
        # Check for API keys / authorization
        local api_keys
        api_keys=$(aws_cmd apigateway get-api-keys --query 'items | length(@)' --output text 2>/dev/null || echo "0")
        if [[ "$api_keys" -eq 0 && "$rest_apis" -gt 0 ]]; then
            log_finding "MEDIUM" "6.6.2" "REST APIs exist but no API keys configured" \
                "Implement API keys or IAM authorization for API access control"
        fi
    else
        log_info "No API Gateway APIs found - check N/A"
        ((pass_count++)) || true
    fi
    
    PILLAR_SCORES["AUTOMATION"]="$pass_count/$total_checks"
    echo ""
    log_info "Automation Pillar Score: $pass_count/$total_checks checks passed"
}

# ============================================================================
# PILLAR 7: VISIBILITY AND ANALYTICS
# Activity 7.1.2 - Log Parsing
# Activity 7.2.1 - Threat Alerting Part 1
# Activity 7.2.4 - Asset ID and Alert Correlation
# Activity 7.3.1 - Analytics Tools
# Activity 7.5.1 - Cyber Threat Intelligence Part 1
# ============================================================================

check_pillar_7_visibility() {
    echo ""
    echo "============================================================================"
    echo "PILLAR 7: VISIBILITY AND ANALYTICS"
    echo "============================================================================"
    
    local pass_count=0
    local total_checks=0
    
    # -------------------------------------------------------------------------
    # Activity 7.1.2 - Logging
    # -------------------------------------------------------------------------
    log_info "Checking Activity 7.1.2 - Log Collection..."
    
    # Check CloudTrail
    ((total_checks++)) || true
    local trails
    trails=$(aws_cmd cloudtrail describe-trails --query 'trailList' --output json 2>/dev/null || echo "[]")
    local trail_count
    trail_count=$(echo "$trails" | jq 'length')
    
    if [[ "$trail_count" -gt 0 ]]; then
        local multi_region
        multi_region=$(echo "$trails" | jq '[.[] | select(.IsMultiRegionTrail == true)] | length')
        local org_trail
        org_trail=$(echo "$trails" | jq '[.[] | select(.IsOrganizationTrail == true)] | length')
        
        if [[ "$multi_region" -gt 0 ]]; then
            log_pass "Multi-region CloudTrail is enabled"
            ((pass_count++)) || true
        else
            log_finding "HIGH" "7.1.2" "CloudTrail is not multi-region" \
                "Enable multi-region trail: aws cloudtrail update-trail --is-multi-region-trail"
        fi
        
        # Check CloudTrail logging status
        for trail_arn in $(echo "$trails" | jq -r '.[].TrailARN'); do
            local is_logging
            is_logging=$(aws_cmd cloudtrail get-trail-status --name "$trail_arn" --query 'IsLogging' --output text 2>/dev/null || echo "")
            if [[ "$is_logging" != "True" ]]; then
                log_finding "BLOCKER" "7.1.2" "CloudTrail $(basename "$trail_arn") is not logging" \
                    "Start logging: aws cloudtrail start-logging --name <trail>"
            fi
        done
    else
        log_finding "BLOCKER" "7.1.2" "No CloudTrail configured" \
            "Create CloudTrail: aws cloudtrail create-trail"
    fi
    
    # Check CloudWatch Log Groups
    ((total_checks++)) || true
    local log_groups
    log_groups=$(aws_cmd logs describe-log-groups --query 'logGroups | length(@)' --output text 2>/dev/null || echo "0")
    if [[ "$log_groups" -gt 0 ]]; then
        log_pass "CloudWatch Logs has $log_groups log groups"
        ((pass_count++)) || true
    else
        log_finding "HIGH" "7.1.2" "No CloudWatch Log Groups found" \
            "Configure application and security logging to CloudWatch"
    fi
    
    # -------------------------------------------------------------------------
    # Activity 7.2.1/7.2.4 - Alerting and Correlation
    # -------------------------------------------------------------------------
    log_info "Checking Activity 7.2.1/7.2.4 - Threat Alerting..."
    
    # Check CloudWatch Alarms
    ((total_checks++)) || true
    local alarms
    alarms=$(aws_cmd cloudwatch describe-alarms --query 'MetricAlarms | length(@)' --output text 2>/dev/null || echo "0")
    if [[ "$alarms" -gt 0 ]]; then
        log_pass "CloudWatch has $alarms metric alarms configured"
        ((pass_count++)) || true
    else
        log_finding "HIGH" "7.2.1" "No CloudWatch alarms configured" \
            "Configure alarms for security metrics and anomalies"
    fi
    
    # Check SNS topics for alerting
    ((total_checks++)) || true
    local sns_topics
    sns_topics=$(aws_cmd sns list-topics --query 'Topics | length(@)' --output text 2>/dev/null || echo "0")
    if [[ "$sns_topics" -gt 0 ]]; then
        log_pass "SNS topics available for alerting ($sns_topics topics)"
        ((pass_count++)) || true
    else
        log_finding "MEDIUM" "7.2.1" "No SNS topics for alerting" \
            "Create SNS topics for security alert delivery"
    fi
    
    # -------------------------------------------------------------------------
    # Activity 7.3.1 - Analytics
    # -------------------------------------------------------------------------
    log_info "Checking Activity 7.3.1 - Analytics Tools..."
    
    # Check AWS Config
    ((total_checks++)) || true
    local config_recorders
    config_recorders=$(aws_cmd configservice describe-configuration-recorders --query 'ConfigurationRecorders | length(@)' --output text 2>/dev/null || echo "0")
    if [[ "$config_recorders" -gt 0 ]]; then
        local recorder_status
        recorder_status=$(aws_cmd configservice describe-configuration-recorder-status --query 'ConfigurationRecordersStatus[0].recording' --output text 2>/dev/null || echo "")
        if [[ "$recorder_status" == "True" ]]; then
            log_pass "AWS Config is recording"
            ((pass_count++)) || true
        else
            log_finding "HIGH" "7.3.1" "AWS Config recorder exists but is not recording" \
                "Start recording: aws configservice start-configuration-recorder"
        fi
    else
        log_finding "HIGH" "7.3.1" "AWS Config is not enabled" \
            "Enable AWS Config for configuration tracking and compliance"
    fi
    
    # Check Config Rules
    ((total_checks++)) || true
    local config_rules
    config_rules=$(aws_cmd configservice describe-config-rules --query 'ConfigRules | length(@)' --output text 2>/dev/null || echo "0")
    if [[ "$config_rules" -gt 0 ]]; then
        log_pass "AWS Config has $config_rules rules for compliance checking"
        ((pass_count++)) || true
    else
        log_finding "MEDIUM" "7.3.1" "No AWS Config rules defined" \
            "Enable managed Config rules or create custom rules"
    fi
    
    # -------------------------------------------------------------------------
    # Activity 7.5.1 - Threat Intelligence
    # -------------------------------------------------------------------------
    log_info "Checking Activity 7.5.1 - Threat Intelligence..."
    
    # GuardDuty already checked in Pillar 2
    # Check for Detective (advanced threat investigation)
    ((total_checks++)) || true
    local detective_graphs
    detective_graphs=$(aws_cmd detective list-graphs --query 'GraphList | length(@)' --output text 2>/dev/null || echo "0")
    if [[ "$detective_graphs" -gt 0 ]]; then
        log_pass "Amazon Detective is enabled for threat investigation"
        ((pass_count++)) || true
    else
        log_finding "LOW" "7.5.1" "Amazon Detective is not enabled" \
            "Consider enabling Detective for advanced threat investigation"
    fi
    
    PILLAR_SCORES["VISIBILITY"]="$pass_count/$total_checks"
    echo ""
    log_info "Visibility Pillar Score: $pass_count/$total_checks checks passed"
}

# ============================================================================
# SUMMARY AND REPORTING
# ============================================================================

generate_report() {
    echo ""
    echo "============================================================================"
    echo "NSA ZIG PHASE ONE COMPLIANCE SUMMARY"
    echo "============================================================================"
    echo ""
    
    echo "PILLAR SCORES:"
    echo "  1. User:                  ${PILLAR_SCORES[USER]:-N/A}"
    echo "  2. Device:                ${PILLAR_SCORES[DEVICE]:-N/A}"
    echo "  3. Application:           ${PILLAR_SCORES[APPLICATION]:-N/A}"
    echo "  4. Data:                  ${PILLAR_SCORES[DATA]:-N/A}"
    echo "  5. Network:               ${PILLAR_SCORES[NETWORK]:-N/A}"
    echo "  6. Automation:            ${PILLAR_SCORES[AUTOMATION]:-N/A}"
    echo "  7. Visibility:            ${PILLAR_SCORES[VISIBILITY]:-N/A}"
    echo ""
    
    # Count findings by severity
    local blockers=0 highs=0 mediums=0 lows=0
    for finding in "${FINDINGS[@]}"; do
        case $(echo "$finding" | jq -r '.severity') in
            BLOCKER) ((blockers++)) ;;
            HIGH) ((highs++)) ;;
            MEDIUM) ((mediums++)) ;;
            LOW) ((lows++)) ;;
        esac
    done
    
    echo "FINDINGS SUMMARY:"
    echo -e "  ${RED}BLOCKER:${NC}  $blockers"
    echo -e "  ${RED}HIGH:${NC}     $highs"
    echo -e "  ${YELLOW}MEDIUM:${NC}   $mediums"
    echo -e "  ${CYAN}LOW:${NC}      $lows"
    echo ""
    
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        echo "Generating JSON report: $REPORT_FILE"
        cat > "$REPORT_FILE" << EOF
{
  "report_date": "$(date -Iseconds)",
  "aws_account": "$ACCOUNT_ID",
  "aws_region": "$AWS_REGION",
  "pillar_scores": {
    "user": "${PILLAR_SCORES[USER]:-N/A}",
    "device": "${PILLAR_SCORES[DEVICE]:-N/A}",
    "application": "${PILLAR_SCORES[APPLICATION]:-N/A}",
    "data": "${PILLAR_SCORES[DATA]:-N/A}",
    "network": "${PILLAR_SCORES[NETWORK]:-N/A}",
    "automation": "${PILLAR_SCORES[AUTOMATION]:-N/A}",
    "visibility": "${PILLAR_SCORES[VISIBILITY]:-N/A}"
  },
  "findings_summary": {
    "blocker": $blockers,
    "high": $highs,
    "medium": $mediums,
    "low": $lows
  },
  "findings": [$(IFS=,; echo "${FINDINGS[*]}")]
}
EOF
        echo "Report saved to: $REPORT_FILE"
    fi
    
    echo ""
    echo "============================================================================"
    echo "BEYOND NATIVE AWS - ECOSYSTEM SOLUTIONS"
    echo "============================================================================"
    echo ""
    echo "Zero Trust spans identity, devices, data, and networks across your entire"
    echo "enterprise. Some ZIG requirements need capabilities that complement cloud-"
    echo "native tooling—this is expected for any cloud provider."
    echo ""
    echo "| Requirement              | AWS Provides                | Ecosystem Solutions          |"
    echo "|--------------------------|-----------------------------|-----------------------------|"
    echo "| PAM / JIT Access         | IAM roles, Secrets Manager  | Sentinel, Vault, CyberArk   |"
    echo "| Device Posture (non-EC2) | SSM for EC2                 | Verified Access, Intune     |"
    echo "| Document-level DRM       | S3 encryption, Object Lock  | Microsoft Purview, Vera     |"
    echo "| Content-aware DLP        | S3 Block Public Access      | Trellix, Forcepoint         |"
    echo "| Unified Policy Engine    | IAM + SCPs + resource policies| OPA, Verified Permissions |"
    echo "| Behavioral SIEM          | Security Hub, CloudWatch    | Splunk, Elastic, Chronicle  |"
    echo ""
    if [[ "$AWS_REGION" == us-gov-* ]]; then
        echo "GOVCLOUD-SPECIFIC:"
        echo "  • Amazon Macie NOT available — use Trellix/Forcepoint for data classification"
        echo "  • IAM Access Analyzer policy generation not supported"
        echo ""
    fi
    echo "ECOSYSTEM PROJECTS:"
    echo "  Projects like Sentinel (github.com/mateoblack/sentinel) provide policy-based"
    echo "  credential issuance with approval workflows—purpose-built for AWS."
    echo ""
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════════════╗"
    echo "║  NSA Zero Trust Implementation Guideline (ZIG) Phase One                   ║"
    echo "║  AWS GovCloud Compliance Checker v$SCRIPT_VERSION                          ║"
    echo "╚════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    preflight_checks
    
    check_pillar_1_user
    check_pillar_2_device
    check_pillar_3_application
    check_pillar_4_data
    check_pillar_5_network
    check_pillar_6_automation
    check_pillar_7_visibility
    
    generate_report
}

main "$@"
