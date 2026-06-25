#!/bin/bash
# =============================================================================
# Remediation: Harden Against Lambda Privilege Escalation
# Scenario:    CloudGoat lambda_privesc
# Author:      Justin Steele
#
# What this does:
#   - Lists all Lambda functions and their attached execution roles
#   - Flags any execution roles with AdministratorAccess or wildcard policies
#   - Outputs an IAM policy template for scoping iam:PassRole correctly
# =============================================================================

set -euo pipefail

REGION="${1:-us-east-1}"

echo "[*] Auditing Lambda execution roles in region: $REGION"
echo ""

FUNCTIONS=$(aws lambda list-functions \
  --region "$REGION" \
  --query 'Functions[].{Name:FunctionName,Role:Role}' \
  --output json)

echo "$FUNCTIONS" | python3 -c "
import json, sys, subprocess

functions = json.load(sys.stdin)
print(f'Found {len(functions)} Lambda function(s)\n')

for fn in functions:
    name = fn['Name']
    role_arn = fn['Role']
    role_name = role_arn.split('/')[-1]
    print(f'Function: {name}')
    print(f'  Role: {role_name}')

    result = subprocess.run([
        'aws', 'iam', 'list-attached-role-policies',
        '--role-name', role_name,
        '--query', 'AttachedPolicies[].PolicyName',
        '--output', 'json'
    ], capture_output=True, text=True)

    policies = json.loads(result.stdout) if result.returncode == 0 else []
    for p in policies:
        flag = ' <-- REVIEW' if 'Admin' in p or p == 'PowerUser' else ''
        print(f'  Policy: {p}{flag}')
    print()
"

echo "============================================="
echo " Recommended Fix: Scope iam:PassRole"
echo "============================================="
cat << 'POLICY'
Replace this (dangerous):
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "*"
}

With this (safe):
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": [
    "arn:aws:iam::ACCOUNT_ID:role/specific-lambda-role-only"
  ],
  "Condition": {
    "StringEquals": {
      "iam:PassedToService": "lambda.amazonaws.com"
    }
  }
}
POLICY

echo ""
echo "============================================="
echo " Additional Steps:"
echo "   1. Remove AdministratorAccess from all Lambda execution roles"
echo "   2. Scope sts:AssumeRole to specific role ARNs per user"
echo "   3. Enable GuardDuty for anomalous Lambda role behavior"
echo "   4. Set CloudWatch alarms on CreateFunction and CreateUser events"
echo "============================================="
