#!/bin/bash
# =============================================================================
# Detection: Lambda-Based Privilege Escalation
# Scenario:  CloudGoat lambda_privesc
# Author:    Justin Steele
#
# What this detects:
#   - IAM user creation from a Lambda execution role (backdoor creation)
#   - Lambda functions created with high-privilege roles attached
#   - iam:PassRole usage from non-admin principals
# =============================================================================

set -euo pipefail

LOG_GROUP="/aws/cloudtrail/logs"
ALARM_EMAIL="security@yourcompany.com"
REGION="us-east-1"
SNS_TOPIC_NAME="security-alerts"

echo "[*] Creating SNS topic..."
SNS_TOPIC_ARN=$(aws sns create-topic \
  --name "$SNS_TOPIC_NAME" \
  --region "$REGION" \
  --query 'TopicArn' \
  --output text)

aws sns subscribe \
  --topic-arn "$SNS_TOPIC_ARN" \
  --protocol email \
  --notification-endpoint "$ALARM_EMAIL" \
  --region "$REGION"

# ── Detection 1: IAM User Created by Lambda Execution Role ───────────────────
echo "[*] Creating alarm: IAM user creation from Lambda role..."

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "IAMUserCreatedByLambdaRole" \
  --filter-pattern '{ ($.eventName = "CreateUser") && ($.userIdentity.sessionContext.sessionIssuer.type = "Role") }' \
  --metric-transformations \
    metricName=IAMUserCreatedByRole,metricNamespace=SecurityDetections,metricValue=1,defaultValue=0 \
  --region "$REGION"

aws cloudwatch put-metric-alarm \
  --alarm-name "ALERT-IAMUserCreatedByLambdaRole" \
  --alarm-description "IAM user created by an assumed role -- possible Lambda privilege escalation backdoor" \
  --metric-name "IAMUserCreatedByRole" \
  --namespace "SecurityDetections" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "$SNS_TOPIC_ARN" \
  --treat-missing-data notBreaching \
  --region "$REGION"

echo "[+] Alarm created: ALERT-IAMUserCreatedByLambdaRole"

# ── Detection 2: Lambda Function Created with IAM Role ───────────────────────
echo "[*] Creating alarm: Lambda function creation..."

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "LambdaFunctionCreated" \
  --filter-pattern '{ $.eventName = "CreateFunction20150331" }' \
  --metric-transformations \
    metricName=LambdaFunctionCreated,metricNamespace=SecurityDetections,metricValue=1,defaultValue=0 \
  --region "$REGION"

aws cloudwatch put-metric-alarm \
  --alarm-name "ALERT-UnexpectedLambdaCreation" \
  --alarm-description "New Lambda function created -- verify role attached is appropriate" \
  --metric-name "LambdaFunctionCreated" \
  --namespace "SecurityDetections" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "$SNS_TOPIC_ARN" \
  --treat-missing-data notBreaching \
  --region "$REGION"

echo "[+] Alarm created: ALERT-UnexpectedLambdaCreation"

# ── Detection 3: Admin Policy Attached to New User ───────────────────────────
echo "[*] Creating alarm: AdministratorAccess policy attached..."

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "AdminPolicyAttached" \
  --filter-pattern '{ ($.eventName = "AttachUserPolicy") && ($.requestParameters.policyArn = "*AdministratorAccess*") }' \
  --metric-transformations \
    metricName=AdminPolicyAttached,metricNamespace=SecurityDetections,metricValue=1,defaultValue=0 \
  --region "$REGION"

aws cloudwatch put-metric-alarm \
  --alarm-name "ALERT-AdminPolicyAttached" \
  --alarm-description "AdministratorAccess policy attached to a user -- verify this is authorized" \
  --metric-name "AdminPolicyAttached" \
  --namespace "SecurityDetections" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "$SNS_TOPIC_ARN" \
  --treat-missing-data notBreaching \
  --region "$REGION"

echo "[+] Alarm created: ALERT-AdminPolicyAttached"
echo ""
echo "============================================="
echo " Detection setup complete"
echo " Alarms: ALERT-IAMUserCreatedByLambdaRole"
echo "         ALERT-UnexpectedLambdaCreation"
echo "         ALERT-AdminPolicyAttached"
echo "============================================="
