---
title: ECS Deployment
description: Deploy dbward on AWS ECS Fargate with CloudFormation
---

# ECS Deployment (CloudFormation)

**Template files:** [`deploy/ecs/`](../../deploy/ecs/)

All commands below assume you are running from the repository root.

## Prerequisites

- VPC with subnets (public for testing, private + NAT Gateway for production)
- Database URL stored in AWS Secrets Manager

## Deploy

### 1. Create database secret

```bash
aws secretsmanager create-secret --name dbward/database-url \
  --secret-string "postgres://user:pass@mydb.rds.amazonaws.com:5432/app"
```

### 2. Deploy stack (server only, without agent)

```bash
aws cloudformation deploy --stack-name dbward \
  --template-file deploy/ecs/template.yaml \
  --parameter-overrides \
    VpcId=vpc-xxx \
    SubnetIds=subnet-aaa \
    DatabaseUrlSecretArn=arn:aws:secretsmanager:REGION:ACCOUNT:secret:dbward/database-url-XXXXXX \
  --capabilities CAPABILITY_NAMED_IAM
```

### 3. Bootstrap tokens (one-time, after first deploy)

```bash
TASK=$(aws ecs list-tasks --cluster dbward --service-name server \
  --query 'taskArns[0]' --output text)

# Read admin token
aws ecs execute-command --cluster dbward --task $TASK --container server \
  --interactive --command "cat /data/admin-token"

# Read agent token
aws ecs execute-command --cluster dbward --task $TASK --container server \
  --interactive --command "cat /data/agent-token"

# Store agent token in Secrets Manager
aws secretsmanager create-secret --name dbward/agent-token --secret-string "dbw_..."
```

### 4. Enable agent (separate stack)

```bash
CLUSTER=$(aws cloudformation describe-stacks --stack-name dbward \
  --query "Stacks[0].Outputs[?OutputKey=='ClusterName'].OutputValue" --output text)
SERVER_SG=$(aws cloudformation describe-stacks --stack-name dbward \
  --query "Stacks[0].Outputs[?OutputKey=='ServerSecurityGroupId'].OutputValue" --output text)

aws cloudformation deploy --stack-name dbward-agent \
  --template-file deploy/ecs/agent.yaml \
  --parameter-overrides \
    ClusterName=$CLUSTER \
    VpcId=vpc-xxx \
    SubnetIds=subnet-aaa \
    ServerSecurityGroupId=$SERVER_SG \
    AgentTokenSecretArn=arn:aws:secretsmanager:REGION:ACCOUNT:secret:dbward/agent-token-XXXXXX \
    DatabaseUrlSecretArn=arn:aws:secretsmanager:REGION:ACCOUNT:secret:dbward/database-url-XXXXXX \
  --capabilities CAPABILITY_NAMED_IAM
```

## Version Upgrade

```bash
aws cloudformation deploy --stack-name dbward \
  --template-file deploy/ecs/template.yaml \
  --parameter-overrides ImageTag=v0.1.3 \
  --capabilities CAPABILITY_NAMED_IAM
```

## SSM Parameter Store Config (Recommended)

Store server config in SSM instead of inline to avoid heredoc issues and enable config changes without template updates:

```bash
# 1. Create parameter
aws ssm put-parameter --name /dbward/server-config --type SecureString --value '
state_dir = "/data"
[auth]
mode = "token"
[[databases]]
name = "app"
environments = ["production"]
'

# 2. Deploy with SSM
aws cloudformation deploy --stack-name dbward \
  --template-file deploy/ecs/template.yaml \
  --parameter-overrides \
    VpcId=vpc-xxx \
    SubnetIds=subnet-aaa \
    ConfigSource=ssm \
    SsmConfigParameter=/dbward/server-config \
  --capabilities CAPABILITY_NAMED_IAM

# 3. Update config (no redeploy needed, just restart)
aws ssm put-parameter --name /dbward/server-config --overwrite --value '...'
aws ecs update-service --cluster dbward --service server --force-new-deployment
```

## S3 Result Storage (Recommended for Production)

Deploy the storage stack separately (long-lived, independent of app lifecycle):

```bash
# 1. Deploy storage stack
aws cloudformation deploy --stack-name dbward-storage \
  --template-file deploy/ecs/storage.yaml \
  --parameter-overrides RetentionDays=30

# 2. Get bucket name
BUCKET=$(aws cloudformation describe-stacks --stack-name dbward-storage \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text)

# 3. Deploy ECS stack with S3
aws cloudformation deploy --stack-name dbward \
  --template-file deploy/ecs/template.yaml \
  --parameter-overrides \
    ResultStorageBackend=s3 \
    ResultBucketName=$BUCKET \
    ...other params... \
  --capabilities CAPABILITY_NAMED_IAM
```

The storage stack provides:
- S3 bucket with encryption (AES256) and public access block
- Lifecycle rule (auto-delete after RetentionDays)
- DenyInsecureTransport bucket policy

The ECS stack's `ServerTaskRole` gets minimal S3 permissions automatically:
- `s3:PutObject/GetObject/DeleteObject/PutObjectTagging` on `results/*`
- `s3:ListBucket` with prefix condition `results/*`

### Production Hardening (Optional)

For stricter isolation, add a Deny policy to the bucket manually:

```json
{
  "Sid": "DenyAccessExceptAllowedPrincipals",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": ["arn:aws:s3:::BUCKET", "arn:aws:s3:::BUCKET/*"],
  "Condition": {
    "ArnNotEquals": {
      "aws:PrincipalArn": [
        "arn:aws:iam::ACCOUNT:role/dbward-server-task",
        "arn:aws:iam::ACCOUNT:role/YOUR_CFN_ROLE",
        "arn:aws:iam::ACCOUNT:root"
      ]
    }
  }
}
```

> ⚠️ Do NOT add this via CloudFormation — it can lock out CFn itself. Apply manually after both stacks are stable.

## Architecture

```
deploy/ecs/
├── template.yaml   # Server: Cluster, EFS, Service Connect, IAM, ALB (optional)
├── agent.yaml      # Agent: TaskDef, Service, SG, IAM (separate lifecycle)
└── storage.yaml    # S3 bucket for result storage (optional, long-lived)
```

- **Server** (`template.yaml`): Fargate + EFS (SQLite persistent storage, survives restarts)
- **Agent** (`agent.yaml`): Fargate (stateless, polls server for tasks, independent scaling)
- **Service-to-service**: Service Connect (sidecar proxy, agent resolves `server:3000`)
- **Secrets**: AWS Secrets Manager → ECS environment variable injection
- **Storage**: S3 bucket (separate stack) or local EFS
- **ALB**: Optional (`EnableAlb=true`)

### Data Persistence

Server state (tokens, workflows, audit logs) is stored in SQLite on EFS:
- EFS FileSystem with encryption at rest + in transit
- Access Point enforces UID 10001 (dbward-server user)
- IAM authorization restricts mount to ServerTaskRole only
- Single replica — no concurrent writer concern

### Service Connect

Agent connects to server via `http://server:3000` using ECS Service Connect:
- No DNS resolution issues (sidecar proxy handles routing)
- Faster failover than DNS-based service discovery
- No need for fixed IPs or load balancers for internal traffic

## Network Requirements

- **Production**: Private subnets + NAT Gateway. Set `AssignPublicIp: DISABLED` in template.
- **Testing**: Public subnets OK (template defaults to `AssignPublicIp: ENABLED`).
- Server egress: HTTPS (443), NFS/EFS (2049), DNS (53).
- Agent egress: server (3000 via Service Connect), database (configurable), HTTPS (443), DNS (53).

## Cleanup

```bash
aws cloudformation delete-stack --stack-name dbward-agent
aws cloudformation delete-stack --stack-name dbward
aws cloudformation delete-stack --stack-name dbward-storage
aws secretsmanager delete-secret --secret-id dbward/database-url --force-delete-without-recovery
aws secretsmanager delete-secret --secret-id dbward/agent-token --force-delete-without-recovery
# Note: EFS and S3 bucket have DeletionPolicy: Retain. Delete manually if no longer needed.
```

## Parameters Reference

### template.yaml (Server)

| Parameter | Required | Description |
|---|---|---|
| VpcId | ✅ | VPC ID |
| SubnetIds | ✅ | Subnet IDs (at least one) |
| ImageRepository | | Container image repo (default: ghcr.io/dbward-dev/dbward-server) |
| ImageTag | | Image tag (default: latest) |
| ServerConfigToml | | server.toml content |
| EnableAlb | | Create ALB (default: false) |
| AlbSubnetIds | | Public subnets for ALB |
| EcrRepositoryName | | ECR repo name (enables ECR pull permissions) |
| AllowedIngressCidr | | CIDR for server access (default: 10.0.0.0/8) |
| ResultStorageBackend | | "local" or "s3" (default: local) |
| ResultBucketName | | S3 bucket name (required when backend=s3) |

### agent.yaml

| Parameter | Required | Description |
|---|---|---|
| ClusterName | ✅ | ECS Cluster name (from server stack) |
| VpcId | ✅ | VPC ID |
| SubnetIds | ✅ | Subnet IDs |
| ServerSecurityGroupId | ✅ | Server SG ID (from server stack) |
| AgentTokenSecretArn | ✅ | Secrets Manager ARN for agent token |
| DatabaseUrlSecretArn | ✅ | Secrets Manager ARN for DB URL |
| ImageRepository | | Container image repo |
| ImageTag | | Image tag |
| AgentDesiredCount | | Agent replicas (default: 1) |
| AgentConfigToml | | agent.toml content |
| DatabasePort | | DB port for SG rule (default: 5432) |
| EcrRepositoryName | | ECR repo name |

## See also

- [Server configuration](server.md) — full server settings reference
- [Agent configuration](agent.md) — agent settings, capabilities, resilience
- [Troubleshooting](troubleshooting.md) — common deployment issues
