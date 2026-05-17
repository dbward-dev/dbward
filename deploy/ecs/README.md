# ECS Deployment Guide (CloudFormation)

## Prerequisites

- VPC with subnets (public for testing, private + NAT Gateway for production)
- Database URL stored in AWS Secrets Manager

## Deploy

### 1. Create database secret

```bash
aws secretsmanager create-secret --name dbward/database-url \
  --secret-string "postgres://user:pass@mydb.rds.amazonaws.com:5432/app"
```

### 2. Prepare config files

```bash
# server.toml
cat > server.toml << 'EOF'
[auth]
mode = "token"
[[databases]]
name = "app"
environments = ["production"]
[result_storage]
backend = "local"
root_dir = "/data/results"
EOF

# agent.toml (replace STACK_NAME with your stack name)
cat > agent.toml << 'EOF'
agent_id = "prod-agent"
poll_interval_ms = 1000
max_concurrent_tasks = 4
[server]
url = "http://server.STACK_NAME.local:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"
[databases.app.production]
url = "${DATABASE_URL}"
EOF
```

### 3. Deploy stack (server only)

```bash
aws cloudformation deploy --stack-name dbward --template-file template.yaml \
  --parameter-overrides \
    VpcId=vpc-xxx \
    SubnetIds=subnet-aaa,subnet-bbb \
    DatabaseUrlSecretArn=arn:aws:secretsmanager:REGION:ACCOUNT:secret:dbward/database-url-XXXXXX \
    ServerConfigToml="$(cat server.toml)" \
    AgentConfigToml="$(cat agent.toml)" \
  --capabilities CAPABILITY_NAMED_IAM
```

### 4. Bootstrap agent token (one-time)

```bash
TASK=$(aws ecs list-tasks --cluster dbward --service-name server --query 'taskArns[0]' --output text)
aws ecs execute-command --cluster dbward --task $TASK --container server --interactive \
  --command "gosu dbward dbward-server --data /data/dbward.db token create --user agent --role admin --agent"

# Store the output token
aws secretsmanager create-secret --name dbward/agent-token \
  --secret-string "dbw_xxxx..."
```

### 5. Enable agent

```bash
aws cloudformation deploy --stack-name dbward --template-file template.yaml \
  --parameter-overrides \
    AgentTokenSecretArn=arn:aws:secretsmanager:REGION:ACCOUNT:secret:dbward/agent-token-XXXXXX \
  --capabilities CAPABILITY_NAMED_IAM
```

## Version Upgrade

```bash
aws cloudformation deploy --stack-name dbward --template-file template.yaml \
  --parameter-overrides ImageTag=v0.1.3 \
  --capabilities CAPABILITY_NAMED_IAM
```

## Config Changes

```bash
# Edit server.toml or agent.toml, then:
aws cloudformation deploy --stack-name dbward --template-file template.yaml \
  --parameter-overrides \
    ServerConfigToml="$(cat server.toml)" \
    AgentConfigToml="$(cat agent.toml)" \
  --capabilities CAPABILITY_NAMED_IAM
```

Config is injected via CFn parameters → written to `/tmp/*.toml` at container startup.
`${DBWARD_AGENT_TOKEN}` and `${DATABASE_URL}` in agent.toml are expanded by the dbward binary at runtime using environment variables injected from Secrets Manager.

## Architecture

- **Server**: Fargate + managed EBS volume (SQLite persistent storage)
- **Agent**: Fargate (stateless)
- **Service Discovery**: Cloud Map (`server.<stack-name>.local`)
- **Secrets**: AWS Secrets Manager → ECS environment variable injection
- **ALB**: Optional (`EnableAlb=true`)

## Network Requirements

- **Production**: Private subnets + NAT Gateway. Set `AssignPublicIp: DISABLED` in template.
- **Testing**: Public subnets OK (template defaults to `AssignPublicIp: ENABLED`).
- Agent egress: server (3000), database (configurable port), HTTPS (443), DNS (53).

## Cleanup

```bash
aws cloudformation delete-stack --stack-name dbward
aws secretsmanager delete-secret --secret-id dbward/database-url --force-delete-without-recovery
aws secretsmanager delete-secret --secret-id dbward/agent-token --force-delete-without-recovery
```

## Parameters Reference

| Parameter | Required | Description |
|---|---|---|
| VpcId | ✅ | VPC ID |
| SubnetIds | ✅ | Comma-separated subnet IDs |
| DatabaseUrlSecretArn | ✅ | Secrets Manager ARN for DB URL |
| AgentTokenSecretArn | | Secrets Manager ARN for agent token (enables agent) |
| ImageRepository | | Container image repo (default: ghcr.io/dbward-dev/dbward) |
| ImageTag | | Image tag (default: latest) |
| ServerConfigToml | | server.toml content |
| AgentConfigToml | | agent.toml content |
| ServerDataVolumeSizeGiB | | EBS volume size (default: 10) |
| AgentDesiredCount | | Agent replicas (default: 1) |
| DatabasePort | | DB port for SG rule (default: 5432) |
| EnableAlb | | Create ALB (default: false) |
| AlbSubnetIds | | Public subnets for ALB |
| EcrRepositoryName | | ECR repo name (enables ECR pull permissions) |
| AllowedIngressCidr | | CIDR for server access (default: 10.0.0.0/8) |
