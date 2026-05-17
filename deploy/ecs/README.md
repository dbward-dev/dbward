# ECS Deployment Guide

## Architecture

- **Server**: EC2 launch type + EBS volume (SQLite requires block storage)
- **Agent**: Fargate (stateless, no persistent storage needed)

## Prerequisites

1. VPC with private subnets
2. ECS cluster (EC2 capacity provider for server, Fargate for agent)
3. EBS volume attached to EC2 instance at `/mnt/dbward-data`
4. SSM parameters: `/dbward/agent-token`, `/dbward/database-url`
5. IAM roles: execution role (ECR pull + SSM + CloudWatch), task roles

## Server Deployment Constraints

- **Single task only**: SQLite does not support concurrent writers
- **Stop-before-start**: Service config must use `minimumHealthyPercent=0`, `maximumPercent=100`
- **AZ affinity**: EBS volume is AZ-bound; place server task in the same AZ

```json
{
  "deploymentConfiguration": {
    "minimumHealthyPercent": 0,
    "maximumPercent": 100
  },
  "placementConstraints": [
    {
      "type": "memberOf",
      "expression": "attribute:ecs.availability-zone == ap-northeast-1a"
    }
  ]
}
```

## Deploy

```bash
# Register task definitions
aws ecs register-task-definition --cli-input-json file://server-task-definition.json
aws ecs register-task-definition --cli-input-json file://agent-task-definition.json

# Create services
aws ecs create-service \
  --cluster dbward \
  --service-name dbward-server \
  --task-definition dbward-server \
  --desired-count 1 \
  --launch-type EC2 \
  --deployment-configuration minimumHealthyPercent=0,maximumPercent=100

aws ecs create-service \
  --cluster dbward \
  --service-name dbward-agent \
  --task-definition dbward-agent \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx]}"
```

## Notes

- Config files (`/config/server.toml`, `/config/agent.toml`) must be baked into a custom image or downloaded at startup via an init script. ECS does not support ConfigMap-style mounts.
- If Fargate is required for server, replace SQLite with RDS (PostgreSQL).
- Litestream can be added as a sidecar for S3 backup of the SQLite file.
