# ECS Deployment Templates

Full documentation: [docs/deployment/ecs.md](../../docs/deployment/ecs.md)

## Quick usage

```bash
# From repository root:
aws cloudformation deploy --stack-name dbward \
  --template-file deploy/ecs/template.yaml \
  --parameter-overrides VpcId=vpc-xxx SubnetIds=subnet-aaa \
  --capabilities CAPABILITY_NAMED_IAM
```
