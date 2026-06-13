---
title: TLS Configuration
description: Recommended TLS patterns for each deployment method
---

# TLS Configuration

dbward does not terminate TLS itself — it delegates TLS to external infrastructure (reverse proxy, load balancer, or Ingress controller). This page describes the recommended TLS setup for each deployment method.

> **Why no built-in TLS?** Keeping TLS termination external simplifies certificate management (auto-renewal via Let's Encrypt/ACM/cert-manager), avoids coupling the application to certificate lifecycle, and follows the same pattern as comparable tools (Bytebase, Grafana, etc.).

## Quick Reference

| Deployment method | TLS approach | Certificate source |
|---|---|---|
| Docker Compose | Caddy reverse proxy (`--profile tls`) | Let's Encrypt (automatic) |
| ECS (CloudFormation) | ALB HTTPS Listener | ACM Certificate |
| Helm / Kubernetes | Ingress + cert-manager | Let's Encrypt via cert-manager |
| Binary / systemd | nginx or Caddy in front | Let's Encrypt or manual |

## Docker Compose

Enable the built-in Caddy profile:

```bash
DOMAIN=dbward.example.com docker compose --profile tls up -d
```

Caddy automatically obtains and renews a Let's Encrypt certificate. See [Docker Compose deployment](docker.md#tls-termination) for full details including `trusted_proxies` configuration.

## ECS (CloudFormation)

Pass an ACM Certificate ARN to the template:

```bash
aws cloudformation deploy \
  --stack-name dbward \
  --template-file template.yaml \
  --parameter-overrides CertificateArn=arn:aws:acm:us-east-1:123456789:certificate/abc-def \
  --capabilities CAPABILITY_NAMED_IAM
```

This enables:
- HTTPS:443 Listener with TLS 1.3 policy (`ELBSecurityPolicy-TLS13-1-2-2021-06`)
- HTTP:80 → HTTPS:443 redirect
- `TransportSecurity` output confirming HTTPS is active

Without `CertificateArn`, the ALB serves HTTP only (suitable for private/internal access behind a VPN).

> **Note:** `CertificateArn` only takes effect when `EnableAlb=true` (the default). With `EnableAlb=false`, traffic uses Service Connect only.

> **Security:** The `AllowedIngressCidr` parameter controls direct access to the server task on port 3000. For internet-facing deployments with HTTPS, restrict this to your VPC CIDR (default `10.0.0.0/8`) so that external traffic can only reach the server through the ALB.

## Helm / Kubernetes

Enable Ingress in `values.yaml`:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: dbward.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: dbward-tls
      hosts:
        - dbward.example.com
```

Prerequisites:
- An Ingress controller (e.g. [ingress-nginx](https://kubernetes.github.io/ingress-nginx/))
- [cert-manager](https://cert-manager.io/) with a `ClusterIssuer` configured

A standalone sample is available at `deploy/kubernetes/base/ingress-example.yaml` for non-Helm users.

## Binary / systemd

Place a reverse proxy in front of the dbward server. Example with Caddy:

```
# /etc/caddy/Caddyfile
dbward.example.com {
    reverse_proxy localhost:3000
}
```

Example with nginx:

```nginx
server {
    listen 443 ssl;
    server_name dbward.example.com;

    ssl_certificate     /etc/letsencrypt/live/dbward.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dbward.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Client-side enforcement

dbward CLI and Agent enforce transport security:

- **Agent**: refuses to start if `[server].url` is external HTTP (non-private IP, non-localhost). Set `allow_insecure = true` to override for API-token-only setups.
- **CLI**: prints a warning for external HTTP connections. Use `--allow-insecure` or `[server] allow_insecure = true` to suppress.
- **OIDC mode**: HTTP is always rejected regardless of `allow_insecure`.

See `dbward doctor` for a TLS connectivity check.

## `trusted_proxies`

When TLS is terminated externally, configure `trusted_proxies` in `server.toml` so the server trusts `X-Forwarded-For` headers from the proxy:

```toml
trusted_proxies = ["10.0.0.0/16"]  # ALB/proxy subnet
```

Without this, audit logs record the proxy IP instead of the real client IP. See [configuration reference](../reference/configuration.md) for details.
